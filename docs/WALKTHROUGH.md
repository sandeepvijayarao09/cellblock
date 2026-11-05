# cellblock walkthrough

This follows one `cellblock run -- /bin/probe mount` from start to finish. For every step it covers the syscall, why it is there, and what would break without it. File references point at the code that does it.

The order is the whole design. Each step needs a privilege that a later step takes away, so it cannot be rearranged freely.

---

## 0. Why cellblock starts as root

Ubuntu 24.04 sets `kernel.apparmor_restrict_unprivileged_userns=1`. An unprivileged process may still create a user namespace, but it gets no capabilities inside it, so it cannot mount anything. cellblock also has to create cgroups under `/sys/fs/cgroup` and write a uid map with more than one entry. All three need real root.

This is the same model as Firecracker's `jailer`: a small trusted launcher starts as root and gives up everything before running untrusted code. The untrusted code never runs as root on the host, not even for one instruction.

## 1. The cgroup is created first ([src/cgroup.rs](../src/cgroup.rs))

```text
mkdir /sys/fs/cgroup/cellblock                  (once)
write "+memory +pids +cpu" > cellblock/cgroup.subtree_control
mkdir  cellblock/run-<pid>-<nanos>
write  memory.max       = 268435456             (--memory, default 256M)
write  memory.swap.max  = 0
write  memory.oom.group = 1
write  pids.max         = 64                    (--pids)
write  cpu.max          = "100000 100000"       (--cpus 1.0 → quota/period in µs)
open   the directory O_DIRECTORY → fd for clone3
```

- **`subtree_control`**: in cgroups v2 a child cgroup can only use a controller its parent turned on for its children. The root cgroup already does that for memory, pids and cpu on Ubuntu, and `cellblock/` does it again for the per-run cgroups.
- **`memory.swap.max = 0`**: without it, a memory hog would be pushed out to swap instead of hitting the limit. (This VM has no swap, but a production host might.)
- **`memory.oom.group = 1`**: on an OOM, kill *every* process in the cgroup, not just the biggest one. A half-killed sandbox is worse than a dead one.
- **`pids.max`** counts processes *and* threads. When it is reached, `fork()`/`clone()` fail with `EAGAIN`. Nothing is killed, which is why the fork bomb is killed later by the timeout.
- **`cpu.max`** is a bandwidth limit: `quota period` means "at most `quota` µs of CPU in every `period` µs". `0.25` cores is `25000 100000`. Going over it throttles the process instead of killing it.

## 2. The seccomp filter is compiled before the clone ([src/seccomp.rs](../src/seccomp.rs))

`seccomp::build()` turns the allowlist into two classic-BPF programs while still in the parent. The child only has to install them, and no parsing or compiling happens late in setup. [Section 8](#8-seccomp-srcseccomprs) explains the rules.

## 3. `clone3` ([src/sandbox.rs](../src/sandbox.rs) `spawn`)

```c
struct clone_args {
  .flags = CLONE_NEWUSER | CLONE_NEWPID | CLONE_NEWNS | CLONE_NEWNET
         | CLONE_NEWUTS | CLONE_NEWIPC | CLONE_NEWCGROUP
         | CLONE_PIDFD | CLONE_INTO_CGROUP,
  .pidfd = &pidfd, .exit_signal = SIGCHLD, .cgroup = <cgroup dir fd>,
}
syscall(SYS_clone3, &args, sizeof args)
```

| Flag | What the child gets |
|---|---|
| `CLONE_NEWUSER` | Its own uid/gid number space and its own set of capabilities. Being "root" in here means nothing to the host. All the other namespaces are *owned* by this one, which is what lets the child set them up. |
| `CLONE_NEWPID` | It is pid 1, and it can only see its own descendants. Host processes have no pid at all from inside, so `ptrace(PTRACE_ATTACH, <host pid>)` fails with `ESRCH`. When pid 1 exits, the kernel kills everything else in the namespace. |
| `CLONE_NEWNS` | Its own mount table, so the mounts below never show up on the host. |
| `CLONE_NEWNET` | A new network stack with only a loopback interface, which is down. There are no routes, so every `connect()` fails with `ENETUNREACH`. |
| `CLONE_NEWUTS` | Its own hostname (`cellblock`). |
| `CLONE_NEWIPC` | Its own System V IPC and POSIX message queues, so it cannot reach host shared memory segments. |
| `CLONE_NEWCGROUP` | `/proc/self/cgroup` shows `0::/` instead of the host cgroup path, so the host layout does not leak. |
| `CLONE_INTO_CGROUP` | The child starts life *inside* the limited cgroup. Doing "fork, then move into the cgroup" leaves a window where the child runs without limits. This closes it. |
| `CLONE_PIDFD` | A file descriptor for the child. The parent `poll()`s it to wait for exit with a timeout. Unlike a pid number, it cannot be reused by another process. |

**Why `clone3` and not `clone`:** `CLONE_INTO_CGROUP` and `CLONE_PIDFD`-with-a-pointer only exist in `clone3`. The libc crate's `CLONE_INTO_CGROUP` constant is an `i32`, but the flag is bit 33, so `sandbox.rs` defines it as a `u64`.

**`stack = 0`** makes `clone3` behave like `fork()`: the child keeps running on a copy of the parent's stack. That is safe only because cellblock is single-threaded at this point. A copied lock held by another thread would deadlock the child.

## 4. Parent writes the uid/gid maps; the child waits

A new user namespace starts with no ids mapped: inside it, the child's uid shows as 65534 (`nobody`). The parent writes:

```text
/proc/<child>/uid_map:  0 200000 65536
/proc/<child>/gid_map:  0 200000 65536
```

This means "ids 0–65535 inside are host ids 200000–265535". So sandbox root is host uid 200000, and the sandbox user 1000 is host uid 201000. Neither one exists in `/etc/passwd`, and neither falls inside `/etc/subuid` (here `524288:1073741824`), so a sandbox can never share an id with a real user or a rootless container.

**Host uid 0 is not mapped.** Files owned by host root (the whole rootfs) appear as owned by `nobody` inside, and the kernel will not honour a setuid bit on a file whose owner has no mapping. That is the third layer under the setuid test.

The child blocks on `read()` from a pipe until the parent writes one byte after the maps. A second pipe goes the other way and carries any setup error back as text. It is `O_CLOEXEC`, so a successful `execve` closes it and the parent reads EOF, which means "started fine".

## 5. Child: become root of the new namespace

```text
setgroups([])            drop host root's supplementary groups
setresgid(0, 0, 0)
setresuid(0, 0, 0)       → host uid 200000, full capabilities inside this namespace only
sethostname("cellblock")
```

The child already held every capability in its new namespace as its creator. Becoming uid 0 gives it a *mapped* identity, so the tmpfs and `/dev` entries it creates have a real owner. `setgroups([])` matters because the child inherited host root's group list (gid 0). Without it, the kernel would still check host gid 0 for group permissions on host files.

## 6. Child: build the filesystem ([src/sandbox.rs](../src/sandbox.rs) `build_filesystem`)

```text
mount(NULL, "/", NULL, MS_REC|MS_PRIVATE)                     stop propagation to the host
mount(rootfs, rootfs, NULL, MS_BIND|MS_REC)                     rootfs becomes a mount point
mount(NULL, rootfs, NULL, MS_REMOUNT|MS_BIND|MS_RDONLY|MS_NOSUID|MS_NODEV)
mount("tmpfs", rootfs/tmp,  "tmpfs", MS_NOSUID|MS_NODEV, "size=64M,mode=1777")
mount("proc",  rootfs/proc, "proc",  MS_NOSUID|MS_NODEV|MS_NOEXEC)
mount("tmpfs", rootfs/dev,  "tmpfs", MS_NOSUID|MS_NOEXEC, "size=64k,mode=755")
  for null zero random urandom: create rootfs/dev/X; mount(/dev/X, rootfs/dev/X, MS_BIND)
chdir(rootfs); pivot_root(".", "."); umount2(".", MNT_DETACH); chdir("/")
```

- **`MS_PRIVATE`**: Ubuntu mounts `/` as *shared*, so a mount made in one namespace would show up in the others. Making our copy private (recursively) stops that, and `pivot_root` requires it.
- **Bind the rootfs onto itself**: `pivot_root` needs the new root to be a mount point, and a bind mount turns a plain directory into one.
- **Remount read-only, nosuid, nodev**: a bind mount takes its flags from a separate remount. `nosuid` is the second layer under the setuid test. `nodev` means a device node in the image would not work.
- **`/tmp` tmpfs**: the only writable place. `size=` caps it, and tmpfs pages count toward `memory.max` as well. `mode=1777` is the usual sticky `/tmp`.
- **A new `/proc`**: mounted from inside the new PID namespace, it lists only sandbox processes. `noexec` because nothing should be run from `/proc`. The host's `/proc` is never visible.
- **`/dev`**: only four harmless character devices, bind-mounted from the host. Device nodes *created* inside a user namespace do not work (the kernel forces `nodev` on those mounts), but bind mounts of existing host nodes do. There is no `/dev/kvm`, no disks and no tty devices.
- **`pivot_root(".", ".")`**: makes the current directory (the rootfs) the new `/` and stacks the old root on top of it at `/`. Then `umount2(".", MNT_DETACH)` lazily removes that old root, which is now on top. After this no path leads back to the host: `..` from `/` is `/`, `/proc/1/root` is the sandbox's own root, and every absolute symlink resolves inside the jail. `chroot()` would not be enough here: a process with `CAP_SYS_CHROOT` can break out of a chroot, and the old root would still be mounted.

The tests show the result: `/var/lib/cellblock-test/host-secret` gives `ENOENT` through its absolute path, through `/proc/1/root/...`, through `../../..` and through symlinks planted in `/tmp`. A hardlink from `/tmp` to a rootfs file fails with `EXDEV` because they are on different mounts.

## 7. Child: give up every privilege ([src/sandbox.rs](../src/sandbox.rs) `drop_privileges`)

```text
write "0" > /proc/sys/user/max_user_namespaces
for cap in 0..=cap_last_cap: prctl(PR_CAPBSET_DROP, cap)
prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_CLEAR_ALL)
setresgid(1000, 1000, 1000)
setresuid(1000, 1000, 1000)
capset(v3, {effective=0, permitted=0, inheritable=0} × 2)
prctl(PR_SET_NO_NEW_PRIVS, 1)
prctl(PR_SET_PDEATHSIG, SIGKILL)
setsid()
close_range(3, ~0, CLOSE_RANGE_CLOEXEC)
```

- **`max_user_namespaces = 0`**: this limit is kept *per user namespace*, and we can write it because we hold `CAP_SYS_RESOURCE` in ours. With it at 0, the payload cannot create a nested user namespace. A nested one would give it a fresh full set of capabilities, and with them the ability to mount filesystems and reach a lot more kernel code. This is the backup for the seccomp rules in §8. With `--seccomp off`, `unshare(CLONE_NEWUSER)` and `clone3(CLONE_NEWUSER)` both fail with `ENOSPC`.
- **Bounding set**: the ceiling on capabilities any future `execve` could grant, for example through file capabilities. Emptying it needs `CAP_SETPCAP`, so it has to happen *before* the uid change.
- **Ambient set**: capabilities that non-root programs keep across `execve`. Cleared.
- **`setresuid(1000)`**: going from uid 0 to a non-zero uid (with `SECBIT_KEEP_CAPS` off) clears the permitted and effective sets. gid goes first, because once uid is 1000 we are no longer allowed to change gid.
- **`capset` to zero**: makes sure all three sets are empty, including the inheritable set, which `setresuid` does not clear. The kernel ABI uses two 32-bit words per set, which covers capabilities 0–63.
- **`no_new_privs`**: from now on `execve` can never *add* privileges, so setuid bits and file capabilities are ignored. This is the first layer under the setuid test. The kernel also requires it before an unprivileged process may install a seccomp filter.
- **`PDEATHSIG`**: if cellblock dies, the kernel sends SIGKILL to the sandbox. It is set *after* `setresuid`, because changing credentials resets it.
- **`setsid()`**: starts a new session with no controlling terminal. `TIOCSTI` (push keystrokes into a terminal's input queue) needs the terminal to be your controlling tty or `CAP_SYS_ADMIN`. So even if the payload's stdin is your shell's tty, it cannot type commands into it. This is the second layer behind the ioctl filter. (Kernels 6.2+ can also turn `TIOCSTI` off globally with `dev.tty.legacy_tiocsti=0`, which this VM's kernel already does. cellblock does not rely on that.)
- **`close_range(..., CLOSE_RANGE_CLOEXEC)`**: every inherited fd above stderr is closed when we `execve`. That includes our error pipe, which is how the parent learns that `execve` succeeded.

`/proc/self/status` inside the sandbox then shows `CapInh/CapPrm/CapEff/CapBnd/CapAmb` all zero, `NoNewPrivs: 1` and `Seccomp: 2` (filter mode). The `sandbox_identity` test checks each of these.

## 8. seccomp ([src/seccomp.rs](../src/seccomp.rs))

The last two steps before `execve` install the filters with `prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, prog)`. Filters are inherited by every child and survive `execve`. Nothing can remove them.

### Two filters, and why they go in this order

1. `clone3 → ENOSYS`, everything else allowed.
2. The allowlist: listed syscalls allowed, everything else denied.

When several filters are installed, the kernel runs all of them and keeps the *most restrictive* result, so filter 1's `ENOSYS` overrides filter 2's "allow" for `clone3`. Filter 1 is installed first because once filter 2 is in, the `prctl` needed to add another filter is itself denied. (This was a real bug during development: setup failed with `prctl: EPERM` until the order was swapped.)

### Modes (`--seccomp`)

| Mode | What happens to a syscall outside the list |
|---|---|
| `enforce` (default) | Fails with `EPERM`. Programs that probe for optional features keep working. This is also what Docker's default profile does. |
| `kill` | The whole process gets SIGSYS. cellblock reports `killed_by=seccomp`. |
| `log` | Allowed, but recorded in the kernel audit log (`type=1326 ... syscall=N`). `scripts/seccomp-log.sh` turns those into names. Use it to find out what a workload needs before tightening the list. |
| `off` | No filter. Only used to test the other layers on their own. |

Example from `log` mode: busybox `sh`, `ls` and `wget` call `setuid`, `setgid` and `prctl`, all outside the list. Under `enforce` those get `EPERM`, and `sh` and `ls` still work (the tests use both).

### Allowed with any arguments

| Group | Syscalls | Why it is safe |
|---|---|---|
| File I/O | `read write readv writev pread64 pwrite64 openat close lseek fstat newfstatat statx faccessat faccessat2 getdents64 readlinkat fcntl dup dup3 pipe2 statfs fstatfs getcwd chdir fchdir umask fsync fdatasync sendfile` | They only touch paths inside the jail or fds the process already holds. The rootfs is read-only and the host is unreachable (§6). |
| Changing files | `mkdirat unlinkat renameat2 symlinkat linkat fchmod fchmodat ftruncate truncate utimensat` | Only `/tmp` is writable, and it is a size-capped tmpfs. `fchownat` is *not* allowed. |
| Memory | `brk mmap munmap mprotect mremap madvise` | Bounded by `memory.max`. |
| Processes | `execve exit exit_group wait4 waitid kill tgkill getpid getppid gettid getpgid setpgid getsid set_tid_address set_robust_list rseq futex sched_yield sched_getaffinity prlimit64 getrlimit getrusage` | Signals and `prlimit` can only reach processes in our PID namespace. `rseq`, `set_robust_list` and `set_tid_address` are called by glibc at startup. |
| Identity (read-only) | `getuid geteuid getgid getegid getgroups getresuid getresgid uname` | Reading is harmless. Every `set*id` call is denied. |
| Signals | `rt_sigaction rt_sigprocmask rt_sigreturn sigaltstack rt_sigsuspend` | Needed by any program that handles signals. |
| Time, randomness, waiting | `clock_gettime clock_getres gettimeofday nanosleep clock_nanosleep getrandom ppoll pselect6 epoll_create1 epoll_ctl epoll_pwait eventfd2` | No privilege involved. |
| Sockets (after creation) | `connect bind listen accept4 sendto recvfrom sendmsg recvmsg getsockname getpeername setsockopt getsockopt shutdown` | The network namespace has no route out, and the socket *types* are restricted below. |
| x86_64 only | `open stat lstat access pipe dup2 fork vfork arch_prctl readlink unlink mkdir rmdir rename symlink link chmod poll select getpgrp epoll_wait time alarm` | Older forms of the calls above. aarch64 only has the `*at` versions, so this list is empty there. |

### Allowed only with certain arguments

| Syscall | Rule | Blocks |
|---|---|---|
| `clone` | `(flags & (NEWUSER\|NEWNS\|NEWPID\|NEWNET\|NEWUTS\|NEWIPC\|NEWCGROUP)) == 0` (64-bit compare) | Creating namespaces. Plain `fork()` and threads still work. |
| `clone3` | allowed by filter 2, forced to `ENOSYS` by filter 1 | BPF can only read syscall *arguments*, not memory, and `clone3` passes its flags through a pointer, so the flags cannot be checked. `ENOSYS` makes glibc fall back to `clone`, which can be checked. Tests: `clone3(CLONE_NEWUSER)` gives `ENOSYS`, and `pthread_create` still works in `enforce` and `kill` modes. |
| `socket` | domain ∈ {`AF_UNIX`, `AF_INET`, `AF_INET6`} **and** `(type & 0xf)` ∈ {`SOCK_STREAM`, `SOCK_DGRAM`} (32-bit compares) | `SOCK_RAW`, `AF_PACKET`, netlink and every other family. The `& 0xf` mask ignores the `SOCK_NONBLOCK`/`SOCK_CLOEXEC` bits that share the `type` argument. |
| `socketpair` | domain = `AF_UNIX` | Same as above. |
| `ioctl` | request ∈ {`TCGETS`, `TIOCGWINSZ`, `FIONREAD`, `FIONBIO`, `FIOCLEX`} (32-bit compare) | `TIOCSTI` and every device ioctl. `TCGETS` is what `isatty()` calls. |

**Why 32-bit compares for `int` arguments:** the kernel reads `socket()`'s domain and type, and `ioctl()`'s request, as 32-bit values. If the filter compared all 64 bits, a caller could set high garbage bits, and the filter would see a different value from the one the kernel acts on. With an allowlist that mismatch only causes false *denials*, but comparing the same 32 bits the kernel uses keeps the filter exact.

### Notably denied

`mount umount2 pivot_root chroot unshare setns ptrace process_vm_readv/writev bpf perf_event_open keyctl add_key init_module finit_module kexec_load reboot swapon setuid setgid setgroups setresuid capset prctl personality userfaultfd io_uring_setup open_by_handle_at name_to_handle_at fchownat mknodat` and everything else not listed. Several of these (`bpf`, `userfaultfd`, `io_uring_setup`, `perf_event_open`, `keyctl`) have a history of kernel bugs that let code escape a sandbox, so leaving them out shrinks the part of the kernel the payload can reach.

## 9. `execve`

```text
execve(argv[0], argv, ["PATH=/bin:/usr/bin", "HOME=/tmp", "TMPDIR=/tmp"])
```

The environment is fixed. Nothing from the host leaks in (`host_environment_does_not_leak` sets a fake token on cellblock and checks it is not visible). This matters for Phase 2, where credentials must never enter the sandbox. If `execve` fails, the message goes back through the error pipe and the child exits with code 127.

## 10. Parent: wait, decide what killed the run, clean up ([src/main.rs](../src/main.rs))

```text
poll(pidfd, POLLIN, timeout_ms)       → readable when the child exits
  on timeout: write "1" > cgroup.kill  (SIGKILL every process in the cgroup, kernel 5.14+)
waitpid(pid)
read memory.events (oom_kill, max), pids.events (max), pids.peak, cpu.stat (usage_usec, throttled_usec), memory.peak
write "1" > cgroup.kill; rmdir the cgroup (retry while it is still busy)
```

`killed_by` is decided in this order:

| Condition | `killed_by` |
|---|---|
| The timeout fired | `timeout` |
| SIGKILL and `oom_kill > 0` | `memory.max` |
| SIGSYS | `seccomp` (only in `kill` mode) |
| Some other signal | `signal` |
| Normal exit | `none` |

`limits_hit` lists every limit the run ran into, even if it did not kill the run: `memory.max`, `pids.max` (a fork was refused) and `cpu.max` (the run was throttled). For example, the fork bomb reports `killed_by=timeout limits_hit=pids.max,cpu.max pids_peak=64`.

## 11. How the benchmark measures cold start ([src/bin/bench.rs](../src/bin/bench.rs))

```text
t0 = clock_gettime(CLOCK_MONOTONIC)          in cellblock-bench, right before spawning
spawn: cellblock run -- /bin/stamp
stamp's main(): first statement prints clock_gettime(CLOCK_MONOTONIC)
start latency = stamp_value − t0             launch → first user instruction
total latency = (cellblock exited) − t0      includes waitpid, reading counters, rmdir
```

`CLOCK_MONOTONIC` gives the same value inside and outside because cellblock does not create a time namespace. `stamp` is static, so no dynamic loader runs before `main()`. Only glibc's own static startup does. The benchmark runs 20 untimed warm-up runs and then 1,000 sequential timed runs, and reports nearest-rank percentiles.

## Questions to be ready for

- *Why not `unshare()` + `fork()`?* `CLONE_INTO_CGROUP` has no `unshare` equivalent. You would have to fork first and move the process into the cgroup afterwards, which leaves it unlimited for a moment. A PID namespace from `unshare` also only applies to the *next* child, which means an extra fork.
- *Why not let the payload run as root inside its namespace?* Root in a user namespace still holds capabilities over everything that namespace owns: its network stack (so raw sockets work), its mounts and its hostname. Running as uid 1000 with empty capability sets removes all of that. The `--seccomp off` test shows raw sockets are still refused (`EPERM`) for exactly that reason.
- *What does seccomp cost?* About 0.29 ms at p50 in this VM (0.86 ms vs 0.57 ms with it off). The cause is not measured yet. The obvious guess, the speculative-store-bypass mitigation the kernel can apply to seccomp'd tasks, does not hold here: `/sys/devices/system/cpu/vulnerabilities/spec_store_bypass` reports `Vulnerable`, meaning no mitigation is applied. Phase 4's eBPF breakdown is meant to answer it.
- *What would still get out?* A kernel bug reachable through an allowed syscall. All sandboxes share one kernel, which is why Phase 3 adds Firecracker.
