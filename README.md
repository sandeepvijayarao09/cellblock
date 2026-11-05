# cellblock

A small Rust sandbox runner for untrusted (for example, model-generated) code. Phase 1 is a Linux namespace jail: seven namespaces, a read-only root with a tmpfs scratch dir, no capabilities, `no_new_privs`, cgroups v2 limits and a seccomp-bpf allowlist. When a run ends it reports which limit, if any, stopped it.

> Built with [Claude Code](https://claude.com/claude-code). I can explain every syscall, seccomp rule and number in this repo, and [docs/WALKTHROUGH.md](docs/WALKTHROUGH.md) goes through them step by step.

```text
$ sudo cellblock run --memory 64M -- /bin/probe memhog
cellblock: exit=137 signal=SIGKILL killed_by=memory.max limits_hit=memory.max oom_kills=2 ... memory_peak_kb=65536 wall_ms=12
```

## Results (measured, 2026-11-05)

| | |
|---|---|
| Escape tests | **19 tests pass** (5 times in a row, 4 threads): the 9 required attacks, 3 extra attacks, a run with seccomp off to check the other layers, and 6 tests of the limits, seccomp modes and reporting |
| Cold start, launch → first user instruction | **p50 0.86 ms, p99 1.24 ms** (1,000 runs) |
| Cold start, launch → sandbox torn down | p50 1.07 ms, p99 1.51 ms |
| Cost of the seccomp filter | +0.29 ms p50 (0.57 ms with `--seccomp off`) |
| Fork bomb | capped at `pids_peak=64`; 97,214 forks refused in 2 s; killed at the timeout |

Machine: Apple M5 Pro (15 cores, 24 GB, macOS 26.6.2) → Lima 2.2.1 VM (`vz`, 4 vCPUs, 8 GiB) → Ubuntu 24.04, kernel 6.8.0-147-generic, aarch64. Sequential runs after 20 untimed warm-up runs. Raw samples are in [bench/](bench/). Full tables are in [bench/results-2026-11-05.md](bench/results-2026-11-05.md).

**What "cold start" measures:** the clock starts right before the benchmark spawns the `cellblock` process. It stops at the first line of `main()` in [`stamp`](rootfs/stamp.c), a static binary that reads `CLOCK_MONOTONIC` (which is not namespaced here). So the number covers exec'ing cellblock, creating the cgroup, `clone3`, the mounts, `pivot_root`, dropping privileges, installing seccomp and the payload's `execve`. Every run gets a new sandbox and a new cgroup. The page cache is warm. I have not yet measured where the extra 0.29 ms with seccomp goes. Phase 4 adds eBPF tracing to break the start-up time down.

## Architecture

```text
 cellblock run (real root, like Firecracker's jailer)
 │
 ├─ mkdir /sys/fs/cgroup/cellblock/run-<pid>-<ns>    memory.max, swap 0, oom.group, pids.max, cpu.max
 ├─ compile seccomp BPF (2 filters)
 ├─ clone3(NEWUSER|NEWPID|NEWNS|NEWNET|NEWUTS|NEWIPC|NEWCGROUP, CLONE_INTO_CGROUP, CLONE_PIDFD)
 │      │
 │      │  parent writes uid_map/gid_map "0 200000 65536", then writes 1 byte to the "go" pipe
 │      ▼
 │    child (pid 1 in its own PID namespace)
 │      setgroups([]), setresgid/setresuid(0)       → root of the new user namespace only
 │      sethostname("cellblock")
 │      mount / MS_PRIVATE; bind rootfs → remount ro,nosuid,nodev
 │      tmpfs /tmp (size-capped), proc /proc, tmpfs /dev + bind null/zero/random/urandom
 │      pivot_root(".", "."); umount2(".", MNT_DETACH)  → host filesystem gone
 │      /proc/sys/user/max_user_namespaces = 0
 │      PR_CAPBSET_DROP all, clear ambient, setresgid/setresuid(1000), capset(0), NO_NEW_PRIVS, PDEATHSIG
 │      setsid(); close_range(3.., CLOEXEC)
 │      seccomp(clone3→ENOSYS); seccomp(allowlist)
 │      execve(user command, env = PATH/HOME/TMPDIR only)
 │
 ├─ poll(pidfd, timeout)  → on timeout: write 1 to cgroup.kill
 ├─ waitpid; read memory.events, pids.events, pids.peak, cpu.stat, memory.peak
 ├─ print the report line: killed_by = memory.max | timeout | seccomp | signal | none
 └─ cgroup.kill, rmdir the cgroup
```

The code is about 1,100 lines of Rust and C, plus 230 lines of tests:

| File | What it does |
|---|---|
| [src/main.rs](src/main.rs) | CLI, timeout loop, deciding what killed the run, the report line |
| [src/sandbox.rs](src/sandbox.rs) | `clone3`, uid maps, mounts, `pivot_root`, dropping privileges, `execve` |
| [src/cgroup.rs](src/cgroup.rs) | Creating cgroups v2, limits, counters, kill, cleanup |
| [src/seccomp.rs](src/seccomp.rs) | The allowlist and its argument filters |
| [src/bin/bench.rs](src/bin/bench.rs) | The cold-start benchmark |
| [rootfs/](rootfs/) | `probe` (escape attempts), `stamp` (benchmark payload), `suid-probe` (a setuid-root binary) |
| [tests/escape.rs](tests/escape.rs) | The escape test suite |

## Threat model

**Attacker:** arbitrary code running inside the sandbox, for example model-generated Python or shell, or a native binary. It can make any syscall the filter allows and knows how cellblock works.

**What we protect:** the host's files, processes, network, devices, terminal and credentials, and the host's ability to keep working (CPU, memory, PIDs).

**Trusted:** the Linux kernel, cellblock itself (it runs as root until `execve`), and the rootfs image (read-only, built by `scripts/build-rootfs.sh`).

| Attack | Blocked by (first layer → backups) | Test |
|---|---|---|
| Fork bomb | `pids.max` → timeout + `cgroup.kill` | `fork_bomb_is_capped_by_pids_max` |
| Memory hog | `memory.max` + `memory.swap.max=0` + `oom.group` | `memory_hog_is_oom_killed_at_memory_max` |
| Read host files (`/etc/shadow`, `/proc/1/root/...`, `../../..`) | `pivot_root` + detach the old root → the PID namespace makes `/proc/1` the sandbox | `host_files_are_unreachable` |
| `mount`, `umount`, remount `/` read-write | no capabilities → seccomp | `mount_and_new_namespaces_are_denied` |
| Nested user namespace to get capabilities back (`unshare`, `clone`, `clone3`) | seccomp (`unshare` denied, `clone` namespace flags denied, `clone3` → `ENOSYS`) → `max_user_namespaces=0` (`ENOSPC`) | same |
| `ptrace` a host process | PID namespace (host PIDs do not exist) → seccomp | `ptrace_is_denied` |
| Raw / packet sockets | seccomp argument filter → no `CAP_NET_RAW` | `raw_sockets_are_denied` |
| Network access | empty network namespace (no interfaces up, no routes) | `network_is_unreachable` |
| setuid-root binary | `no_new_privs` → `nosuid` mount → the file's owner is unmapped | `setuid_binary_does_not_grant_root` |
| Symlink or hardlink out of scratch | links resolve inside the new root; hardlinks across mounts fail with `EXDEV` | `symlinks_in_scratch_cannot_escape` |
| TIOCSTI (inject keystrokes into the host terminal) | seccomp ioctl allowlist → `setsid()` (no controlling tty) | `tiocsti_is_denied` |
| Writing to the rootfs | read-only bind mount | `rootfs_is_read_only` |
| Reading the host's environment (tokens) | `execve` with a fixed 3-variable environment | `host_environment_does_not_leak` |

`layers_without_seccomp_still_block` runs the attacks again with `--seccomp off`. Every one is still blocked, by the namespaces, the missing capabilities and `no_new_privs` alone. Seccomp is the only layer that stops one sandboxed process from ptracing another, which stays inside the jail either way.

**Out of scope for Phase 1, and known limits:**
- **Kernel bugs.** Every sandbox here shares the host kernel, so a kernel exploit reachable through an allowed syscall breaks out. That is why Phase 3 adds a Firecracker microVM backend.
- **Side channels** (cache timing, Spectre) and **covert channels** between sandboxes.
- **Network egress policy.** Phase 1 has no network at all. Phase 2 adds a single veth link to an egress proxy that only allows listed hosts and adds per-session credentials outside the sandbox.
- **Disk I/O limits** (`io.max`) and **inode exhaustion** are not set. The scratch tmpfs is capped by size only, and it counts toward `memory.max`.
- **Every sandbox uses the same uid range** (host 200000–265535). Sandboxes cannot see each other (separate PID and mount namespaces), but per-sandbox uid ranges would be stronger.
- cellblock runs as root and parses no input from inside the sandbox. It reads only cgroup counters and the exit status.

## How to run

Namespaces, cgroups and seccomp need Linux. On a Mac (Apple silicon, M3 or later for nested virtualization):

```bash
brew install lima
```

```bash
limactl create --name=cellblock vm/lima-cellblock.yaml && limactl start cellblock
```

```bash
limactl shell cellblock
```

Inside the VM (the repo is mounted at the same path):

```bash
scripts/ci.sh                 # builds the rootfs and cellblock, then runs the 19 escape tests as root
```

```bash
sudo ~/cellblock-target/release/cellblock run -- /bin/sh -c 'id; hostname; ls /'
```

```bash
scripts/bench.sh              # 1,000-run cold-start benchmark → bench/results-<date>.md
```

```bash
scripts/seccomp-log.sh /bin/sh -c 'wget -q http://1.1.1.1/'   # which syscalls outside the allowlist a workload makes
```

`cellblock run` flags: `--memory 256M`, `--cpus 1.0`, `--pids 64`, `--scratch 64M`, `--timeout 10` (seconds), `--seccomp enforce|kill|log|off`, `--rootfs /var/lib/cellblock/rootfs`. The command after `--` is a path inside the rootfs. The exit code is the payload's (or 128 + the signal), and 125 if cellblock itself failed.

`.github/workflows/ci.yml` runs the same `scripts/ci.sh` on an x86_64 Ubuntu 24.04 runner. The code type-checks for x86_64, but the workflow has not run yet because the repo is not pushed.

**`/dev/kvm`:** it exists in this VM (`crw-rw---- root kvm 10, 232`), so the Firecracker backend in Phase 3 can run on the same Mac.

## Roadmap

- **Phase 2:** egress proxy over a veth link, an allowlist of hosts, per-session credentials added outside the sandbox.
- **Phase 3:** Firecracker backend behind the same interface; cold boot vs. snapshot restore vs. a warm pool; memory per sandbox (PSS).
- **Phase 4:** per-sandbox eBPF probes (`aya`) keyed by cgroup ID; a breakdown of the cold-start time.
