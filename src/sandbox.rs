//! The jail itself: clone3 into fresh namespaces, then (in the child) build the
//! filesystem, drop privileges and exec the user's command.
//!
//! Order matters. Each step needs a privilege that a later step removes:
//!   1. parent: clone3(NEWUSER|NEWPID|NEWNS|NEWNET|NEWUTS|NEWIPC|NEWCGROUP, INTO_CGROUP)
//!   2. parent: write uid_map/gid_map, then tell the child to continue
//!   3. child:  become uid 0 *inside* the user namespace (full caps there only)
//!   4. child:  hostname, mounts, pivot_root            (needs CAP_SYS_ADMIN)
//!   5. child:  drop the capability bounding set         (needs CAP_SETPCAP)
//!   6. child:  setresgid/setresuid to the sandbox user  (clears all caps)
//!   7. child:  no_new_privs, seccomp filter, execve
//!
//! Full explanation: docs/WALKTHROUGH.md.

use nix::mount::{mount, umount2, MntFlags, MsFlags};
use nix::unistd::{chdir, pivot_root, sethostname, setresgid, setresuid, setsid, Gid, Uid};
use seccompiler::BpfProgram;
use std::ffi::CString;
use std::fs;
use std::io::{Read, Write};
use std::os::fd::{FromRawFd, OwnedFd};
use std::os::unix::io::RawFd;

/// Host uid/gid that uid/gid 0 inside the sandbox maps to. Chosen outside the
/// ranges in /etc/subuid so a sandbox can never share an id with a real user
/// or a rootless container.
pub const HOST_ID_BASE: u32 = 200_000;
const ID_COUNT: u32 = 65_536;
/// The payload runs as this uid/gid inside the sandbox (host uid 201000).
pub const SANDBOX_ID: u32 = 1000;

pub struct Config {
    pub rootfs: String,
    pub scratch_bytes: u64,
    pub argv: Vec<String>,
    pub filters: Vec<BpfProgram>,
}

/// From <linux/sched.h>. Defined here because the libc crate's constant is an
/// i32 and this flag (bit 33) only fits in clone3's 64-bit flags.
const CLONE_INTO_CGROUP: u64 = 0x2_0000_0000;

/// <linux/capability.h>: capset() header and per-32-bit-word data.
#[repr(C)]
struct CapHeader {
    version: u32,
    pid: i32,
}
#[repr(C)]
#[derive(Clone, Copy)]
struct CapData {
    effective: u32,
    permitted: u32,
    inheritable: u32,
}
const LINUX_CAPABILITY_VERSION_3: u32 = 0x2008_0522;

/// struct clone_args from <linux/sched.h>. Every field is a u64.
#[repr(C)]
#[derive(Default)]
struct CloneArgs {
    flags: u64,
    pidfd: u64,
    child_tid: u64,
    parent_tid: u64,
    exit_signal: u64,
    stack: u64,
    stack_size: u64,
    tls: u64,
    set_tid: u64,
    set_tid_size: u64,
    cgroup: u64,
}

pub struct Child {
    pub pid: i32,
    pub pidfd: OwnedFd,
}

fn pipe() -> (OwnedFd, OwnedFd) {
    let mut fds = [0; 2];
    // O_CLOEXEC so neither end leaks into the user's program.
    assert_eq!(unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) }, 0, "pipe2");
    unsafe { (OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])) }
}

/// Start the sandbox. Returns once the child has exec'd the user's command
/// (or with the child's setup error).
pub fn spawn(cfg: &Config, cgroup_fd: RawFd) -> Result<Child, String> {
    // go: parent -> child "uid_map is written, continue".
    // err: child -> parent setup error text. It is O_CLOEXEC, so a successful
    // execve closes it and the parent reads EOF.
    let (go_r, go_w) = pipe();
    let (err_r, err_w) = pipe();

    let mut pidfd: RawFd = -1;
    let mut args = CloneArgs {
        flags: (libc::CLONE_NEWUSER
            | libc::CLONE_NEWPID
            | libc::CLONE_NEWNS
            | libc::CLONE_NEWNET
            | libc::CLONE_NEWUTS
            | libc::CLONE_NEWIPC
            | libc::CLONE_NEWCGROUP
            | libc::CLONE_PIDFD) as u64
            | CLONE_INTO_CGROUP,
        pidfd: &mut pidfd as *mut RawFd as u64,
        exit_signal: libc::SIGCHLD as u64,
        cgroup: cgroup_fd as u64,
        ..Default::default()
    };
    // stack = 0 means "fork-like": the child continues on a copy of our stack.
    // That is safe because cellblock is single-threaded at this point.
    let pid = unsafe { libc::syscall(libc::SYS_clone3, &mut args as *mut CloneArgs, std::mem::size_of::<CloneArgs>()) };
    if pid < 0 {
        return Err(format!("clone3: {}", std::io::Error::last_os_error()));
    }
    if pid == 0 {
        drop(go_w);
        drop(err_r);
        child(cfg, go_r, err_w); // never returns
    }
    let pid = pid as i32;
    drop(go_r);
    drop(err_w);
    let pidfd = unsafe { OwnedFd::from_raw_fd(pidfd) };

    // Map sandbox ids 0..65535 to host ids 200000..265535. We are real root,
    // so we may write a multi-id map; host uid 0 stays unmapped, which means
    // root-owned files on the host show up as "nobody" inside.
    let map = format!("0 {HOST_ID_BASE} {ID_COUNT}\n");
    fs::write(format!("/proc/{pid}/uid_map"), &map).map_err(|e| format!("uid_map: {e}"))?;
    fs::write(format!("/proc/{pid}/gid_map"), &map).map_err(|e| format!("gid_map: {e}"))?;
    fs::File::from(go_w).write_all(b"1").map_err(|e| format!("signal child: {e}"))?;

    let mut msg = String::new();
    let _ = fs::File::from(err_r).read_to_string(&mut msg);
    if !msg.is_empty() {
        return Err(msg);
    }
    Ok(Child { pid, pidfd })
}

/// Runs in the new namespaces. On any error: report through `err` and exit 127.
fn child(cfg: &Config, go: OwnedFd, err: OwnedFd) -> ! {
    let mut err = fs::File::from(err);
    if let Err(e) = setup_and_exec(cfg, go) {
        let _ = err.write_all(e.as_bytes());
    }
    unsafe { libc::_exit(127) }
}

macro_rules! check {
    ($what:expr, $e:expr) => {
        $e.map_err(|e| format!("{}: {}", $what, e))?
    };
}

fn setup_and_exec(cfg: &Config, go: OwnedFd) -> Result<(), String> {
    // Wait until the parent has written our uid/gid maps. Before that our ids
    // are unmapped and setresuid(0) below would fail.
    let mut b = [0u8; 1];
    check!("wait for parent", fs::File::from(go).read_exact(&mut b));

    // Become root of the new user namespace. We already hold every capability
    // in it (as its creator); this just gives us a mapped uid so the files we
    // create (tmpfs, /dev entries) have a valid owner. setgroups([]) drops the
    // supplementary groups inherited from host root.
    check!("setgroups", nix::unistd::setgroups(&[]));
    check!("setresgid(0)", setresgid(Gid::from_raw(0), Gid::from_raw(0), Gid::from_raw(0)));
    check!("setresuid(0)", setresuid(Uid::from_raw(0), Uid::from_raw(0), Uid::from_raw(0)));

    check!("sethostname", sethostname("cellblock"));
    build_filesystem(cfg)?;

    // Nested user namespaces would hand the payload a fresh full set of
    // capabilities. This per-namespace limit blocks creating one, even with
    // seccomp off. (Writable because we hold CAP_SYS_RESOURCE in our namespace.)
    check!("max_user_namespaces", fs::write("/proc/sys/user/max_user_namespaces", "0"));

    drop_privileges()?;

    // New session: the user's tty (if any) is no longer our controlling
    // terminal, which blocks TIOCSTI keystroke injection into the host shell.
    check!("setsid", setsid());
    // Every fd >= 3 is closed when we exec (stdin/out/err stay).
    if unsafe { libc::syscall(libc::SYS_close_range, 3u32, u32::MAX, libc::CLOSE_RANGE_CLOEXEC) } != 0 {
        return Err(format!("close_range: {}", std::io::Error::last_os_error()));
    }

    // Build execve arguments before seccomp, so no allocation happens under it.
    let argv: Vec<CString> = cfg.argv.iter().map(|a| CString::new(a.as_str()).unwrap()).collect();
    let env = [c"PATH=/bin:/usr/bin", c"HOME=/tmp", c"TMPDIR=/tmp"];

    // seccomp last: from here on only allowlisted syscalls work. execve is on
    // the list; the filter survives it and applies to the user's program.
    for f in &cfg.filters {
        check!("seccomp", seccompiler::apply_filter(f));
    }
    let e = nix::unistd::execve(&argv[0], &argv, &env).unwrap_err();
    Err(format!("execve {}: {e}", cfg.argv[0]))
}

/// Read-only rootfs + tmpfs scratch, then pivot_root so the host filesystem is
/// no longer reachable by any path.
fn build_filesystem(cfg: &Config) -> Result<(), String> {
    let none: Option<&str> = None;
    // Stop mount events from propagating back to the host (Ubuntu's / is shared).
    check!("make / private", mount(none, "/", none, MsFlags::MS_REC | MsFlags::MS_PRIVATE, none));

    // Bind the rootfs onto itself so it is a mount point (pivot_root needs one),
    // then remount that bind read-only, nosuid, nodev.
    let root = cfg.rootfs.as_str();
    check!("bind rootfs", mount(Some(root), root, none, MsFlags::MS_BIND | MsFlags::MS_REC, none));
    check!(
        "remount rootfs read-only",
        mount(
            none,
            root,
            none,
            MsFlags::MS_REMOUNT | MsFlags::MS_BIND | MsFlags::MS_RDONLY | MsFlags::MS_NOSUID | MsFlags::MS_NODEV,
            none,
        )
    );

    // These mount on top of empty directories that the rootfs image provides.
    let nosuid_nodev = MsFlags::MS_NOSUID | MsFlags::MS_NODEV;
    // Scratch space: size-capped tmpfs, sticky + world-writable like /tmp.
    let scratch_opts = format!("size={},mode=1777", cfg.scratch_bytes);
    check!(
        "mount /tmp",
        mount(Some("tmpfs"), format!("{root}/tmp").as_str(), Some("tmpfs"), nosuid_nodev, Some(scratch_opts.as_str()))
    );
    // A proc for *our* PID namespace: it only shows processes in the sandbox.
    check!(
        "mount /proc",
        mount(Some("proc"), format!("{root}/proc").as_str(), Some("proc"), nosuid_nodev | MsFlags::MS_NOEXEC, none)
    );
    // /dev: a tiny tmpfs with only null, zero, random, urandom bind-mounted
    // from the host. No disks, no /dev/kvm, no tty devices.
    let dev = format!("{root}/dev");
    check!(
        "mount /dev",
        mount(
            Some("tmpfs"),
            dev.as_str(),
            Some("tmpfs"),
            MsFlags::MS_NOSUID | MsFlags::MS_NOEXEC,
            Some("size=64k,mode=755")
        )
    );
    for node in ["null", "zero", "random", "urandom"] {
        let target = format!("{dev}/{node}");
        check!(format!("create {target}"), fs::File::create(&target));
        check!(
            format!("bind {target}"),
            mount(Some(format!("/dev/{node}").as_str()), target.as_str(), none, MsFlags::MS_BIND, none)
        );
    }

    // pivot_root(".", "."): the rootfs becomes "/", and the old root is stacked
    // on top of it at "/". Unmounting "." (lazily) then removes the old root,
    // so no path inside the sandbox leads back to the host filesystem.
    check!("chdir rootfs", chdir(root));
    check!("pivot_root", pivot_root(".", "."));
    check!("detach old root", umount2(".", MntFlags::MNT_DETACH));
    check!("chdir /", chdir("/"));
    Ok(())
}

/// Linux capability numbers run 0..=CAP_LAST_CAP; read the real upper bound.
fn last_cap() -> u32 {
    fs::read_to_string("/proc/sys/kernel/cap_last_cap").ok().and_then(|s| s.trim().parse().ok()).unwrap_or(40)
}

fn drop_privileges() -> Result<(), String> {
    // 1. Bounding set: the ceiling on capabilities any later execve can grant.
    //    Must be emptied while we still hold CAP_SETPCAP.
    for cap in 0..=last_cap() {
        if unsafe { libc::prctl(libc::PR_CAPBSET_DROP, cap, 0, 0, 0) } != 0 {
            return Err(format!("PR_CAPBSET_DROP {cap}: {}", std::io::Error::last_os_error()));
        }
    }
    // 2. Ambient set: capabilities that survive execve for non-root. Clear it.
    if unsafe { libc::prctl(libc::PR_CAP_AMBIENT, libc::PR_CAP_AMBIENT_CLEAR_ALL, 0, 0, 0) } != 0 {
        return Err(format!("PR_CAP_AMBIENT_CLEAR_ALL: {}", std::io::Error::last_os_error()));
    }
    // 3. Switch to the unprivileged sandbox user. Going from uid 0 to non-zero
    //    clears the permitted and effective sets (no SECBIT_KEEP_CAPS set).
    let id = SANDBOX_ID;
    check!("setresgid", setresgid(Gid::from_raw(id), Gid::from_raw(id), Gid::from_raw(id)));
    check!("setresuid", setresuid(Uid::from_raw(id), Uid::from_raw(id), Uid::from_raw(id)));
    // 4. Belt and braces: explicitly zero effective/permitted/inheritable.
    let mut hdr = CapHeader { version: LINUX_CAPABILITY_VERSION_3, pid: 0 };
    let data = [CapData { effective: 0, permitted: 0, inheritable: 0 }; 2]; // 2 words = caps 0..63
    if unsafe { libc::syscall(libc::SYS_capset, &mut hdr, data.as_ptr()) } != 0 {
        return Err(format!("capset: {}", std::io::Error::last_os_error()));
    }
    // 5. no_new_privs: execve can never add privileges again (setuid bits and
    //    file capabilities are ignored). Also required to install seccomp
    //    without CAP_SYS_ADMIN.
    if unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } != 0 {
        return Err(format!("PR_SET_NO_NEW_PRIVS: {}", std::io::Error::last_os_error()));
    }
    // 6. If cellblock dies, kill the sandbox. Set after setresuid because
    //    changing credentials resets the parent-death signal.
    unsafe { libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL, 0, 0, 0) };
    Ok(())
}
