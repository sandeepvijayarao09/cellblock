//! seccomp-bpf allowlist. Every syscall not listed here is denied.
//!
//! The filter is compiled to BPF in the parent (before clone3) and installed by
//! the child as the very last step before execve, so cellblock's own setup code
//! never runs under it. See docs/WALKTHROUGH.md for why each group is allowed.

use seccompiler::{
    BpfProgram, SeccompAction, SeccompCmpArgLen as Len, SeccompCmpOp as Op, SeccompCondition as Cond, SeccompFilter,
    SeccompRule,
};
use std::collections::BTreeMap;

#[derive(Clone, Copy, Debug, PartialEq, Eq, clap::ValueEnum)]
pub enum Mode {
    /// Denied syscalls fail with EPERM (what Docker's default profile does).
    Enforce,
    /// Denied syscalls kill the whole process with SIGSYS.
    Kill,
    /// Allow everything, but log syscalls outside the allowlist to the kernel
    /// audit log (`journalctl -k | grep SECCOMP`). Use it to see what a workload needs.
    Log,
    /// No seccomp filter (used by the tests to check the other layers alone).
    Off,
}

/// Syscalls allowed with any arguments.
const ALLOW: &[libc::c_long] = &[
    // File I/O on already-open fds and paths inside the jail.
    libc::SYS_read,
    libc::SYS_write,
    libc::SYS_readv,
    libc::SYS_writev,
    libc::SYS_pread64,
    libc::SYS_pwrite64,
    libc::SYS_openat,
    libc::SYS_close,
    libc::SYS_lseek,
    libc::SYS_fstat,
    libc::SYS_newfstatat,
    libc::SYS_statx,
    libc::SYS_faccessat,
    libc::SYS_faccessat2,
    libc::SYS_getdents64,
    libc::SYS_readlinkat,
    libc::SYS_fcntl,
    libc::SYS_dup,
    libc::SYS_dup3,
    libc::SYS_pipe2,
    libc::SYS_statfs,
    libc::SYS_fstatfs,
    libc::SYS_getcwd,
    libc::SYS_chdir,
    libc::SYS_fchdir,
    libc::SYS_umask,
    libc::SYS_fsync,
    libc::SYS_fdatasync,
    libc::SYS_sendfile,
    // Changing files (only the tmpfs scratch is writable; rootfs is read-only).
    libc::SYS_mkdirat,
    libc::SYS_unlinkat,
    libc::SYS_renameat2,
    libc::SYS_symlinkat,
    libc::SYS_linkat,
    libc::SYS_fchmod,
    libc::SYS_fchmodat,
    libc::SYS_ftruncate,
    libc::SYS_truncate,
    libc::SYS_utimensat,
    // Memory.
    libc::SYS_brk,
    libc::SYS_mmap,
    libc::SYS_munmap,
    libc::SYS_mprotect,
    libc::SYS_mremap,
    libc::SYS_madvise,
    // Processes. clone is allowed below only without namespace flags.
    libc::SYS_execve,
    libc::SYS_exit,
    libc::SYS_exit_group,
    libc::SYS_wait4,
    libc::SYS_waitid,
    libc::SYS_kill,
    libc::SYS_tgkill,
    libc::SYS_getpid,
    libc::SYS_getppid,
    libc::SYS_gettid,
    libc::SYS_getpgid,
    libc::SYS_setpgid,
    libc::SYS_getsid,
    libc::SYS_set_tid_address,
    libc::SYS_set_robust_list,
    libc::SYS_rseq,
    libc::SYS_futex,
    libc::SYS_sched_yield,
    libc::SYS_sched_getaffinity,
    libc::SYS_prlimit64,
    libc::SYS_getrlimit,
    libc::SYS_getrusage,
    // Identity (read-only; set*id is denied).
    libc::SYS_getuid,
    libc::SYS_geteuid,
    libc::SYS_getgid,
    libc::SYS_getegid,
    libc::SYS_getgroups,
    libc::SYS_getresuid,
    libc::SYS_getresgid,
    libc::SYS_uname,
    // Signals.
    libc::SYS_rt_sigaction,
    libc::SYS_rt_sigprocmask,
    libc::SYS_rt_sigreturn,
    libc::SYS_sigaltstack,
    libc::SYS_rt_sigsuspend,
    // Time, randomness, waiting.
    libc::SYS_clock_gettime,
    libc::SYS_clock_getres,
    libc::SYS_gettimeofday,
    libc::SYS_nanosleep,
    libc::SYS_clock_nanosleep,
    libc::SYS_getrandom,
    libc::SYS_ppoll,
    libc::SYS_pselect6,
    libc::SYS_epoll_create1,
    libc::SYS_epoll_ctl,
    libc::SYS_epoll_pwait,
    libc::SYS_eventfd2,
    // Sockets. socket() itself is filtered below; the net namespace has no route out.
    libc::SYS_connect,
    libc::SYS_bind,
    libc::SYS_listen,
    libc::SYS_accept4,
    libc::SYS_sendto,
    libc::SYS_recvfrom,
    libc::SYS_sendmsg,
    libc::SYS_recvmsg,
    libc::SYS_getsockname,
    libc::SYS_getpeername,
    libc::SYS_setsockopt,
    libc::SYS_getsockopt,
    libc::SYS_shutdown,
];

/// Legacy syscalls that only exist on x86_64 (aarch64 has only the *at forms).
#[cfg(target_arch = "x86_64")]
const ALLOW_X86: &[libc::c_long] = &[
    libc::SYS_open,
    libc::SYS_stat,
    libc::SYS_lstat,
    libc::SYS_access,
    libc::SYS_pipe,
    libc::SYS_dup2,
    libc::SYS_fork,
    libc::SYS_vfork,
    libc::SYS_arch_prctl,
    libc::SYS_readlink,
    libc::SYS_unlink,
    libc::SYS_mkdir,
    libc::SYS_rmdir,
    libc::SYS_rename,
    libc::SYS_symlink,
    libc::SYS_link,
    libc::SYS_chmod,
    libc::SYS_poll,
    libc::SYS_select,
    libc::SYS_getpgrp,
    libc::SYS_epoll_wait,
    libc::SYS_time,
    libc::SYS_alarm,
];
#[cfg(not(target_arch = "x86_64"))]
const ALLOW_X86: &[libc::c_long] = &[];

/// clone() flags that would create new namespaces (a nested user namespace would
/// hand the payload a fresh set of capabilities).
const CLONE_NS_FLAGS: u64 = (libc::CLONE_NEWUSER
    | libc::CLONE_NEWNS
    | libc::CLONE_NEWPID
    | libc::CLONE_NEWNET
    | libc::CLONE_NEWUTS
    | libc::CLONE_NEWIPC
    | libc::CLONE_NEWCGROUP) as u64;

/// ioctls a normal program needs on stdio. Notably absent: TIOCSTI (push
/// characters into the terminal's input queue, a classic escape when the
/// sandbox shares the user's tty).
const IOCTLS: &[u64] =
    &[libc::TCGETS, libc::TIOCGWINSZ, libc::FIONREAD, libc::FIONBIO, libc::FIOCLEX];

/// `len` is the argument's C type width. int arguments (socket domain/type, the
/// ioctl request, which the kernel truncates to 32 bits) are compared as Dword,
/// so high garbage bits cannot make a call look different from what the kernel sees.
fn cond(arg: u8, len: Len, op: Op, value: u64) -> Cond {
    Cond::new(arg, len, op, value).expect("valid seccomp condition")
}

fn rule(conds: Vec<Cond>) -> SeccompRule {
    SeccompRule::new(conds).expect("valid seccomp rule")
}

fn allowlist() -> BTreeMap<i64, Vec<SeccompRule>> {
    let mut rules: BTreeMap<i64, Vec<SeccompRule>> = BTreeMap::new();
    for &nr in ALLOW.iter().chain(ALLOW_X86) {
        rules.insert(nr, vec![]); // empty rule list = allow with any arguments
    }

    // clone(flags, ...): allowed only if no namespace flag is set.
    rules.insert(libc::SYS_clone, vec![rule(vec![cond(0, Len::Qword, Op::MaskedEq(CLONE_NS_FLAGS), 0)])]);
    // clone3 takes a pointer to its flags, which BPF cannot read. It is "allowed"
    // here and then forced to ENOSYS by the second filter, so libc falls back to clone().
    rules.insert(libc::SYS_clone3, vec![]);

    // socket(domain, type, protocol): only UNIX, IPv4 and IPv6 stream/datagram
    // sockets. The low 4 bits of `type` are the socket type; the rest are
    // SOCK_NONBLOCK / SOCK_CLOEXEC. So SOCK_RAW and AF_PACKET never match.
    let mut socket_rules = vec![];
    for domain in [libc::AF_UNIX, libc::AF_INET, libc::AF_INET6] {
        for ty in [libc::SOCK_STREAM, libc::SOCK_DGRAM] {
            socket_rules.push(rule(vec![
                cond(0, Len::Dword, Op::Eq, domain as u64),
                cond(1, Len::Dword, Op::MaskedEq(0xf), ty as u64),
            ]));
        }
    }
    rules.insert(libc::SYS_socket, socket_rules);
    rules.insert(libc::SYS_socketpair, vec![rule(vec![cond(0, Len::Dword, Op::Eq, libc::AF_UNIX as u64)])]);

    // ioctl(fd, request, ...): only the requests in IOCTLS.
    rules.insert(libc::SYS_ioctl, IOCTLS.iter().map(|&req| rule(vec![cond(1, Len::Dword, Op::Eq, req)])).collect());
    rules
}

fn arch() -> seccompiler::TargetArch {
    std::env::consts::ARCH.try_into().expect("supported architecture")
}

/// Returns the BPF programs to install, in install order.
pub fn build(mode: Mode) -> Vec<BpfProgram> {
    let mismatch = match mode {
        Mode::Enforce => SeccompAction::Errno(libc::EPERM as u32),
        Mode::Kill => SeccompAction::KillProcess,
        Mode::Log => SeccompAction::Log,
        Mode::Off => return vec![],
    };
    let main = SeccompFilter::new(allowlist(), mismatch, SeccompAction::Allow, arch()).expect("valid filter");

    // Second filter: clone3 -> ENOSYS, everything else allowed. When several
    // filters are installed the kernel runs all of them and keeps the most
    // restrictive result, so this overrides the "allow" for clone3 above.
    let clone3 = SeccompFilter::new(
        BTreeMap::from([(libc::SYS_clone3, vec![])]),
        SeccompAction::Allow,
        SeccompAction::Errno(libc::ENOSYS as u32),
        arch(),
    )
    .expect("valid filter");

    // The clone3 filter goes in first: once the allowlist is installed, the
    // prctl() needed to add another filter is itself denied.
    vec![clone3.try_into().expect("compile filter"), main.try_into().expect("compile filter")]
}
