//! Escape test suite. Every test runs an attack *inside* a real sandbox and
//! asserts it was blocked. Needs root and the rootfs from scripts/build-rootfs.sh;
//! run everything with scripts/ci.sh.

use std::collections::HashMap;
use std::process::Command;

const SECRET_DIR: &str = "/var/lib/cellblock-test";
const SECRET: &str = "/var/lib/cellblock-test/host-secret";
const SECRET_TEXT: &str = "HOST-SECRET-6f1c";

struct Run {
    code: i32,
    stdout: String,
    report: HashMap<String, String>,
}

impl Run {
    fn get(&self, k: &str) -> &str {
        self.report.get(k).map(String::as_str).unwrap_or_else(|| panic!("no {k} in report {:?}", self.report))
    }
    fn num(&self, k: &str) -> u64 {
        self.get(k).parse().unwrap()
    }
    /// Every attempt printed BLOCKED and none printed ESCAPED.
    fn assert_all_blocked(&self) {
        assert!(!self.stdout.contains("ESCAPED"), "escape succeeded:\n{}", self.stdout);
        assert!(self.stdout.contains("BLOCKED"), "probe printed nothing:\n{}", self.stdout);
        assert_eq!(self.code, 0, "probe exit code, output:\n{}", self.stdout);
    }
}

fn cellblock(flags: &[&str], cmd: &[&str]) -> Run {
    assert!(nix_is_root(), "the escape tests must run as root: use scripts/ci.sh");
    let out = Command::new(env!("CARGO_BIN_EXE_cellblock"))
        .arg("run")
        .args(flags)
        .arg("--")
        .args(cmd)
        .output()
        .expect("spawn cellblock");
    let stderr = String::from_utf8_lossy(&out.stderr).to_string();
    let line = stderr
        .lines()
        .find(|l| l.starts_with("cellblock: exit="))
        .unwrap_or_else(|| panic!("no report line; stderr:\n{stderr}"));
    let report = line["cellblock: ".len()..]
        .split_whitespace()
        .filter_map(|kv| kv.split_once('='))
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();
    Run { code: out.status.code().unwrap_or(-1), stdout: String::from_utf8_lossy(&out.stdout).to_string(), report }
}

fn nix_is_root() -> bool {
    unsafe { libc::geteuid() == 0 }
}

fn host_secret() -> &'static str {
    std::fs::create_dir_all(SECRET_DIR).unwrap();
    std::fs::write(SECRET, SECRET_TEXT).unwrap();
    SECRET
}

// ---- The nine required escapes (seccomp in its default enforce mode) ----

#[test]
fn fork_bomb_is_capped_by_pids_max() {
    let r = cellblock(&["--pids", "64", "--timeout", "2"], &["/bin/probe", "forkbomb"]);
    assert_eq!(r.get("killed_by"), "timeout");
    assert!(r.num("pids_max_events") > 0, "fork never failed: {:?}", r.report);
    assert!(r.num("pids_peak") <= 64, "more than pids.max processes: {:?}", r.report);
    // The host can still fork.
    assert!(Command::new("true").status().unwrap().success());
}

#[test]
fn memory_hog_is_oom_killed_at_memory_max() {
    let r = cellblock(&["--memory", "64M"], &["/bin/probe", "memhog"]);
    assert_eq!(r.get("killed_by"), "memory.max");
    assert_eq!(r.get("signal"), "SIGKILL");
    assert!(r.num("oom_kills") >= 1);
    assert!(r.num("memory_peak_kb") <= 64 * 1024, "{:?}", r.report);
}

#[test]
fn host_files_are_unreachable() {
    let r = cellblock(&[], &["/bin/probe", "read-host", host_secret()]);
    r.assert_all_blocked();
    assert!(!r.stdout.contains(SECRET_TEXT));
    // The well-known host files are not the host's either.
    let r = cellblock(&[], &["/bin/sh", "-c", "cat /etc/shadow; cat /etc/hostname; ls /home /root /var"]);
    assert_ne!(r.code, 0);
    assert!(r.stdout.is_empty(), "read something: {}", r.stdout);
}

#[test]
fn mount_and_new_namespaces_are_denied() {
    let r = cellblock(&[], &["/bin/probe", "mount"]);
    r.assert_all_blocked();
    assert!(r.stdout.contains("BLOCKED mount(tmpfs, /tmp/m): EPERM"));
    assert!(r.stdout.contains("BLOCKED unshare(CLONE_NEWUSER): EPERM"));
    assert!(r.stdout.contains("BLOCKED clone3(CLONE_NEWUSER): ENOSYS"), "{}", r.stdout);
}

#[test]
fn ptrace_is_denied() {
    let host_pid = std::process::id().to_string();
    let r = cellblock(&[], &["/bin/probe", "ptrace", &host_pid]);
    r.assert_all_blocked();
    // Even a process inside the sandbox cannot be traced: seccomp denies ptrace.
    let r = cellblock(&[], &["/bin/probe", "ptrace-child"]);
    r.assert_all_blocked();
    assert!(r.stdout.contains("EPERM"));
}

#[test]
fn raw_sockets_are_denied() {
    let r = cellblock(&[], &["/bin/probe", "raw-socket"]);
    r.assert_all_blocked();
    assert_eq!(r.stdout.matches(": EPERM").count(), 3, "{}", r.stdout);
}

#[test]
fn network_is_unreachable() {
    let r = cellblock(&[], &["/bin/probe", "network"]);
    r.assert_all_blocked();
    assert_eq!(r.stdout.matches("ENETUNREACH").count(), 4, "{}", r.stdout);
}

#[test]
fn setuid_binary_does_not_grant_root() {
    let r = cellblock(&[], &["/bin/suid-probe"]);
    r.assert_all_blocked();
    assert!(r.stdout.contains("ruid=1000 euid=1000"), "{}", r.stdout);
}

#[test]
fn symlinks_in_scratch_cannot_escape() {
    let r = cellblock(&[], &["/bin/probe", "symlink", host_secret()]);
    r.assert_all_blocked();
    assert!(!r.stdout.contains(SECRET_TEXT));
}

// ---- Extra attacks ----

#[test]
fn tiocsti_is_denied() {
    let r = cellblock(&[], &["/bin/probe", "tiocsti"]);
    r.assert_all_blocked();
    assert!(r.stdout.contains("EPERM"));
}

#[test]
fn rootfs_is_read_only() {
    let r = cellblock(&[], &["/bin/sh", "-c", "echo x > /bin/pwned || echo x > /etc/passwd || exit 3; exit 0"]);
    assert_eq!(r.code, 3);
}

#[test]
fn host_environment_does_not_leak() {
    let out = Command::new(env!("CARGO_BIN_EXE_cellblock"))
        .env("CELLBLOCK_TEST_TOKEN", "sk-should-not-leak")
        .args(["run", "--", "/bin/env"])
        .output()
        .unwrap();
    let env = String::from_utf8_lossy(&out.stdout);
    assert!(!env.contains("sk-should-not-leak"), "{env}");
    assert!(env.contains("PATH=/bin:/usr/bin"));
}

// ---- Defense in depth: with seccomp OFF the other layers still hold ----

#[test]
fn layers_without_seccomp_still_block() {
    let off = ["--seccomp", "off"];
    let host_pid = std::process::id().to_string();
    for probe in [
        vec!["/bin/probe", "read-host", host_secret()],
        vec!["/bin/probe", "symlink", host_secret()],
        vec!["/bin/probe", "mount"],             // no capabilities + max_user_namespaces=0
        vec!["/bin/probe", "ptrace", &host_pid], // PID namespace: host pids do not exist
        vec!["/bin/probe", "raw-socket"],        // no CAP_NET_RAW
        vec!["/bin/probe", "network"],           // empty network namespace
        vec!["/bin/suid-probe"],                 // no_new_privs + nosuid mount
    ] {
        let r = cellblock(&off, &probe);
        r.assert_all_blocked();
    }
}

// ---- Limits and reporting ----

#[test]
fn cpu_max_throttles() {
    let r = cellblock(&["--cpus", "0.25"], &["/bin/probe", "spin", "2"]);
    assert!(r.get("limits_hit").contains("cpu.max"), "{:?}", r.report);
    let (cpu, wall) = (r.num("cpu_usage_ms") as f64, r.num("wall_ms") as f64);
    assert!(cpu < 0.35 * wall, "used {cpu} ms CPU in {wall} ms wall at 0.25 cores");
}

#[test]
fn timeout_kills_the_whole_cgroup() {
    let r = cellblock(&["--timeout", "1"], &["/bin/sh", "-c", "sleep 30 & sleep 30 & sleep 30"]);
    assert_eq!(r.get("killed_by"), "timeout");
    assert!(r.num("wall_ms") < 3000);
}

#[test]
fn seccomp_kill_mode_reports_seccomp() {
    let r = cellblock(&["--seccomp", "kill"], &["/bin/probe", "ptrace-child"]);
    assert_eq!(r.get("killed_by"), "seccomp");
    assert_eq!(r.get("signal"), "SIGSYS");
}

#[test]
fn seccomp_log_mode_only_logs() {
    // ptrace of our own child is denied by enforce mode but allowed (and logged) here.
    let r = cellblock(&["--seccomp", "log"], &["/bin/probe", "ptrace-child"]);
    assert!(r.stdout.contains("ESCAPED ptrace(ATTACH, own child)"), "{}", r.stdout);
}

#[test]
fn threads_work_under_seccomp() {
    // clone3 is forced to ENOSYS, so glibc must fall back to clone() (which the
    // allowlist permits without namespace flags). Checks the filter does not
    // break normal programs.
    for mode in ["enforce", "kill"] {
        let r = cellblock(&["--seccomp", mode], &["/bin/probe", "threads"]);
        assert_eq!(r.code, 0, "{mode}: {}", r.stdout);
        assert!(r.stdout.contains("OK thread created"), "{mode}: {}", r.stdout);
    }
}

#[test]
fn sandbox_identity() {
    let r = cellblock(&[], &["/bin/sh", "-c", "id; hostname; grep -E '^(Cap|NoNewPrivs|Seccomp)' /proc/self/status"]);
    assert_eq!(r.code, 0);
    assert!(r.stdout.contains("uid=1000(sandbox) gid=1000(sandbox)"));
    assert!(r.stdout.contains("cellblock\n"));
    for cap in ["CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb"] {
        assert!(r.stdout.contains(&format!("{cap}:\t0000000000000000")), "{cap}: {}", r.stdout);
    }
    assert!(r.stdout.contains("NoNewPrivs:\t1"));
    assert!(r.stdout.contains("Seccomp:\t2"));
}
