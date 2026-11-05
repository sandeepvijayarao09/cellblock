//! cellblock: run an untrusted command in a namespace jail.
//!
//!   sudo cellblock run [--memory 256M] [--cpus 1] [--pids 64] [--timeout 10] -- /bin/sh -c 'echo hi'
//!
//! cellblock must start as real root (like Firecracker's jailer): it creates
//! cgroups and writes uid maps. The command itself runs as an unprivileged,
//! capability-less user that does not exist on the host.

mod cgroup;
mod sandbox;
mod seccomp;

use clap::{Parser, Subcommand};
use nix::poll::{poll, PollFd, PollFlags, PollTimeout};
use nix::sys::wait::{waitpid, WaitStatus};
use nix::unistd::Pid;
use std::os::fd::AsFd;
use std::process::ExitCode;
use std::time::{Duration, Instant};

#[derive(Parser)]
#[command(version, about = "Run untrusted code in a Linux namespace jail")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Run a command inside a fresh sandbox.
    Run(RunArgs),
}

#[derive(clap::Args)]
struct RunArgs {
    /// Directory used as the read-only root filesystem.
    #[arg(long, default_value = "/var/lib/cellblock/rootfs")]
    rootfs: String,
    /// memory.max (accepts K, M, G suffixes).
    #[arg(long, default_value = "256M", value_parser = parse_size)]
    memory: u64,
    /// cpu.max in cores (0.5 = half a core).
    #[arg(long, default_value_t = 1.0)]
    cpus: f64,
    /// pids.max: most processes + threads alive at once.
    #[arg(long, default_value_t = 64)]
    pids: u64,
    /// Size of the writable tmpfs mounted at /tmp.
    #[arg(long, default_value = "64M", value_parser = parse_size)]
    scratch: u64,
    /// Wall-clock limit in seconds; the whole cgroup is killed after it.
    #[arg(long, default_value_t = 10.0)]
    timeout: f64,
    #[arg(long, value_enum, default_value = "enforce")]
    seccomp: seccomp::Mode,
    /// Command and arguments (path is inside the rootfs).
    #[arg(last = true, required = true)]
    command: Vec<String>,
}

fn parse_size(s: &str) -> Result<u64, String> {
    let (num, mult) = match s.chars().last() {
        Some('K' | 'k') => (&s[..s.len() - 1], 1u64 << 10),
        Some('M' | 'm') => (&s[..s.len() - 1], 1 << 20),
        Some('G' | 'g') => (&s[..s.len() - 1], 1 << 30),
        _ => (s, 1),
    };
    num.parse::<u64>().map(|n| n * mult).map_err(|e| format!("{s}: {e}"))
}

fn main() -> ExitCode {
    let Cmd::Run(args) = Cli::parse().cmd;
    match run(args) {
        Ok(code) => ExitCode::from(code),
        Err(e) => {
            eprintln!("cellblock: {e}");
            ExitCode::from(125)
        }
    }
}

fn run(args: RunArgs) -> Result<u8, String> {
    if !nix::unistd::geteuid().is_root() {
        return Err("must run as root (it creates cgroups and uid maps)".into());
    }
    let start = Instant::now();
    let limits = cgroup::Limits { memory_bytes: args.memory, cpus: args.cpus, pids: args.pids };
    let nanos = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos();
    let name = format!("run-{}-{nanos}", std::process::id());
    let cg = cgroup::Cgroup::create(&name, &limits).map_err(|e| format!("cgroup: {e}"))?;

    let cfg = sandbox::Config {
        rootfs: args.rootfs,
        scratch_bytes: args.scratch,
        argv: args.command,
        filters: seccomp::build(args.seccomp),
    };
    let child = match sandbox::spawn(&cfg, cg.fd()) {
        Ok(c) => c,
        Err(e) => {
            cg.destroy();
            return Err(format!("sandbox setup failed: {e}"));
        }
    };

    // Wait for exit or timeout. The pidfd becomes readable when the child exits.
    let deadline = start + Duration::from_secs_f64(args.timeout);
    let mut timed_out = false;
    loop {
        let left = deadline.saturating_duration_since(Instant::now());
        let ms = PollTimeout::try_from(left.as_millis().min(i32::MAX as u128) as i32).unwrap();
        let mut fds = [PollFd::new(child.pidfd.as_fd(), PollFlags::POLLIN)];
        match poll(&mut fds, ms) {
            Ok(0) => {
                // Timeout: SIGKILL everything in the cgroup, not just pid 1.
                timed_out = true;
                cg.kill_all();
                break;
            }
            Ok(_) => break,
            Err(nix::errno::Errno::EINTR) => continue,
            Err(e) => return Err(format!("poll: {e}")),
        }
    }
    let status = waitpid(Pid::from_raw(child.pid), None).map_err(|e| format!("waitpid: {e}"))?;
    let wall = start.elapsed();
    let usage = cg.usage();
    cg.destroy();

    let (exit_code, signal) = match status {
        WaitStatus::Exited(_, c) => (c, None),
        WaitStatus::Signaled(_, s, _) => (128 + s as i32, Some(s)),
        other => return Err(format!("unexpected wait status {other:?}")),
    };

    // Which limit (if any) ended or constrained the run.
    let killed_by = match signal {
        _ if timed_out => "timeout",
        Some(nix::sys::signal::SIGKILL) if usage.oom_kills > 0 => "memory.max",
        Some(nix::sys::signal::SIGSYS) => "seccomp",
        Some(_) => "signal",
        None => "none",
    };
    let mut hit = vec![];
    if usage.oom_kills > 0 || usage.memory_max_hits > 0 {
        hit.push("memory.max");
    }
    if usage.pids_max_hits > 0 {
        hit.push("pids.max");
    }
    if usage.cpu_throttled_usec > 0 {
        hit.push("cpu.max");
    }
    // One machine-readable line on stderr; the tests parse it.
    eprintln!(
        "cellblock: exit={exit_code} signal={} killed_by={killed_by} limits_hit={} oom_kills={} pids_max_events={} \
         pids_peak={} cpu_usage_ms={} cpu_throttled_ms={} memory_peak_kb={} wall_ms={}",
        signal.map(|s| s.as_str()).unwrap_or("none"),
        if hit.is_empty() { "none".to_string() } else { hit.join(",") },
        usage.oom_kills,
        usage.pids_max_hits,
        usage.pids_peak,
        usage.cpu_usage_usec / 1000,
        usage.cpu_throttled_usec / 1000,
        usage.memory_peak / 1024,
        wall.as_millis(),
    );
    Ok(exit_code.clamp(0, 255) as u8)
}
