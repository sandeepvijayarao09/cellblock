//! Cold-start benchmark: time from launching `cellblock run` to the first line
//! of the user's main() (the `stamp` program prints CLOCK_MONOTONIC there).
//!
//!   sudo cellblock-bench --runs 1000 [--csv out.csv] [-- <extra cellblock flags>]
//!
//! Runs are sequential, so each one pays the full cost: exec of cellblock,
//! cgroup creation, clone3 into 7 namespaces, mounts, pivot_root, privilege
//! drop, seccomp install and execve of the user program.

use clap::Parser;
use std::io::Write;
use std::process::{Command, Stdio};

#[derive(Parser)]
struct Args {
    #[arg(long, default_value_t = 1000)]
    runs: usize,
    /// Untimed runs first, to warm the page cache.
    #[arg(long, default_value_t = 20)]
    warmup: usize,
    /// Path of the cellblock binary (default: next to this one).
    #[arg(long)]
    cellblock: Option<String>,
    /// Write every sample here (start_us,total_us).
    #[arg(long)]
    csv: Option<String>,
    /// Extra flags passed to `cellblock run`.
    #[arg(last = true)]
    flags: Vec<String>,
}

fn now_ns() -> i64 {
    let mut ts = libc::timespec { tv_sec: 0, tv_nsec: 0 };
    unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut ts) };
    ts.tv_sec * 1_000_000_000 + ts.tv_nsec
}

/// One run. Returns (launch -> first user instruction, launch -> cellblock exited), in ns.
fn sample(bin: &str, flags: &[String]) -> (i64, i64) {
    let t0 = now_ns();
    let out = Command::new(bin)
        .arg("run")
        .args(flags)
        .args(["--", "/bin/stamp"])
        .stderr(Stdio::null())
        .output()
        .expect("spawn cellblock");
    let t_end = now_ns();
    assert!(out.status.success(), "cellblock failed: {:?}", out.status);
    let t_user: i64 = String::from_utf8_lossy(&out.stdout).trim().parse().expect("stamp output");
    (t_user - t0, t_end - t0)
}

/// Nearest-rank percentile of a sorted slice.
fn pct(sorted: &[i64], p: f64) -> f64 {
    let rank = ((p / 100.0) * sorted.len() as f64).ceil().max(1.0) as usize;
    sorted[rank - 1] as f64 / 1e6
}

fn main() {
    let a = Args::parse();
    let bin = a.cellblock.clone().unwrap_or_else(|| {
        let me = std::env::current_exe().unwrap();
        me.with_file_name("cellblock").to_string_lossy().into_owned()
    });
    for _ in 0..a.warmup {
        sample(&bin, &a.flags);
    }
    let samples: Vec<(i64, i64)> = (0..a.runs).map(|_| sample(&bin, &a.flags)).collect();

    if let Some(path) = &a.csv {
        let mut f = std::fs::File::create(path).unwrap();
        writeln!(f, "start_us,total_us").unwrap();
        for (s, t) in &samples {
            writeln!(f, "{},{}", s / 1000, t / 1000).unwrap();
        }
    }
    let mut start: Vec<i64> = samples.iter().map(|s| s.0).collect();
    let mut total: Vec<i64> = samples.iter().map(|s| s.1).collect();
    start.sort_unstable();
    total.sort_unstable();
    let mean = |v: &[i64]| v.iter().sum::<i64>() as f64 / v.len() as f64 / 1e6;
    println!("runs={} flags={:?}", a.runs, a.flags);
    println!();
    println!("| metric | p50 ms | p90 ms | p99 ms | max ms | mean ms |");
    println!("|---|---|---|---|---|---|");
    for (name, v) in [("launch -> first user instruction", &start), ("launch -> sandbox torn down", &total)] {
        println!(
            "| {name} | {:.2} | {:.2} | {:.2} | {:.2} | {:.2} |",
            pct(v, 50.0),
            pct(v, 90.0),
            pct(v, 99.0),
            pct(v, 100.0),
            mean(v)
        );
    }
}
