//! cgroups v2: one cgroup per run under /sys/fs/cgroup/cellblock/.
//!
//! The child is born inside the cgroup (clone3 + CLONE_INTO_CGROUP), so there is
//! no window where untrusted code runs without limits. After the run we read the
//! *.events / cpu.stat counters to say which limit, if any, was hit.

use std::fs;
use std::io;
use std::os::fd::{AsRawFd, OwnedFd};
use std::path::{Path, PathBuf};
use std::thread::sleep;
use std::time::{Duration, Instant};

const ROOT: &str = "/sys/fs/cgroup/cellblock";

pub struct Limits {
    pub memory_bytes: u64,
    /// CPU bandwidth in "cores", e.g. 0.5 = half of one core.
    pub cpus: f64,
    pub pids: u64,
}

pub struct Cgroup {
    pub path: PathBuf,
    /// Directory fd handed to clone3 as `cgroup`.
    pub dir: OwnedFd,
}

/// Counters read after the run. All are deltas from a fresh cgroup, so they
/// describe this run only.
#[derive(Debug, Default)]
pub struct Usage {
    pub oom_kills: u64,
    pub memory_max_hits: u64,
    pub pids_max_hits: u64,
    pub pids_peak: u64,
    pub cpu_usage_usec: u64,
    pub cpu_throttled_usec: u64,
    pub memory_peak: u64,
}

fn write(path: &Path, value: &str) -> io::Result<()> {
    fs::write(path, value).map_err(|e| io::Error::new(e.kind(), format!("write {} = {value:?}: {e}", path.display())))
}

impl Cgroup {
    pub fn create(name: &str, limits: &Limits) -> io::Result<Cgroup> {
        let root = Path::new(ROOT);
        if !root.exists() {
            fs::create_dir(root)?;
        }
        // A cgroup can only use a controller its parent enables for children.
        // /sys/fs/cgroup already delegates these to its children on Ubuntu 24.04.
        write(&root.join("cgroup.subtree_control"), "+memory +pids +cpu")?;

        let path = root.join(name);
        fs::create_dir(&path)?;
        let cg = Cgroup { dir: open_dir(&path)?, path };

        cg.set("memory.max", &limits.memory_bytes.to_string())?;
        // No swap, otherwise a memory hog pages out instead of hitting memory.max.
        if cg.path.join("memory.swap.max").exists() {
            cg.set("memory.swap.max", "0")?;
        }
        // On OOM kill every process in the cgroup, not just the biggest one.
        cg.set("memory.oom.group", "1")?;
        cg.set("pids.max", &limits.pids.to_string())?;
        // cpu.max = "<quota> <period>" in microseconds.
        let period = 100_000u64;
        let quota = (limits.cpus * period as f64).round().max(1000.0) as u64;
        cg.set("cpu.max", &format!("{quota} {period}"))?;
        Ok(cg)
    }

    fn set(&self, file: &str, value: &str) -> io::Result<()> {
        write(&self.path.join(file), value)
    }

    fn read_kv(&self, file: &str, key: &str) -> u64 {
        fs::read_to_string(self.path.join(file))
            .ok()
            .and_then(|s| {
                s.lines().find_map(|l| {
                    l.strip_prefix(key).and_then(|v| v.strip_prefix(' ')).map(|v| v.trim().parse().unwrap_or(0))
                })
            })
            .unwrap_or(0)
    }

    fn read_one(&self, file: &str) -> u64 {
        fs::read_to_string(self.path.join(file)).ok().and_then(|s| s.trim().parse().ok()).unwrap_or(0)
    }

    pub fn usage(&self) -> Usage {
        Usage {
            oom_kills: self.read_kv("memory.events", "oom_kill"),
            memory_max_hits: self.read_kv("memory.events", "max"),
            pids_max_hits: self.read_kv("pids.events", "max"),
            pids_peak: self.read_one("pids.peak"),
            cpu_usage_usec: self.read_kv("cpu.stat", "usage_usec"),
            cpu_throttled_usec: self.read_kv("cpu.stat", "throttled_usec"),
            memory_peak: self.read_one("memory.peak"),
        }
    }

    /// SIGKILL every process in the cgroup (kernel 5.14+). Used for timeouts and
    /// to make sure nothing survives the run.
    pub fn kill_all(&self) {
        let _ = self.set("cgroup.kill", "1");
    }

    /// Wait until the cgroup is empty, then remove it.
    pub fn destroy(self) {
        self.kill_all();
        let deadline = Instant::now() + Duration::from_secs(2);
        loop {
            match fs::remove_dir(&self.path) {
                Ok(()) => return,
                // EBUSY while killed processes are still exiting.
                Err(_) if Instant::now() < deadline => sleep(Duration::from_micros(200)),
                Err(e) => {
                    eprintln!("cellblock: could not remove {}: {e}", self.path.display());
                    return;
                }
            }
        }
    }

    pub fn fd(&self) -> i32 {
        self.dir.as_raw_fd()
    }
}

fn open_dir(path: &Path) -> io::Result<OwnedFd> {
    use std::os::unix::fs::OpenOptionsExt;
    let f = fs::OpenOptions::new().read(true).custom_flags(libc::O_DIRECTORY | libc::O_CLOEXEC).open(path)?;
    Ok(f.into())
}
