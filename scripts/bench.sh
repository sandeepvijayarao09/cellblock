#!/usr/bin/env bash
# Cold-start benchmark, 1,000 sequential runs per configuration. Run in the VM:
#   scripts/bench.sh
set -euo pipefail
cd "$(dirname "$0")/.."
export CARGO_TARGET_DIR=${CARGO_TARGET_DIR:-$HOME/cellblock-target}
cargo build --release
BIN=$CARGO_TARGET_DIR/release
OUT=bench/results-$(date +%Y-%m-%d).md
{
  echo "# Cold start, $(date -u +%Y-%m-%dT%H:%MZ)"
  echo
  echo "- kernel: $(uname -r), $(nproc) vCPUs, $(free -g | awk '/Mem:/{print $2}') GiB RAM"
  echo "- cellblock defaults: 256M memory, 1 cpu, 64 pids, seccomp enforce"
  echo
  echo "## Default (seccomp enforce)"
  sudo "$BIN/cellblock-bench" --runs 1000 --csv bench/coldstart-enforce.csv
  echo
  echo "## seccomp off (to show what the filter costs)"
  sudo "$BIN/cellblock-bench" --runs 1000 --csv bench/coldstart-off.csv -- --seccomp off
} | tee "$OUT"
