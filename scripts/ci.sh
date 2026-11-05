#!/usr/bin/env bash
# Build, then run the escape tests as root. Run inside the Linux VM:
#   scripts/ci.sh
set -euo pipefail
cd "$(dirname "$0")/.."
export CARGO_TARGET_DIR=${CARGO_TARGET_DIR:-$HOME/cellblock-target}
sudo scripts/build-rootfs.sh
cargo build --release
# Compile the tests as the normal user, then run the test binary as root.
TEST_BIN=$(cargo test --release --no-run --message-format=json 2>/dev/null \
  | grep -o '"executable":"[^"]*escape-[^"]*"' | cut -d'"' -f4)
sudo "$TEST_BIN" --test-threads=4
