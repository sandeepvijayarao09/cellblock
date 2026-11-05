#!/usr/bin/env bash
# Run a command with --seccomp log and list the syscalls it made that are
# NOT in the allowlist, by name. Run in the VM:
#   scripts/seccomp-log.sh /bin/sh -c 'wget -q http://example.com'
set -euo pipefail
BIN=${CARGO_TARGET_DIR:-$HOME/cellblock-target}/release/cellblock
# Kernel audit records look like: audit: type=1326 ... comm="sh" ... syscall=167 ...
sudo dmesg --clear
sudo "$BIN" run --seccomp log -- "$@" || true
# Syscall number -> name, from the C headers for this architecture.
declare -A NAME
while read -r _ nr num; do NAME[$num]=${nr#__NR_}; done < <(
  echo '#include <sys/syscall.h>' | gcc -E -dM - | awk '$2 ~ /^__NR_/ && $3 ~ /^[0-9]+$/')
echo "--- syscalls outside the allowlist (count, comm, syscall):"
sudo dmesg | grep -o 'comm="[^"]*".*syscall=[0-9]*' | sed -E 's/comm="([^"]*)".*syscall=([0-9]+)/\1 \2/' \
  | sort | uniq -c | while read -r count comm num; do echo "$count $comm ${NAME[$num]:-?}($num)"; done
