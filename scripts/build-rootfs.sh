#!/usr/bin/env bash
# Build the sandbox root filesystem: busybox + three static test programs.
# Run as root inside the Linux VM:  sudo scripts/build-rootfs.sh [dest]
set -euo pipefail
DEST=${1:-/var/lib/cellblock/rootfs}
SRC=$(cd "$(dirname "$0")/../rootfs" && pwd)

rm -rf "$DEST"
mkdir -p "$DEST"/{bin,etc,proc,dev,tmp}
# Empty mount points: /proc, /dev and /tmp get fresh mounts at run time.

cp /bin/busybox "$DEST/bin/busybox"         # from the busybox-static package
for app in $("$DEST/bin/busybox" --list); do
  [ "$app" = busybox ] || ln -s busybox "$DEST/bin/$app"
done

for prog in probe stamp suid-probe; do
  gcc -static -O2 -Wall -o "$DEST/bin/$prog" "$SRC/$prog.c"
done
# The setuid test needs a real setuid-root binary in the image.
chown root:root "$DEST/bin/suid-probe"
chmod 4755 "$DEST/bin/suid-probe"

echo "sandbox:x:1000:1000:sandbox:/tmp:/bin/sh" > "$DEST/etc/passwd"
echo "sandbox:x:1000:" > "$DEST/etc/group"
echo "rootfs ready at $DEST ($(du -sh "$DEST" | cut -f1))"
