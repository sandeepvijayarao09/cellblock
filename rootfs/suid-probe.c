// suid-probe: installed in the rootfs as root-owned and mode 4755 (setuid).
// On a normal system running it gives euid 0. Inside cellblock it must not:
// no_new_privs, the nosuid mount and the unmapped owner each prevent it.
#include <stdio.h>
#include <unistd.h>

int main(void) {
    uid_t r = getuid(), e = geteuid();
    printf("ruid=%d euid=%d\n", r, e);
    if (e == 0) { printf("ESCAPED setuid binary gave euid 0\n"); return 1; }
    if (setuid(0) == 0) { printf("ESCAPED setuid(0) succeeded\n"); return 1; }
    printf("BLOCKED setuid binary: euid stayed %d\n", e);
    return 0;
}
