// probe: escape attempts, run *inside* the sandbox by tests/escape.rs.
//
// Each attempt prints one line:
//   BLOCKED <attempt>: <errno name>   the attack failed (good)
//   ESCAPED <attempt>                 the attack worked (test failure)
// Exit status: 0 if every attempt was blocked, 1 if anything escaped.
//
// Built statically so the rootfs needs no shared libraries.

#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/sched.h>
#include <linux/if_ether.h>
#include <netinet/in.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mount.h>
#include <sys/ptrace.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

static int escaped = 0;

// Record the result of one attempt. `rc` < 0 means the syscall failed.
static void report(const char *what, long rc) {
    if (rc < 0) {
        printf("BLOCKED %s: %s\n", what, strerrorname_np(errno));
    } else {
        printf("ESCAPED %s\n", what);
        escaped = 1;
    }
}

// Read a host file by its absolute path, and via tricks that work against
// chroot (not pivot_root): /proc/1/root and a long ../ chain.
static void read_host(const char *path) {
    char buf[4096];
    const char *prefixes[] = {"", "/proc/1/root", "/proc/self/root/../../../..", "/../../../../../.."};
    for (size_t i = 0; i < sizeof prefixes / sizeof *prefixes; i++) {
        snprintf(buf, sizeof buf, "%s%s", prefixes[i], path);
        char what[4200];
        snprintf(what, sizeof what, "open(%s)", buf);
        report(what, open(buf, O_RDONLY));
    }
}

// Symlinks and hardlinks created in the writable scratch dir that point at
// the host file. Resolution happens inside the jail's root, so they dangle.
static void symlink_escape(const char *path) {
    char target[4096];
    snprintf(target, sizeof target, "../../../../../../..%s", path);
    unlink("/tmp/esc");
    if (symlink(target, "/tmp/esc") != 0) { perror("symlink"); exit(2); }
    report("open(/tmp/esc -> ../../..host path)", open("/tmp/esc", O_RDONLY));

    unlink("/tmp/esc2");
    if (symlink("/proc/1/root/../../..", "/tmp/esc2") != 0) { perror("symlink"); exit(2); }
    snprintf(target, sizeof target, "/tmp/esc2%s", path);
    report("open(/tmp/esc2 -> /proc/1/root/../.. + host path)", open(target, O_RDONLY));

    // A hardlink to a rootfs file is refused: it is a different mount (EXDEV).
    report("link(/bin/busybox, /tmp/hard)", link("/bin/busybox", "/tmp/hard"));
}

static void try_mount(void) {
    mkdir("/tmp/m", 0755);
    report("mount(tmpfs, /tmp/m)", mount("none", "/tmp/m", "tmpfs", 0, NULL));
    report("umount2(/proc)", umount2("/proc", MNT_DETACH));
    report("mount(remount / read-write)", mount(NULL, "/", NULL, MS_REMOUNT | MS_BIND, NULL));
    // A nested user namespace would give back a full set of capabilities.
    report("unshare(CLONE_NEWUSER)", unshare(CLONE_NEWUSER));
    report("unshare(CLONE_NEWNS)", unshare(CLONE_NEWNS));
    // clone3 hides its flags behind a pointer, so the clone() flag filter
    // cannot see them. cellblock forces clone3 to ENOSYS instead.
    struct clone_args ca = {.flags = CLONE_NEWUSER, .exit_signal = SIGCHLD};
    long pid = syscall(SYS_clone3, &ca, sizeof ca);
    if (pid == 0) _exit(0);  // only reached if the escape worked
    report("clone3(CLONE_NEWUSER)", pid);
}

static void try_ptrace(pid_t host_pid) {
    char what[64];
    snprintf(what, sizeof what, "ptrace(ATTACH, %d)", host_pid);
    report(what, ptrace(PTRACE_ATTACH, host_pid, 0, 0));
    snprintf(what, sizeof what, "ptrace(SEIZE, %d)", host_pid);
    report(what, ptrace(PTRACE_SEIZE, host_pid, 0, 0));
    // pid 1 in our namespace is whatever cellblock exec'd (possibly us).
    report("ptrace(ATTACH, 1)", ptrace(PTRACE_ATTACH, 1, 0, 0));
}

// Like try_ptrace, but against our own child: this one is *inside* the
// sandbox, so only seccomp blocks it. Used by the enforce-mode test only.
static void try_ptrace_child(void) {
    pid_t c = fork();
    if (c == 0) { pause(); _exit(0); }
    report("ptrace(ATTACH, own child)", ptrace(PTRACE_ATTACH, c, 0, 0));
    kill(c, SIGKILL);
    waitpid(c, NULL, 0);
}

static void raw_sockets(void) {
    report("socket(AF_INET, SOCK_RAW, ICMP)", socket(AF_INET, SOCK_RAW, IPPROTO_ICMP));
    report("socket(AF_INET6, SOCK_RAW, ICMPV6)", socket(AF_INET6, SOCK_RAW, IPPROTO_ICMPV6));
    report("socket(AF_PACKET, SOCK_RAW, ETH_P_ALL)", socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL)));
}

static void network(void) {
    // Public internet, plus the Lima host gateway (192.168.5.2).
    const char *addrs[] = {"1.1.1.1", "8.8.8.8", "192.168.5.2"};
    for (size_t i = 0; i < sizeof addrs / sizeof *addrs; i++) {
        int s = socket(AF_INET, SOCK_STREAM, 0);
        if (s < 0) { report("socket(AF_INET, SOCK_STREAM)", s); continue; }
        struct sockaddr_in sa = {.sin_family = AF_INET, .sin_port = htons(80)};
        inet_pton(AF_INET, addrs[i], &sa.sin_addr);
        char what[64];
        snprintf(what, sizeof what, "connect(%s:80)", addrs[i]);
        report(what, connect(s, (struct sockaddr *)&sa, sizeof sa));
        close(s);
    }
    int u = socket(AF_INET, SOCK_DGRAM, 0);
    struct sockaddr_in dns = {.sin_family = AF_INET, .sin_port = htons(53)};
    inet_pton(AF_INET, "8.8.8.8", &dns.sin_addr);
    report("sendto(8.8.8.8:53 UDP)", sendto(u, "x", 1, 0, (struct sockaddr *)&dns, sizeof dns));
}

// Push a character into the terminal's input queue (keystroke injection).
static void tiocsti(void) {
    char c = 'x';
    report("ioctl(0, TIOCSTI)", ioctl(0, TIOCSTI, &c));
}

// Allocate and touch memory until something stops us. Under cellblock the
// OOM killer ends this; reaching the end means the limit did not work.
static void memhog(void) {
    for (size_t mb = 0;; mb++) {
        char *p = malloc(1 << 20);
        if (!p) { printf("BLOCKED malloc after %zu MiB: ENOMEM\n", mb); return; }
        memset(p, 1, 1 << 20);
        if (mb == 16384) { printf("ESCAPED allocated 16 GiB\n"); escaped = 1; return; }
    }
}

// The classic C fork bomb: every process forks forever. pids.max caps the
// total; the wall-clock timeout then kills the whole cgroup. Never returns.
static void forkbomb(void) {
    for (;;) fork();
}

// Not an attack: checks that threads still work under the filter. glibc's
// pthread_create tries clone3 first and falls back to clone on ENOSYS.
static void *thread_fn(void *arg) { return arg; }
static int threads(void) {
    pthread_t t;
    int rc = pthread_create(&t, NULL, thread_fn, NULL);
    if (rc != 0) { printf("FAILED pthread_create: %s\n", strerrorname_np(rc)); return 1; }
    pthread_join(t, NULL);
    printf("OK thread created and joined\n");
    return 0;
}

// Burn CPU for `secs` seconds of wall time (used to check cpu.max throttling).
static void spin(int secs) {
    time_t end = time(NULL) + secs;
    volatile unsigned long x = 0;
    while (time(NULL) < end) x++;
}

int main(int argc, char **argv) {
    setvbuf(stdout, NULL, _IONBF, 0);
    if (argc < 2) { fprintf(stderr, "usage: probe <test> [arg]\n"); return 2; }
    const char *t = argv[1];
    const char *arg = argc > 2 ? argv[2] : "";
    if (!strcmp(t, "read-host")) read_host(arg);
    else if (!strcmp(t, "symlink")) symlink_escape(arg);
    else if (!strcmp(t, "mount")) try_mount();
    else if (!strcmp(t, "ptrace")) try_ptrace(atoi(arg));
    else if (!strcmp(t, "ptrace-child")) try_ptrace_child();
    else if (!strcmp(t, "raw-socket")) raw_sockets();
    else if (!strcmp(t, "network")) network();
    else if (!strcmp(t, "tiocsti")) tiocsti();
    else if (!strcmp(t, "memhog")) memhog();
    else if (!strcmp(t, "forkbomb")) forkbomb();
    else if (!strcmp(t, "threads")) return threads();
    else if (!strcmp(t, "spin")) spin(atoi(arg));
    else { fprintf(stderr, "unknown test %s\n", t); return 2; }
    return escaped;
}
