// stamp: the "user code" for the cold-start benchmark. The first thing main()
// does is read CLOCK_MONOTONIC and print it in nanoseconds. CLOCK_MONOTONIC is
// not namespaced here (no time namespace), so the benchmark on the host can
// subtract its own launch timestamp from this value.
#include <stdio.h>
#include <time.h>

int main(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    printf("%lld\n", (long long)ts.tv_sec * 1000000000LL + ts.tv_nsec);
    return 0;
}
