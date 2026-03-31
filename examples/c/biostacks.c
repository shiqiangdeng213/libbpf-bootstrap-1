#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <bpf/libbpf.h>
#include "biostacks.skel.h"

static volatile bool exiting = 0;

static void sig(int s) { exiting = 1; }

int main()
{
    struct biostacks_bpf *skel;
    unsigned long key = 0, next, val;
    int fd, err;

    signal(SIGINT, sig);
    signal(SIGTERM, sig);

    skel = biostacks_bpf__open_and_load();
    if (!skel) return 1;

    err = biostacks_bpf__attach(skel);
    if (err) {
        biostacks_bpf__destroy(skel);
        return 1;
    }

    printf("Tracing block IO... Ctrl+C to stop\n");
    while (!exiting) pause();

    fd = bpf_map__fd(skel->maps.lat_map);
    printf("\nBlock IO latency (us):\n");
    while (bpf_map_get_next_key(fd, &key, &next) == 0) {
        bpf_map_lookup_elem(fd, &next, &val);
        printf("%8llu us : %10llu times\n", next, val);
        key = next;
    }

    biostacks_bpf__destroy(skel);
    return 0;
}
