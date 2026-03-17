// SPDX-License-Identifier: GPL-2.0
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <string.h>
#include <unistd.h>
#include <bpf/libbpf.h>
#include "runqlat.skel.h"
#include "runqlat.h"

static volatile bool exiting = false;

void sig_handler(int sig)
{
    exiting = true;
}

int handle_event(void *ctx, void *data, size_t sz)
{
    const struct event *e = data;
	
	printf("pid=%-6d comm=%-16s on_cpu=%-6d prio=%-6d run_lat=%ld\n", e->pid, e->comm, e->target_cpu, e->prio, e->lat_time_ns);
	
    return 0;
}

int main(int argc, char **argv)
{
    struct runqlat_bpf *skel;
    struct ring_buffer *rb = NULL;
    int err;

    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    skel = runqlat_bpf__open_and_load();
    if (!skel) {
        fprintf(stderr, "open failed\n");
		
        return 1;
    }

    rb = ring_buffer__new(bpf_map__fd(skel->maps.rb), handle_event, NULL, NULL);
    if (!rb) {
        err = -1;
        fprintf(stderr, "ringbuf failed\n");
	
        goto cleanup;
    }

    err = runqlat_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "attach failed\n");
		
        goto cleanup;
    }

    printf("开始监控进程调度延迟...\n\n");

    while (!exiting) {
        ring_buffer__poll(rb, 100);
    }
	
cleanup:
    ring_buffer__free(rb);
    runqlat_bpf__destroy(skel);
	
    return err < 0 ? -err : 0;
}



