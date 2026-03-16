// SPDX-License-Identifier: GPL-2.0
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <string.h>
#include <unistd.h>
#include <bpf/libbpf.h>
#include "migrate_monitor.skel.h"
#include "migrate_monitor.h"

static volatile bool exiting = false;

void sig_handler(int sig)
{
    exiting = true;
}

int handle_event(void *ctx, void *data, size_t sz)
{
    const struct event *e = data;
	
    if (e->is_numa_migrate) {
        printf("[NUMA 迁移] pid=%-6d comm=%-16s | node %d → %d\n",
               e->pid, e->comm, e->src_nid, e->dst_nid);
    } else {
        printf("[CPU 迁移] pid=%-6d comm=%-16s | cpu %d → %d\n",
               e->pid, e->comm, e->orig_cpu, e->dest_cpu);
    }
	
    return 0;
}

int main(int argc, char **argv)
{
    struct migrate_monitor_bpf *skel;
    struct ring_buffer *rb = NULL;
    int err;

    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    skel = migrate_monitor_bpf__open_and_load();
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

    err = migrate_monitor_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "attach failed\n");
        goto cleanup;
    }

    printf("开始监控 CPU 迁移 & NUMA 迁移...\n\n");

    while (!exiting) {
        ring_buffer__poll(rb, 100);
    }

cleanup:
    ring_buffer__free(rb);
    migrate_monitor_bpf__destroy(skel);
    return err < 0 ? -err : 0;
}

