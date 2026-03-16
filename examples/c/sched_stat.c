// SPDX-License-Identifier: GPL-2.0
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <string.h>
#include <unistd.h>
#include <bpf/libbpf.h>
#include "sched_stat.skel.h"
#include "sched_stat.h"

static volatile bool exiting = false;

void sig_handler(int sig)
{
    exiting = true;
}

int handle_event(void *ctx, void *data, size_t sz)
{
    const struct event *e = data;
	
    if (e->event_type == BLOCK) {
        printf("[等锁或者等待IO] pid=%-6d comm=%-16s delay=%ld\n",
               e->pid, e->comm, e->block_time_ns);
    } else if (e->event_type == SLEEP) {
        printf("[睡眠等待] pid=%-6d comm=%-16s delay=%ld\n",
               e->pid, e->comm, e->block_time_ns);
    } else if (e->event_type == IOWAIT) {
		printf("[等待IO] pid=%-6d comm=%-16s delay=%ld\n",
               e->pid, e->comm, e->block_time_ns);
	} else if (e->event_type == RUN_WAIT) {
		printf("[队列等待] pid=%-6d comm=%-16s delay=%ld\n",
               e->pid, e->comm, e->block_time_ns);
	}
	
    return 0;
}

int main(int argc, char **argv)
{
    struct sched_stat_bpf *skel;
    struct ring_buffer *rb = NULL;
    int err;

    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    skel = sched_stat_bpf__open_and_load();
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

    err = sched_stat_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "attach failed\n");
		
        goto cleanup;
    }

    printf("开始监控进程等待事件...\n\n");

    while (!exiting) {
        ring_buffer__poll(rb, 100);
    }

cleanup:
    ring_buffer__free(rb);
    sched_stat_bpf__destroy(skel);
	
    return err < 0 ? -err : 0;
}


