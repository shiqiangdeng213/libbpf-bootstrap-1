// SPDX-License-Identifier: GPL-2.0
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "migrate_monitor.h"

// 输出到用户态
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} rb SEC(".maps");

// -------------------------
// 监听：任意CPU之间迁移
// -------------------------
SEC("tp/sched/sched_migrate_task")
int handle_migrate(struct trace_event_raw_sched_migrate_task *ctx)
{
    struct event e = {};

    e.pid = ctx->pid;
    e.orig_cpu = ctx->orig_cpu;
    e.dest_cpu = ctx->dest_cpu;
    e.src_nid = -1;
    e.dst_nid = -1;
    e.is_numa_migrate = 0;
	
    bpf_core_read_str(e.comm, sizeof(e.comm), &ctx->comm);

    bpf_ringbuf_output(&rb, &e, sizeof(e), 0);
    return 0;
}


// -------------------------
// 监听：仅跨NUMA节点迁移
// -------------------------
SEC("tp/sched/sched_move_numa")
int handle_move_numa(struct trace_event_raw_sched_move_numa *ctx)
{
	struct task_struct *task;
    struct event e = {};

    e.pid = ctx->pid;
    e.orig_cpu = ctx->src_cpu;
    e.dest_cpu = ctx->dst_cpu;
    e.src_nid = ctx->src_nid;
    e.dst_nid = ctx->dst_nid;
    e.is_numa_migrate = 1;

	task = (struct task_struct *)bpf_get_current_task();
	BPF_CORE_READ_STR_INTO(e.comm, task, comm);
	
    bpf_ringbuf_output(&rb, &e, sizeof(e), 0);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";

