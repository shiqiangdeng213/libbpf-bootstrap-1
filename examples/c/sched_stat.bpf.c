// SPDX-License-Identifier: GPL-2.0
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "sched_stat.h"

// 输出到用户态
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} rb SEC(".maps");

struct trace_event_raw_sched_stat_template {
	struct trace_entry ent;
	char comm[16];
	pid_t pid;
	u64 delay;
	char __data[0];
};

// 跟踪等锁或者等待io
SEC("tp/sched/sched_stat_blocked")		// 等锁或者等待io
int handle_blocked(struct trace_event_raw_sched_stat_template *ctx)
{
	struct event e = {};
	pid_t pid;
	
	pid = ctx->pid;
	e.pid = pid;
	e.block_time_ns = ctx->delay;
	bpf_core_read_str(e.comm, sizeof(e.comm), &ctx->comm);
	
	e.event_type = BLOCK;
	bpf_ringbuf_output(&rb, &e, sizeof(e), 0);
}

// 可中断睡眠等待
SEC("tp/sched/sched_stat_sleep")		
int handle_sleep(struct trace_event_raw_sched_stat_template *ctx)
{
	struct event e = {};
	pid_t pid;
	
	pid = ctx->pid;
	e.pid = pid;
	e.block_time_ns = ctx->delay;
	bpf_core_read_str(e.comm, sizeof(e.comm), &ctx->comm);
	
	e.event_type = SLEEP;
	bpf_ringbuf_output(&rb, &e, sizeof(e), 0);
}

// 等待IO
SEC("tp/sched/sched_stat_iowait")
int handle_iowait(struct trace_event_raw_sched_stat_template *ctx)
{
	struct event e = {};
	pid_t pid;
	
	pid = ctx->pid;
	e.pid = pid;
	e.block_time_ns = ctx->delay;
	bpf_core_read_str(e.comm, sizeof(e.comm), &ctx->comm);
	
	e.event_type = IOWAIT;
	bpf_ringbuf_output(&rb, &e, sizeof(e), 0);
}

// 在运行队列中等待
SEC("tp/sched/sched_stat_wait")	
int handle_wait(struct trace_event_raw_sched_stat_template *ctx)
{
	struct event e = {};
	pid_t pid;
	
	pid = ctx->pid;
	e.pid = pid;
	e.block_time_ns = ctx->delay;
	bpf_core_read_str(e.comm, sizeof(e.comm), &ctx->comm);
	
	e.event_type = RUN_WAIT;
	bpf_ringbuf_output(&rb, &e, sizeof(e), 0);
}

char LICENSE[] SEC("license") = "GPL";

