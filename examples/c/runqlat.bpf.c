// SPDX-License-Identifier: GPL-2.0
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "runqlat.h"

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 8192);
	__type(key, pid_t);
	__type(value, u64); 
} wake_up SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} rb SEC(".maps");

SEC("tp/sched/sched_wakeup")
int handle_wakeup(struct trace_event_raw_sched_wakeup_template *ctx)
{
	pid_t pid = ctx->pid;
	u64 ts = bpf_ktime_get_ns();
	
	bpf_map_update_elem(&wake_up, &pid, &ts, BPF_ANY);
	return 0;
}

SEC("tp/sched/sched_switch")
int handle_switch(struct trace_event_raw_sched_switch *ctx)
{
	struct event *e;
	pid_t pid = ctx->next_pid;
	u64 *tsp;
	
	tsp = bpf_map_lookup_elem(&wake_up, &pid);
	if (!tsp)
		return 0;
	
	e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
	if (!e) {
		bpf_map_delete_elem(&wake_up, &pid);
		return 0;
	}
	
	e->pid = pid;
	e->prio = ctx->next_prio;
	e->target_cpu = bpf_get_smp_processor_id();
	e->wakeup_time_ns = *tsp;
	e->lat_time_ns = bpf_ktime_get_ns() - *tsp;
	
	bpf_core_read_str(e->comm, sizeof(e->comm), &ctx->next_comm);
	
	bpf_ringbuf_submit(e, 0);
	bpf_map_delete_elem(&wake_up, &pid);

	return 0;
}

char LICENSE[] SEC("license") = "GPL";