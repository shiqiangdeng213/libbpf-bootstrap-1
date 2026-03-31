// SPDX-License-Identifier: GPL-2.0
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 8192);
	__type(key, pid_t);
	__type(value, u64); 
} wake_up SEC(".maps");

// 直方图 MAP：key = 延迟 ns, value = 计数
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1024);
	__type(key, u64);
	__type(value, u64);
} lat_hist SEC(".maps");

SEC("tp/sched/sched_wakeup")
int handle_wakeup(struct trace_event_raw_sched_wakeup_template *ctx)
{
	pid_t pid = ctx->pid;
	u64 ts = bpf_ktime_get_ns();	
	bpf_map_update_elem(&wake_up, &pid, &ts, BPF_ANY);
	
	return 0;
}

SEC("tp/sched/sched_wakeup_new")
int handle_wakeup_new(struct trace_event_raw_sched_wakeup_template *ctx)
{
	pid_t pid = ctx->pid;
	u64 ts = bpf_ktime_get_ns();	
	bpf_map_update_elem(&wake_up, &pid, &ts, BPF_ANY);
	
	return 0;
}

SEC("tp/sched/sched_switch")
int handle_switch(struct trace_event_raw_sched_switch *ctx)
{
	pid_t pid = ctx->next_pid;
	u64 *tsp, delta, us, *cnt;
	
	tsp = bpf_map_lookup_elem(&wake_up, &pid);
	if (!tsp)
		return 0;

	// 计算调度延迟
	delta = bpf_ktime_get_ns() - *tsp;
	us = delta / 1000; // 转微秒

	// 更新直方图
	cnt = bpf_map_lookup_elem(&lat_hist, &us);
	if (cnt)
		__sync_fetch_and_add(cnt, 1);
	else {
		u64 init = 1;
		bpf_map_update_elem(&lat_hist, &us, &init, BPF_ANY);
	}

	bpf_map_delete_elem(&wake_up, &pid);
	
	return 0;
}

char LICENSE[] SEC("license") = "GPL";

