// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* Copyright (c) 2020 Facebook */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "process_switch.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

/* 哈希表：key = 线程TID，value = 切换时记录的信息（含开始时间） */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 8192);
	__type(key, pid_t);
	__type(value, struct process_info);
} exec_start SEC(".maps");

/* 环形缓冲区：发给用户态 */
struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} rb SEC(".maps");

/*
 * 调度切换事件：统计线程运行时间
 * 逻辑：
 *  1. 被换下的进程(prev) → 计算运行时长并上报
 *  2. 新换上的进程(next) → 记录开始时间
 */
SEC("tp/sched/sched_switch")
int handle_sched_switch(struct trace_event_raw_sched_switch *ctx)
{
	struct process_info *info, *send_info;
	u64 current_time;
	pid_t prev_pid, next_pid;

	current_time = bpf_ktime_get_ns();
	prev_pid = ctx->prev_pid;	// 被换下的线程（要统计时长）
	next_pid = ctx->next_pid;	// 新换上的线程（记录开始时间）

	// ----------------------
	// 第一步：统计【被换下进程】的运行时长
	// ----------------------
	info = bpf_map_lookup_elem(&exec_start, &prev_pid);
	if (info) {
		// 计算运行时间
		info->runtime = current_time - info->current_time;
		
		// 填充完整信息（当前进程名、下一个进程名）
		bpf_core_read_str(info->prev_comm, sizeof(info->prev_comm), &ctx->prev_comm);
		bpf_core_read_str(info->next_comm, sizeof(info->next_comm), &ctx->next_comm);
		
		// 发送到用户态
		send_info = bpf_ringbuf_reserve(&rb, sizeof(*send_info), 0);
		if (send_info) {
			__builtin_memcpy(send_info, info, sizeof(struct process_info));
			bpf_ringbuf_submit(send_info, 0);
		}

		// 用完删除，避免脏数据
		bpf_map_delete_elem(&exec_start, &prev_pid);
	}

	// ----------------------
	// 第二步：记录【新换上进程】的开始时间
	// ----------------------
	struct process_info new_info = {};
	new_info.prev_pid = prev_pid;
	new_info.next_pid = next_pid;
	new_info.current_time = current_time;

	// 保存本次切换的进程名
	bpf_core_read_str(new_info.prev_comm, sizeof(new_info.prev_comm), &ctx->prev_comm);
	bpf_core_read_str(new_info.next_comm, sizeof(new_info.next_comm), &ctx->next_comm);

	bpf_map_update_elem(&exec_start, &next_pid, &new_info, BPF_ANY);

	return 0;
}

/* 线程退出时清理 map */
SEC("tp/sched/sched_process_exit")
int handle_exit(struct trace_event_raw_sched_process_template *ctx)
{
	pid_t tid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
	bpf_map_delete_elem(&exec_start, &tid);
	
	return 0;
}

