// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* Copyright (c) 2020 Facebook */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "bootstrap.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

/* 定义哈希表，用来存放进程的启动信息 */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 8192);			/* 系统中应该不会同时存在8192个正在运行的进程 */
	__type(key, pid_t);					/* 进程id作为键 */
	__type(value, u64);					/* 启动时候的时间戳作为值 */
} exec_start SEC(".maps");
/* 定义ringbuf用于像用户空间传递数据 */
struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} rb SEC(".maps");

const volatile unsigned long long min_duration_ns = 0;

SEC("tp/sched/sched_process_exec")
int handle_exec(struct trace_event_raw_sched_process_exec *ctx)
{
	struct task_struct *task;
	unsigned fname_off;
	struct event *e;										/* 自定义的结构体用来描述进程信息 */
	pid_t pid;
	u64 ts;

	/* remember time exec() was executed for this PID */
	pid = bpf_get_current_pid_tgid() >> 32;					/* 调用sched_process_exec函数的进程id */
	ts = bpf_ktime_get_ns();								/* 调用函数时候的时间戳 */
	bpf_map_update_elem(&exec_start, &pid, &ts, BPF_ANY);	/* 记录进程id和调用时候的时间戳到map */

	/* don't emit exec events when minimum duration is specified */
	if (min_duration_ns)
		return 0;

	/* reserve sample from BPF ringbuf */
	e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);			/* 申请ringbuf */
	if (!e)
		return 0;

	/* fill out the sample with data */
	task = (struct task_struct *)bpf_get_current_task();	/* 获取调用这个进程的任务结构体 */

	e->exit_event = false;									/* 置位flase表示进程还没退出 */
	e->pid = pid;											/* 记录进程id */
	e->ppid = BPF_CORE_READ(task, real_parent, tgid);		/* 获取父进程id */
	bpf_get_current_comm(&e->comm, sizeof(e->comm));		/* 获取进程名字，将名字拷贝到e->comm数组中 */

	fname_off = ctx->__data_loc_filename & 0xFFFF;
	bpf_probe_read_str(&e->filename, sizeof(e->filename), (void *)ctx + fname_off);	/* 获取文件路径，比如:/usr/bin/grep */

	/* successfully submit it to user-space for post-processing */
	bpf_ringbuf_submit(e, 0);								/* 进程开始执行的时候把数据提交到用户空间 */
	return 0;
}

SEC("tp/sched/sched_process_exit")
int handle_exit(struct trace_event_raw_sched_process_template *ctx)
{
	struct task_struct *task;
	struct event *e;
	pid_t pid, tid;
	u64 id, ts, *start_ts, duration_ns = 0;

	/* get PID and TID of exiting thread/process */
	id = bpf_get_current_pid_tgid();						/* 获取线程id */
	pid = id >> 32;											/* 获取进程id */
	tid = (u32)id;											/* 线程id */

	/* ignore thread exits */
	if (pid != tid)											/* 判断退出的是否是线程，是线程的话不记录 */
		return 0;

	/* if we recorded start of the process, calculate lifetime duration */
	start_ts = bpf_map_lookup_elem(&exec_start, &pid);		/* 通过进程id去查找map，看是否有过开始执行的记录 */
	if (start_ts)
		duration_ns = bpf_ktime_get_ns() - *start_ts;		/* 当前的时间戳减去开始执行的时间戳得到进程执行的时长 */
	else if (min_duration_ns)
		return 0;
	bpf_map_delete_elem(&exec_start, &pid);					/* 进程已经退出了，删除对应的map */

	/* if process didn't live long enough, return early */
	if (min_duration_ns && duration_ns < min_duration_ns)	/* 运行的间隔如果小于设置的间隔，就不记录了 */
		return 0;

	/* reserve sample from BPF ringbuf */
	e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);			/* 申请ringbuf */
	if (!e)
		return 0;

	/* fill out the sample with data */
	task = (struct task_struct *)bpf_get_current_task();	/* 拿到调用这个sched_process_exit的任务结构体 */

	e->exit_event = true;									/* 标记进程已经退出了 */
	e->duration_ns = duration_ns;							/* 记录总的运行时长 */
	e->pid = pid;											/* 记录进程id */
	e->ppid = BPF_CORE_READ(task, real_parent, tgid);		/* 获取父进程id */
	e->exit_code = (BPF_CORE_READ(task, exit_code) >> 8) & 0xff;	/* 进程的退出码 */
	bpf_get_current_comm(&e->comm, sizeof(e->comm));		/* 获取进程的comm */

	/* send data to user-space for post-processing */
	bpf_ringbuf_submit(e, 0);								/* 进程退出的时候把数据提交到用户空间 */
	return 0;
}
