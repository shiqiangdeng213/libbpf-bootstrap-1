// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* Copyright (c) 2020 Facebook */
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

//int my_pid = {0};

/* 定义map，用来保存comm和pid */

struct comm {
	char comm[30];
	int pid;
	int count;
};

//struct comm my_test = {0};						/* 这个结构体好像没法放到全局变量去，编译阶段就报错了 */

/* Create an array with 1 entry instead of a global variable
 * which does not work with older kernels */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	//__uint(type, BPF_MAP_TYPE_RINGBUF);			/* 创建类型为RINGBUF的MAP(创建这个类型会报错) */
	__uint(max_entries, 1024);
	__type(key, int);								/* 使用pid作为map的key */
	__type(value, struct comm);
} my_pid_map SEC(".maps");

SEC("tp/writeback/writeback_start")					/* 定义一个程序类型tracepoint */
int func_comm_test(void *ctx)
{
	//u64 *cts, *pts, *cstate, *pstate, prev_state, cur_ts, delta;	/* 变量定义未使用也会报错 */
	struct comm my_test = {0};
	struct comm *get_info = NULL;
	int pid = 0;
	//char comm[30] = {0};							/* 保存调用writeback_start跟踪点的进程名 */
	//int pid = 0;									/* 保存调用writeback_start跟踪点的进程ID */
	my_test.pid = bpf_get_current_pid_tgid() >> 32;
	bpf_get_current_comm(my_test.comm, 30);
	/* 查找map当中的元素 */
	get_info = bpf_map_lookup_elem(&my_pid_map, &my_test.pid);
	/* 从map中查找的和当前的进程不是同一个进程，那就写进去 */
	if (get_info != NULL) {
		get_info->count += 1;
		bpf_map_update_elem(&my_pid_map, &my_test.pid, &get_info, BPF_EXIST);
	}
	else {
		my_test.count += 1;
		bpf_map_update_elem(&my_pid_map, &my_test.pid, &my_test, BPF_NOEXIST);
	}

	bpf_printk("dsq_debug:%d %s\n", my_test.pid, my_test.comm);

	return 0;
}

