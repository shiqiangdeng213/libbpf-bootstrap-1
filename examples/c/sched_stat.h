#ifndef __SCHED_STAT_H
#define __SCHED_STAT_H

enum EVENT_TYPE {
	BLOCK = 0,				// 不可中断阻塞时间	D 状态（I/O、锁）
	SLEEP,					// 可中断睡眠	S 状态（sleep、wait）
	IOWAIT,					// 专门等待 I/O	D 状态（专门 IO）
	RUN_WAIT
};

struct event {
    pid_t pid;
    char comm[16];
	unsigned long block_time_ns;		// 阻塞的时长:ns
	enum EVENT_TYPE event_type;
};

#endif


