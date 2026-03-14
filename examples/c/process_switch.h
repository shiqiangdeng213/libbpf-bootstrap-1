/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
/* Copyright (c) 2020 Facebook */
#ifndef __BOOTSTRAP_H
#define __BOOTSTRAP_H

#define TASK_COMM_LEN	 16				/* 进程名字长度通常是16字节 */
#define MAX_FILENAME_LEN 127			/* 文件名加路径长度通常是127字节 */

/* 描述进程信息 */
struct process_info {
	//u32 prev_cpu;					/* 上一次运行cpu(参数中没有所以这个成员暂时不用)*/
	pid_t prev_pid;					/* 当前运行的进程 */
	pid_t next_pid;					/* 下一个即将运行的进程 */
	char prev_comm[16];				/* 当前线程名字 */
	char next_comm[16];				/* 下一个线程名字 */
	unsigned long current_time;	 	/* 当前调用schedule函数的时间 */
	//unsigned long last_time;		/* 上一次调用schedule函数的时间 */
	unsigned long runtime;			/* 两次调度之间的时间间隔 */
};

#endif /* __BOOTSTRAP_H */

