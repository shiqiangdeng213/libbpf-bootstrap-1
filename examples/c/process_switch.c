// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2020 Facebook */
#include <argp.h>
#include <signal.h>
#include <stdio.h>
#include <time.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include "process_switch.h"
#include "process_switch.skel.h"

static volatile bool exiting = false;

static void sig_handler(int sig)
{
	exiting = true;
}

static int handle_event(void *ctx, void *data, size_t data_sz)
{
	const struct process_info *e = data;
	struct tm *tm;
	char ts[32];
	time_t t;
	/* 拿到系统时间 */
	time(&t);
	tm = localtime(&t);
	strftime(ts, sizeof(ts), "%H:%M:%S", tm);
	
	printf("%-8s\t %-5d\t\t %-16s\t %-7d\t %-7s\t\t %ld\n", ts, e->prev_pid, e->prev_comm, e->next_pid, e->next_comm, e->runtime);

	return 0;
}

int main(int argc, char **argv)
{
	struct ring_buffer *rb = NULL;			/* 描述一个ringbuf */
	struct process_switch_bpf *skel;		/* 手脚架文件 */
	int err;
	
	/* Cleaner handling of Ctrl-C */
	signal(SIGINT, sig_handler);
	signal(SIGTERM, sig_handler);

	/* Load and verify BPF application */
	skel = process_switch_bpf__open();		/* 打开bpf文件 */
	if (!skel) {
		fprintf(stderr, "Failed to open and load BPF skeleton\n");
		return 1;
	}
	
	/* Load & verify BPF programs */
	err = process_switch_bpf__load(skel);	/* 加载到内核中进行字节码校验 */
	if (err) {
		fprintf(stderr, "Failed to load and verify BPF skeleton\n");
		goto cleanup;
	}

	/* Attach tracepoints */
	err = process_switch_bpf__attach(skel);	/* 挂载跟踪点 */
	if (err) {
		fprintf(stderr, "Failed to attach BPF skeleton\n");
		goto cleanup;
	}
	/* 设置唤醒缓冲区轮询 */
	/* Set up ring buffer polling */
	rb = ring_buffer__new(bpf_map__fd(skel->maps.rb), handle_event, NULL, NULL);
	if (!rb) {
		err = -1;
		fprintf(stderr, "Failed to create ring buffer\n");
		goto cleanup;
	}
	/* 设置打印标题 */
	/* Process events */
	printf("%-8s\t %-8s\t %-16s\t %-8s\t %-16s\t %-8s\n", "TIME", "prev_pid", "prev_comm", "next_pid", "next_comm", "runtime:ns");
	/* 没有收到退出信号就持续轮询 */
	while (!exiting) {
		/* 调用ringbuf轮询函数，超时设置为100ms，然后去执行 handle_event */
		err = ring_buffer__poll(rb, 100 /* timeout, ms */);
		/* Ctrl-C will cause -EINTR */
		if (err == -EINTR) {
			err = 0;
			break;
		}
		if (err < 0) {
			printf("Error polling perf buffer: %d\n", err);
			break;
		}
	}

cleanup:
	/* Clean up */
	ring_buffer__free(rb);
	process_switch_bpf__destroy(skel);

	return err < 0 ? -err : 0;
}

