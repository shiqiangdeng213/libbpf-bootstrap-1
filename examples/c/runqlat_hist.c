// SPDX-License-Identifier: GPL-2.0
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <string.h>
#include <unistd.h>
#include <bpf/libbpf.h>
#include "runqlat_hist.skel.h"

static volatile bool exiting = false;

void sig_handler(int sig)
{
	exiting = true;
}

void print_auto_hist(int fd)
{
	__u64 key = 0, next_key = 0, count = 0;
	__u64 min = 100000000, max = 0;
	__u64 step = 0, start = 0, end = 0, cnt = 0;
	
	__u64 idx = 0, max_cnt = 0;  // 增加 max_cnt 存最大次数
	char bar[64] = {0};
	__u64 buckets[100] = {0};
	__u32 width = 0;
	
	// 第一次遍历：找 min、max、max_cnt
	while (bpf_map_get_next_key(fd, &key, &next_key) == 0) {
		bpf_map_lookup_elem(fd, &next_key, &count);
		if (next_key < min)
			min = next_key;
		
		if (next_key > max)
			max = next_key;
		
		key = next_key;
	}

	if (min > max) {
		printf("No data\n");
		
		return;
	}

	step = (max - min + 10) / 20;
	if (step == 0) 
		step = 1;
	
	// 第二次遍历：统计区间 + 找最大次数
	key = 0;
	while (bpf_map_get_next_key(fd, &key, &next_key) == 0) {
		bpf_map_lookup_elem(fd, &next_key, &count);
		
		idx = (next_key - min) / step;
		if (idx >= 100)
			idx = 99;
		
		buckets[idx] += count;
		// 记录区间最大次数
		if (buckets[idx] > max_cnt)
			max_cnt = buckets[idx];
		
		key = next_key;
	}

	// 输出直方图
	printf("\nRun Queue Latency Histogram (us)\n");
	printf("----------------------------------------\n");
	printf("min: %llu us, max: %llu us, step: %llu us\n\n", min, max, step);
	
	for (int i = 0; i < 20; i++) {
		start = min + i * step;
		end = start + step;
		cnt = buckets[i];

		memset(bar, 0, sizeof(bar));
		// ===================== 缩放 =====================
		if (max_cnt > 0)
			width = (cnt * 50) / max_cnt;  	// 按最大次数等比例缩放
		
		if (width == 0 && cnt > 0)
			width = 1;  					// 至少画1个，表示有数据
		
		memset(bar, '@', width);
		
		printf("[%4llu, %4llu] | %8llu | %s\n", start, end, cnt, bar);
	}
}

int main(int argc, char **argv)
{
	struct runqlat_hist_bpf *skel = NULL;
	int err = 0;

	signal(SIGINT, sig_handler);
	signal(SIGTERM, sig_handler);

	skel = runqlat_hist_bpf__open_and_load();
	if (!skel) {
		fprintf(stderr, "open failed\n");
		
		return 1;
	}

	err = runqlat_hist_bpf__attach(skel);
	if (err) {
		fprintf(stderr, "attach failed\n");
		runqlat_hist_bpf__destroy(skel);
	
		return 1;
	}

	printf("Tracing run queue latency... Ctrl+C to stop\n");

	while (!exiting)
		pause();

	// 输出直方图
	print_auto_hist(bpf_map__fd(skel->maps.lat_hist));
	runqlat_hist_bpf__destroy(skel);

	return 0;
}

