#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <bpf/libbpf.h>
#include "biostacks.skel.h"

static volatile bool exiting = 0;

static void sig(int s) 
{ 
	exiting = 1; 
}

void print_auto_hist(int fd)
{
	//描述map中数据的变量
    __u64 key = 0, next_key = 0, count = 0, total = 0;
    __u64 min = 100000000, max = 0;
	
	//描述直方图数据的变量
	__u64 step = 0, start = 0, end = 0, cnt = 0, w = 0;
    char bar[64] = {0};
	
    // 第一次遍历：找 min 和 max，界定出直方图范围
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
	
    // 根据统计结果的最大最小计算区间步长
    step = (max - min + 10) / 20; // 分成20个区间
    if (step == 0)
		step = 1;

    // 第二次遍历：统计每个区间
    __u64 buckets[100] = {0};
    key = 0;
    while (bpf_map_get_next_key(fd, &key, &next_key) == 0) {
        bpf_map_lookup_elem(fd, &next_key, &count);
        int idx = (next_key - min) / step;
		
        if (idx >= 100)
			idx = 99;
		
        buckets[idx] += count;
        total += count;
        key = next_key;
    }

    // 输出直方图
    printf("\nBlock IO Latency Histogram (us)\n");
    printf("----------------------------------------\n");
    printf("min: %llu us, max: %llu us, step: %llu us\n\n", min, max, step);

    for (int i = 0; i < 20; i++) {
        start = min + i * step;
        end = start + step;
        cnt = buckets[i];

        memset(bar, 0, sizeof(bar));
        w = cnt > 50 ? 50 : cnt;
        memset(bar, '@', w);

        printf("[%llu, %8llu] : %8llu | %s\n",
               start, end, cnt, bar);
    }
}


int main()
{
    struct biostacks_bpf *skel = NULL;
    unsigned long key = 0, next = 0, val = 0;
    int fd = 0, err = 0;

    signal(SIGINT, sig);
    signal(SIGTERM, sig);

    skel = biostacks_bpf__open_and_load();
    if (!skel)
		return 1;

    err = biostacks_bpf__attach(skel);
    if (err) {
        biostacks_bpf__destroy(skel);
		
        return 1;
    }

    printf("Tracing block IO... Ctrl+C to stop\n");
	
    while (!exiting)
		pause();

    fd = bpf_map__fd(skel->maps.lat_map);
    printf("\nBlock IO latency (us):\n");
	
	print_auto_hist(fd);
    biostacks_bpf__destroy(skel);
	
    return 0;
}
