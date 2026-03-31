#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

//跟踪点使用的通用结构体当前vmlinux.h中没有，需要自定义
struct trace_event_raw_block_bio {
	struct trace_entry ent;
	dev_t dev;
	sector_t sector;
	unsigned int nr_sector;
	char rwbs[8];
	char comm[16];
	char __data[0];
};

struct trace_event_raw_block_bio_complete {
	struct trace_entry ent;
	dev_t dev;
	sector_t sector;
	unsigned int nr_sector;
	int error;
	char rwbs[8];
	char __data[0];
};

struct key {
    u64 dev;
    u64 sector;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8192);
    __type(key, struct key);
    __type(value, u64);
} start_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, u64);
    __type(value, u64);
} lat_map SEC(".maps");

SEC("tracepoint/block/block_bio_queue")
int bio_queue(struct trace_event_raw_block_bio *ctx)
{
    struct key k = {};
    u64 ts;

    k.dev    = ctx->dev;
    k.sector = ctx->sector;
    ts = bpf_ktime_get_ns();

    bpf_map_update_elem(&start_map, &k, &ts, BPF_ANY);
    return 0;
}

SEC("tracepoint/block/block_bio_complete")
int bio_complete(struct trace_event_raw_block_bio_complete *ctx)
{
    struct key k = {};
    u64 *tsp, delta, us, *cnt;

    k.dev    = ctx->dev;
    k.sector = ctx->sector;
    tsp = bpf_map_lookup_elem(&start_map, &k);
    if (!tsp)
        return 0;

    delta = bpf_ktime_get_ns() - *tsp;
    us = delta / 1000;

    cnt = bpf_map_lookup_elem(&lat_map, &us);
    if (cnt)
        __sync_fetch_and_add(cnt, 1);
    else {
        __u64 init = 1;
        bpf_map_update_elem(&lat_map, &us, &init, BPF_ANY);
    }

    bpf_map_delete_elem(&start_map, &k);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
