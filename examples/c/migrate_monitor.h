#ifndef __MIGRATE_H
#define __MIGRATE_H

struct event {
    pid_t pid;
    char comm[16];			// 内核线程来说好像32个不够
    int orig_cpu;			// 当前cpu
    int dest_cpu;
    int src_nid;			// 当前numa节点
    int dst_nid;
    int is_numa_migrate;	// 是否跨numa节点迁移
};

#endif

