#ifndef __RUNQLAT_H
#define __RUNQLAT_H

struct event {
	pid_t pid;
	char comm[16];
	int prio;
	int target_cpu;
	unsigned long wakeup_time_ns;
	unsigned long lat_time_ns;
};

#endif
