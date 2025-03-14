#define BPF_NO_GLOBAL_DATA

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_endian.h>

struct perf_bpf_common {
    int pid;
    int tid;
    char comm[16];
};

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(max_entries, 32);
    __type(key, int);
    __type(value, unsigned int);
} events SEC(".maps");

// SEC("kprobe/spidev_ioctl")
SEC("tracepoint/kmem/kmalloc")
int bpf_spidev_ioctl(void *ctx){
     struct perf_bpf_common data;
     long id = bpf_get_current_pid_tgid();
     data.pid = id >> 32;
     data.tid = (int) id;
	 bpf_get_current_comm(&data.comm, sizeof(data.comm));
     bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &data, sizeof(data));
     return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";

