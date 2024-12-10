#define BPF_NO_GLOBAL_DATA

// #include <linux/bpf.h>
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

struct perf_bpf_common {
    int pid;
    int tid;
    int count;
    char comm[16];
    int diff_ns;
};

#define DEFINITION_STRUCT_PERF_BPF_COMMON(name) {.pid = 0, .tid=0, .count=0, .diff_ns=0}

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(max_entries, 32);
    __type(key, int);
    __type(value, unsigned int);
} perf_map SEC(".maps");

// SEC("kprobe/spidev_ioctl")
// SEC("tracepoint/block/block_rq_issue")
SEC("kprobe/do_sys_openat2")
int bpf_spidev_ioctl(void *ctx){
     struct perf_bpf_common data = DEFINITION_STRUCT_PERF_BPF_COMMON();
     long id = bpf_get_current_pid_tgid();
     data.pid = id >> 32;
     data.tid = (int) id;
	 bpf_get_current_comm(&data.comm, sizeof(data.comm));
     bpf_perf_event_output(ctx, &perf_map, BPF_F_CURRENT_CPU, &data, sizeof(data));
     return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";

