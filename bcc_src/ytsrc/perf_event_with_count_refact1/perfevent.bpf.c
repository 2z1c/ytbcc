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

const volatile int filter_pid = 0;
#define DEFINITION_STRUCT_PERF_BPF_COMMON(name) {.pid = 0, .tid=0, .count=0, .diff_ns=0}

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(max_entries, 32);
    __type(key, int);
    __type(value, unsigned int);
} perf_map SEC(".maps");


struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, u32);
} count_map SEC(".maps");

static int fecth_add_count_and_perf(void *ctx){
     struct perf_bpf_common data = DEFINITION_STRUCT_PERF_BPF_COMMON();
     long id = bpf_get_current_pid_tgid();
	 u32 index = 0;
     u32 *p_count;
     data.pid = id >> 32;
     data.tid = (int) id;
	 bpf_get_current_comm(&data.comm, sizeof(data.comm));
     
     p_count = bpf_map_lookup_elem(&count_map, &index);
    if (p_count) {
        __sync_fetch_and_add(p_count, 1); // 原子递增计数器
        data.count = *p_count;
    } else {
        long init_val = 1;
        data.count = init_val;
        bpf_map_update_elem(&count_map, &index, &init_val, BPF_ANY);
    }

     
    bpf_perf_event_output(ctx, &perf_map, BPF_F_CURRENT_CPU, &data, sizeof(data));
    return 0;
}

// SEC("kprobe/spidev_ioctl")
// SEC("tracepoint/block/block_rq_issue")
SEC("kprobe/do_sys_openat2")
int bpf_spidev_ioctl(void *ctx) {
    long id = bpf_get_current_pid_tgid();
    int pid = id >> 32;
    int tid = (int) id;

    if (filter_pid == 0 || filter_pid == pid) {
        return fecth_add_count_and_perf(ctx);
    }
    return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";

