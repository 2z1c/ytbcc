#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
struct data_t {
    u32 pid;
    u64 count;
    char comm[16];
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, u32);
    __type(value, u64);
    __uint(max_entries, 10240);
} counts SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
} events SEC(".maps");

SEC("kprobe/kmem_cache_alloc")
int BPF_KPROBE(trace_kmem_cache_alloc)
{
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 *count = bpf_map_lookup_elem(&counts, &pid);
    if (count) {
        (*count)++;
    } else {
        u64 initial_count = 1;
        bpf_map_update_elem(&counts, &pid, &initial_count, BPF_ANY);
    }

    struct data_t data = {};
    data.pid = pid;
    data.count = *count;
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &data, sizeof(data));

    return 0;
}

char LICENSE[] SEC("license") = "GPL";
