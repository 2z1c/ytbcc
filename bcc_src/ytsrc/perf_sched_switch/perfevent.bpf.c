#define BPF_NO_GLOBAL_DATA

// #include <linux/bpf.h>
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

struct state_change {
    u32 pid;
    pid_t prev_pid;
    pid_t next_pid;
    pid_t filter_pid;
    long int prev_state;
    u64 timestamp;
    u64 count;
};
const volatile pid_t filter_pid = 0;

static u64 fetch_count = 0;
struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(max_entries, 16);
    __type(key, int);
    __type(value, u32);
} events SEC(".maps");

/*******************************************************************************
cat /sys/kernel/debug/tracing/events/sched/sched_switch/format
format:
        field:unsigned short common_type;       offset:0;       size:2; signed:0;
        field:unsigned char common_flags;       offset:2;       size:1; signed:0;
        field:unsigned char common_preempt_count;       offset:3;       size:1; signed:0;
        field:int common_pid;   offset:4;       size:4; signed:1;

        field:char prev_comm[16];       offset:8;       size:16;        signed:0;
        field:pid_t prev_pid;   offset:24;      size:4; signed:1;
        field:int prev_prio;    offset:28;      size:4; signed:1;
        field:long prev_state;  offset:32;      size:8; signed:1;
        field:char next_comm[16];       offset:40;      size:16;        signed:0;
        field:pid_t next_pid;   offset:56;      size:4; signed:1;
        field:int next_prio;    offset:60;      size:4; signed:1;


struct trace_event_raw_sched_switch {
	struct trace_entry ent;
	char prev_comm[16];
	pid_t prev_pid;
	int prev_prio;
	long int prev_state;
	char next_comm[16];
	pid_t next_pid;
	int next_prio;
	char __data[0];
};

******* */

SEC("tracepoint/sched/sched_switch")
int trace_sched_switch(struct trace_event_raw_sched_switch *ctx) {
    u64 id = bpf_get_current_pid_tgid();
    u64 timestamp = bpf_ktime_get_ns();         // 获取当前时间戳（纳秒）

    pid_t prev_pid= 0, next_pid = 0;
    // 创建事件并提交到 perf buffer
    struct state_change sc = {};
    sc.pid = id >> 32;
    // BPF_CORE_READ(task, start_time);
    sc.prev_pid = (u32)ctx->prev_pid;
    sc.next_pid = (u32)ctx->next_pid;
    // next_pid = BPF_CORE_READ(ctx, next_pid);
    // bpf_printk("helloworld test_int:%d\n", filter_pid);
    bpf_printk("%d:%d\n", sc.prev_pid, filter_pid);
    if (sc.prev_pid == filter_pid || sc.next_pid  == filter_pid) {
        sc.timestamp = timestamp;
        // bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &sc, sizeof(sc));
        __sync_fetch_and_add(&fetch_count, 1);
        // bpf_printk("prev_pid:%d,  next_pid:%d\n", sc.prev_pid, sc.next_pid);
        sc.filter_pid = filter_pid;
        sc.count = fetch_count;
        sc.prev_state = ctx->prev_state;
        bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &sc, sizeof(sc));
    }
    return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
