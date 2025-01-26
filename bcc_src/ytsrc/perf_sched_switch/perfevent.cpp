
#include <stdio.h>
#include <unistd.h>
#include <sys/resource.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#include <signal.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <iostream>
#include <cassert>
#include <unordered_map>
#include "perfevent.skel.h"


typedef unsigned int u32;
typedef unsigned long long u64;
#define PERF_BUFFER_PAGES (32)
struct perf_bpf_common {
    int pid;
    int tid;
    int count;
    char comm[16];
    int diff_ns;
};

static int exiting = 0;
static void sig_handle_int(int signo)
{
	exiting = 1;
}

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	return vfprintf(stderr, format, args);
}


// 用于记录进程状态变化的结构体
struct state_change {
    u32 pid;
    pid_t prev_pid;
    pid_t next_pid;
    pid_t filter_pid;
    long int prev_state;
    u64 timestamp;
    u64 count;
};

// 用于存储进程状态的时间
struct state_time {
    uint64_t sleep_time = 0;
    uint64_t running_time = 0;
    uint64_t io_wait_time = 0;
    uint64_t ready_time = 0;
};

// 定义一个存储每个进程状态时间的 map
static std::unordered_map<uint32_t, state_time> process_state_time;
// void *ctx, int cpu, void *data, __u32 data_sz
void process_event(void *ctx, int cpu, void *data, __u32 len) {
    struct state_change *event = (struct state_change*)data;
    printf("prev_pid:%d, next_pid:%d filter_pid:%d prev_state:%lu count:%lu\n", 
            event->prev_pid, event->next_pid, event->filter_pid, event->prev_state ,event->count);
    // uint32_t pid = event->pid;
    // char prev_state = event->prev_state;
    // char next_state = event->next_state;
    // uint64_t timestamp = event->timestamp;

    // // 如果进程不在 map 中，初始化其状态
    // if (process_state_time.find(pid) == process_state_time.end()) {
    //     process_state_time[pid] = state_time();
    // }

    // auto& times = process_state_time[pid];

    // // 计算状态变化的时间差
    // static uint64_t last_timestamp = 0;
    // uint64_t duration = 0;
    // if (last_timestamp != 0) {
    //     duration = timestamp - last_timestamp;
    // }
    // last_timestamp = timestamp;

    // // 根据状态类型更新状态时间
    // if (prev_state == 'R' && next_state == 'S') {
    //     // 运行 -> 睡眠
    //     times.running_time += duration;
    // } else if (prev_state == 'S' && next_state == 'R') {
    //     // 睡眠 -> 运行
    //     times.sleep_time += duration;
    // } else if (next_state == 'I') {
    //     // 等待 I/O
    //     times.io_wait_time += duration;
    // } else if (next_state == 'R') {
    //     // 就绪态
    //     times.ready_time += duration;
    // }
}

// 打印进程状态时间
void print_state_time(uint32_t pid) {
    if (process_state_time.find(pid) != process_state_time.end()) {
        auto& times = process_state_time[pid];
        std::cout << "PID: " << pid << "\n"
                  << "Running Time: " << times.running_time << " ns\n"
                  << "Sleep Time: " << times.sleep_time << " ns\n"
                  << "IO Wait Time: " << times.io_wait_time << " ns\n"
                  << "Ready Time: " << times.ready_time << " ns\n";
    }
}


static void perf_handle_event(void *ctx, int cpu, void *data, __u32 data_sz){
    struct perf_bpf_common * bpf_data = (struct perf_bpf_common *)data;
    printf("pid: %d, tid:%d, comm: %s, count: %d\n", bpf_data->pid, bpf_data->tid, bpf_data->comm, bpf_data->count);
    return;
}

static void perf_handle_lost_event(void *ctx, int cpu, __u64 lost_cnt)
{
	printf("%s cpu: %d\n", __func__ , cpu);
}

void enable_trace(void)
{
	assert(!system("echo 'trace:off' > /sys/kernel/debug/mtkfb"));
	assert(!system("echo > /sys/kernel/tracing/set_event"));
	assert(!system("echo > /sys/kernel/tracing/trace"));
	assert(!system("echo 1 > /sys/kernel/tracing/tracing_on"));
}

int main(int argc, char *argv[]){

    struct perfevent_bpf *skel = NULL;
    int err = 0;
    struct perf_buffer *pb = NULL;

    int filter_pid = 0;

    if (argc > 1)
        filter_pid = atoi(argv[1]);
    libbpf_set_print(libbpf_print_fn);

    skel = perfevent_bpf__open();
    if (!skel) {
        fprintf(stderr, "Failed to open and load BPF skeleton\n");
        return 1;
    }


    // /* Set PID to trace */
    skel->rodata->filter_pid = filter_pid;
    // skel->rodata->filter_tid = filter_tid;

    err = perfevent_bpf__load(skel);
    if (err) {
        fprintf(stderr, "Failed to load BPF skeleton\n");
        perfevent_bpf__destroy(skel);
        return 1;
    }
    /* Attach tracepoint handler */
	err = perfevent_bpf__attach(skel);
	if (err) {
		fprintf(stderr, "Failed to attach BPF skeleton\n");
		goto cleanup;
	}

    pb = perf_buffer__new(bpf_map__fd(skel->maps.events), PERF_BUFFER_PAGES, process_event, perf_handle_lost_event, NULL, NULL);
    if(!pb){
        err = -errno;
        printf("failed to open perf buffer: %d\n", err);
		goto cleanup;
    }

    if (signal(SIGINT, sig_handle_int) == SIG_ERR){
        printf("can't set signal handler: %s\n", strerror(errno));
		err = 1;
		goto cleanup;
    }

    enable_trace();
    while(!exiting){
        // 1ms
        err = perf_buffer__poll(pb, 1000 * 1);
        if(err < 0 && err != -EINTR){
            printf("error polling perf buffer: %s\n", strerror(-err));
			goto cleanup;
        }
        err = 0;
    }

cleanup:
    perf_buffer__free(pb);
    perfevent_bpf__destroy(skel);
    return 0;
}