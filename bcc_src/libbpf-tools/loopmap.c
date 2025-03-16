#include <stdio.h>
#include <signal.h>
#include <unistd.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "loopmap.skel.h"

static volatile bool exiting = false;
typedef unsigned long long u64;
typedef unsigned int u32;

struct alloc_info {
    u64 size;
    u64 timestamp_ns;
    u32 pid;
    u32 tid;
};
static void handle_signal(int sig)
{
    exiting = true;
}

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args) {
    return vfprintf(stderr, format, args);
}

int main(int argc, char **argv)
{
    struct loopmap_bpf *skel;
    int err;

    /* 处理信号以便在按下 Ctrl-C 时退出 */
    signal(SIGINT, handle_signal);
    signal(SIGTERM, handle_signal);

    libbpf_set_print(libbpf_print_fn);
    /* 打开并加载 eBPF 程序 */
    // skel = loopmap_bpf__open_and_load();
    skel = loopmap_bpf__open();
    if (!skel) {
        fprintf(stderr, "Failed to open and load BPF skeleton\n");
        return 1;
    }

    /* 验证和加载 BPF 程序 */
    err = loopmap_bpf__load(skel);
    if (err) {
        fprintf(stderr, "Failed to load BPF skeleton: %d\n", err);
        loopmap_bpf__destroy(skel);
        return 1;
    }

    /* 附加 BPF 程序到 tracepoints */
    err = loopmap_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "Failed to attach BPF skeleton: %d\n", err);
        loopmap_bpf__destroy(skel);
        return 1;
    }

    printf("Tracing kmem events... Press Ctrl-C to end.\n");

    while (!exiting) {
        /* 遍历 allocs 映射 */
        __u64 key = 0, next_key;
        struct alloc_info info;

        while (bpf_map_get_next_key(bpf_map__fd(skel->maps.allocs), &key, &next_key) == 0) {
            if (bpf_map_lookup_elem(bpf_map__fd(skel->maps.allocs), &next_key, &info) == 0) {
                // if (info.pid == 14606){
                    // printf("PID: %llu, Alloc Size: %llu bytes, Timestamp: %llu ns\n", next_key, info.size, info.timestamp_ns);
                // }

                printf("PID: %u, TID: %u, Alloc Size: %llu bytes, Timestamp: %llu ns\n", info.pid, info.tid, info.size, info.timestamp_ns);
            }
            key = next_key; 
        }

        sleep(1);
    }

    /* 清理并销毁 BPF skeleton */
    loopmap_bpf__destroy(skel);
    return 0;
}
