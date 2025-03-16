#include <stdio.h>
#include <signal.h>
#include <unistd.h>
#include <bpf/libbpf.h>

#include "kmemleak.skel.h"
#define PERF_BUFFER_PAGES	16
#define PERF_POLL_TIMEOUT_MS	100
typedef unsigned int u32;
typedef unsigned long long u64;
typedef unsigned int  __u32;

static volatile bool exiting = false;
struct data_t {
    u32 pid;
    u32 count;
    size_t bytes;
    char comm[16];
};


static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	return vfprintf(stderr, format, args);
}

static void handle_event(void *ctx, int cpu, void *data, __u32 data_sz){
    struct data_t *e = data;
    static u32 count = 0;
    count ++;
    if (count != e->count){
        printf("PID: %d , bytes: %ld, ex:%u real:%u\n", e->pid, e->bytes, count, e->count);
        count = e->count;
    }
}

void sig_handler(int signo)
{
    exiting = true;
}

int main(int argc, char **argv)
{
    struct perf_buffer *rb = NULL;
    struct kmemleak_bpf *skel;
    int err;

    // 处理信号以安全退出
    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    libbpf_set_print(libbpf_print_fn);
    // 打开并加载 eBPF 程序
    skel = kmemleak_bpf__open_and_load();
    if (!skel) {
        fprintf(stderr, "Failed to open and load BPF skeleton\n");
        return 1;
    }

    // 附加 kprobe
    err = kmemleak_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "Failed to attach BPF skeleton\n");
        goto cleanup;
    }

    // 设置环形缓冲区以接收事件
    // rb = ring_buffer__new(bpf_map__fd(skel->maps.events), handle_event, NULL, NULL);
    rb = perf_buffer__new(bpf_map__fd(skel->maps.events), PERF_BUFFER_PAGES, handle_event, NULL, NULL, NULL);
    if (!rb) {
        fprintf(stderr, "Failed to create ring buffer\n");
        err = 1;
        goto cleanup;
    }

    printf("Tracing kmem_cache_alloc... Press Ctrl+C to exit.\n");
    while (!exiting) {
        err = perf_buffer__poll(rb, 100 /* timeout, ms */);
        if (err == -EINTR) {
            err = 0;
            break;
        }
        if (err < 0) {
            fprintf(stderr, "Error polling ring buffer: %d\n", err);
            break;
        }
    }

cleanup:
    perf_buffer__free(rb);
    kmemleak_bpf__destroy(skel);
    return err < 0 ? -err : 0;
}
