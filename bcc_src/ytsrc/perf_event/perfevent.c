
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
#include "perfevent.skel.h"
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
	if (level == LIBBPF_DEBUG)
		return 0;
	return vfprintf(stderr, format, args);
}

static void perf_handle_event(void *ctx, int cpu, void *data, __u32 data_sz){
    struct perf_bpf_common * bpf_data = (struct perf_bpf_common *)data;
    printf("pid: %d, tid:%d, comm: %s\n", bpf_data->pid, bpf_data->tid, bpf_data->comm);
    return;
}

static void perf_handle_lost_event(void *ctx, int cpu, __u64 lost_cnt)
{
	printf("%s cpu: %d\n", __func__ , cpu);
}

void enable_trace(void)
{
	(void)system("echo 'trace:off' > /sys/kernel/debug/mtkfb");
	(void)system("echo > /sys/kernel/tracing/set_event");
	(void)system("echo > /sys/kernel/tracing/trace");
	(void)system("echo 1 > /sys/kernel/tracing/tracing_on");
}

int main(int argc, char *argv[]){

    struct perfevent_bpf *skel = NULL;
    int err = 0, pid = 0;
    unsigned int index = 0;
    struct perf_buffer *pb = NULL;

    libbpf_set_print(libbpf_print_fn);

    skel = perfevent_bpf__open_and_load();
    if(!skel){
        fprintf(stderr, "Failed to open and load BPF skeleton\n");
		return 1;
    }

    /* Attach tracepoint handler */
	err = perfevent_bpf__attach(skel);
	if (err) {
		fprintf(stderr, "Failed to attach BPF skeleton\n");
		goto cleanup;
	}

    pb = perf_buffer__new(bpf_map__fd(skel->maps.perf_map), PERF_BUFFER_PAGES, perf_handle_event, perf_handle_lost_event, NULL, NULL);
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
        err = perf_buffer__poll(pb, 100);
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