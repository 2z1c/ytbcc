#define BPF_NO_GLOBAL_DATA

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_endian.h>
#include "core_fixes.bpf.h"

struct trace_event_raw_kmalloc {
        struct trace_entry         ent;                  /*     0     8 */
        unsigned long              call_site;            /*     8     8 */
        const void  *              ptr;                  /*    16     8 */
        size_t                     bytes_req;            /*    24     8 */
        size_t                     bytes_alloc;          /*    32     8 */
        unsigned long              gfp_flags;            /*    40     8 */
        int                        node;                 /*    48     4 */
        char                       __data[];             /*    52     0 */

        /* size: 56, cachelines: 1, members: 8 */
        /* padding: 4 */
        /* last cacheline: 56 bytes */
};


struct data_t {
    u32 pid;
    u32 count;
    size_t bytes;
    char comm[16];
};
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, u64);
} event_count SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(max_entries, 1024);
    __type(key, int);
    __type(value, unsigned int);
} events SEC(".maps");

unsigned int count = 0;


// SEC("kprobe/spidev_ioctl")
SEC("tracepoint/kmem/kmalloc")
int bpf_spidev_ioctl(void *ctx){
     struct data_t data;
     u32 key = 0;
     long id = bpf_get_current_pid_tgid();
    struct trace_event_raw_kmalloc *args = ctx;
    const void *ptr = BPF_CORE_READ(args, ptr);

    __sync_fetch_and_add(&count, 1);

     data.pid = id >> 32;
    //  data.tid = (int) id;
     data.count = count;
     data.bytes = BPF_CORE_READ(args, bytes_alloc);

    //  trace_event_raw_kmem_alloc
	 bpf_get_current_comm(&data.comm, sizeof(data.comm));
     bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &data, sizeof(data));
     return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";

