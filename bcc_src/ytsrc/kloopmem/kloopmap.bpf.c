#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_endian.h>
#include <asm-generic/errno.h>

#define PERF_MAX_STACK_DEPTH 127
#define MAX_ENTRIES 8192

typedef unsigned int u32;

struct alloc_info {
    u64 size;
    u64 timestamp_ns;
    u32 pid;
    u32 tid;
    u64 count;
};


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

// struct trace_event_raw_kfree {
//         struct trace_entry         ent;                  /*     0     8 */
//         unsigned long              call_site;            /*     8     8 */
//         const void  *              ptr;                  /*    16     8 */
//         char                       __data[];             /*    24     0 */

//         /* size: 24, cachelines: 1, members: 4 */
//         /* last cacheline: 24 bytes */
// };

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, u64);
    __type(value, struct alloc_info);
} allocs SEC(".maps");


struct {
	__uint(type, BPF_MAP_TYPE_STACK_TRACE);
	__uint(key_size, sizeof(u32));
    __uint(max_entries, 10240);
    __uint(value_size, PERF_MAX_STACK_DEPTH * sizeof(u64));
} stackmap SEC(".maps");

static __always_inline void *
bpf_map_lookup_or_try_init(void *map, const void *key, const void *init)
{
	void *val;
	/* bpf helper functions like bpf_map_update_elem() below normally return
	 * long, but using int instead of long to store the result is a workaround
	 * to avoid incorrectly evaluating err in cases where the following criteria
	 * is met:
	 *     the architecture is 64-bit
	 *     the helper function return type is long
	 *     the helper function returns the value of a call to a bpf_map_ops func
	 *     the bpf_map_ops function return type is int
	 *     the compiler inlines the helper function
	 *     the compiler does not sign extend the result of the bpf_map_ops func
	 *
	 * if this criteria is met, at best an error can only be checked as zero or
	 * non-zero. it will not be possible to check for a negative value or a
	 * specific error value. this is because the sign bit would have been stuck
	 * at the 32nd bit of a 64-bit long int.
	 */
	int err;

	val = bpf_map_lookup_elem(map, key);
	if (val)
		return val;

	err = bpf_map_update_elem(map, key, init, BPF_NOEXIST);
	if (err && err != -EEXIST)
		return 0;

	return bpf_map_lookup_elem(map, key);
}


SEC("tracepoint/kmem/kmalloc")
int trace_kmalloc(struct trace_event_raw_kmalloc *ctx)
{
    u64 id = bpf_get_current_pid_tgid();
    int stack_id = 0;
    u32 pid = id >> 32;
    u32 tid = (u32)id;
    struct alloc_info init_info = {
        .size = ctx->bytes_alloc,
        .timestamp_ns = bpf_ktime_get_ns(),
        .pid = pid,
        .tid = tid,
        .count = 0,
    };

    struct alloc_info * info = NULL;
    // stack_id = bpf_get_stackid(ctx, &stackmap, BPF_F_USER_STACK);
    // if (stack_id >= 0) {
        // bpf_map_update_elem(&allocs, &id, &info, BPF_ANY);
    // }

    info = bpf_map_lookup_or_try_init(&allocs, &id, &init_info);
    
    // update
    if (info) {
        // info
        info->size = ctx->bytes_alloc;
        // __sync_fetch_and_add(&info->size, ctx->bytes_alloc);
        __sync_fetch_and_add(&info->count, 1);
        // bpf_map_update_elem(&allocs, &id, &info, BPF_ANY);
        // __sync_fetch_and_add(&info->timestamp_ns, info->timestamp_ns);
    }

    return 0;
}

SEC("tracepoint/kmem/kfree")
int trace_kfree(struct trace_event_raw_kfree *ctx)
{
    u64 id = bpf_get_current_pid_tgid();
    struct alloc_info *info = bpf_map_lookup_elem(&allocs, &id);

    if (info) {
        if (info->count <= 1){
            bpf_map_delete_elem(&allocs, &id);
        } else{
            __sync_fetch_and_add(&info->count, -1);
        }
    }
    // bpf_map_delete_elem(&allocs, &pid);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
