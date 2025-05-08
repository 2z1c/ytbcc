#include <stdio.h>
#include <signal.h>
#include <unistd.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <unordered_map>
#include <vector>
#include "kloopmap.skel.h"
#include "cxxopts.hpp"

static volatile bool exiting = false;
typedef unsigned long long u64;
typedef unsigned int u32;

struct alloc_info {
    u64 size;
    u64 timestamp_ns;
    u32 pid;
    u32 tid;
    u64 count;
};

// 结构体用于存储 pid 的状态信息
struct PidInfo {
    u64 last_count = 0;     // 上一次的 count 值
    u64 mismatch_count = 0; // count 变化次数
};

u32 filter_pid = 0;

class AllocTracker {
public:
    void process_data(const alloc_info& info) {
        auto& pid_info = pid_map[info.pid];  // 使用 operator[] 避免额外查找

        // 检查 count 是否发生变化
        if (pid_info.last_count != 0 && pid_info.last_count != info.count) {
            // 优化一下排序
            printf("Count changed for pid:%-16u old:%-16llu new:%-16llu miss:%-16llu size:%-16llu \n",
                   info.pid, pid_info.last_count, info.count, pid_info.mismatch_count + 1, info.size);
            pid_info.mismatch_count++;  // 统计当前 pid 发生 count 变化的次数
        }

        // 更新 last_count
        pid_info.last_count = info.count;
    }

    void print_stats() const {
        printf("========== Mismatch Statistics ==========\n");
        for (const auto& [pid, info] : pid_map) {
            if (info.mismatch_count > 0) {
                printf("pid %u: count mismatched %llu times\n", pid, info.mismatch_count);
            }
        }
    }

private:
    std::unordered_map<uint32_t, PidInfo> pid_map;  // 存储每个 pid 的 count 状态
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
    struct kloopmap_bpf *skel;
    int err;
    AllocTracker tracker;
    /* 处理信号以便在按下 Ctrl-C 时退出 */
    signal(SIGINT, handle_signal);
    signal(SIGTERM, handle_signal);

    libbpf_set_print(libbpf_print_fn);
    /* 打开并加载 eBPF 程序 */
    // skel = kloopmap_bpf__open_and_load();
    cxxopts::Options options("demo_program", "A demo program for command line parsing");

    // 定义选项
    options.add_options()
        ("h,help", "Show help message")
        ("pid", "work job", cxxopts::value<int>()->default_value("0"), "int");
    auto result = options.parse(argc, argv);
    

    if (result.count("help")) {
        std::cout << options.help() << std::endl;
        return 0;
    }

    filter_pid = ()result["pid"].as<int>();
    skel = kloopmap_bpf__open();
    if (!skel) {
        fprintf(stderr, "Failed to open and load BPF skeleton\n");
        return 1;
    }

    /* 验证和加载 BPF 程序 */
    err = kloopmap_bpf__load(skel);
    if (err) {
        fprintf(stderr, "Failed to load BPF skeleton: %d\n", err);
        kloopmap_bpf__destroy(skel);
        return 1;
    }

    /* 附加 BPF 程序到 tracepoints */
    err = kloopmap_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "Failed to attach BPF skeleton: %d\n", err);
        kloopmap_bpf__destroy(skel);
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
                tracker.process_data(info);

                // printf("PID: %u, TID: %u, Alloc Size: %llu bytes, count: %llu\n", info.pid, info.tid, info.size, info.count);
            }
            key = next_key; 
        }

        sleep(1);
    }

    /* 清理并销毁 BPF skeleton */
    kloopmap_bpf__destroy(skel);
    return 0;
}
