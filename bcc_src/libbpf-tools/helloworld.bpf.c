/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
#define BPF_NO_GLOBAL_DATA
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

SEC("tracepoint/spi/spi_message_start")
int spi_spi_message_start(struct trace_event_raw_sys_enter *ctx)
{
	int i = 0 ;
	bpf_printk("helloworld %d\n", ++i);	
	bpf_printk("helloworld %d\n", ++i);	
	return 0;
}
