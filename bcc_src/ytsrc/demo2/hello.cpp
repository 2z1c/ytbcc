/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
#include <string>
#include <stdio.h>
#include <unistd.h>
#include <sys/resource.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <bpf/libbpf.h>
#include <sys/types.h>
#include <sys/wait.h>

#include "helloworld.skel.h"


int mysystem(const char * __command)
{
        pid_t pid;
        int retval=0;
        if(NULL==__command){
                return 1;
        }
        if((pid=fork())<0){//fork error
                return -1;
        }
        else if(pid==0){
                //use __command to replace current process
                execl("/bin/sh", "sh", "-c", __command, (char *)0);
                return 127;
        }else{
                while(waitpid(pid,&retval,0)<0){
                        if(EINTR!=errno){
                                retval = -1;
                                break;
                        }
                }
        }
        return retval;
}


static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	return vfprintf(stderr, format, args);
}

void read_trace_pipe(void)
{
	
	// mysystem("echo 'trace:off' > /sys/kernel/debug/mtkfb");
	mysystem("echo > /sys/kernel/tracing/set_event");
    mysystem("echo 1 > /sys/kernel/tracing/tracing_on");
	mysystem("cat /sys/kernel/debug/tracing/trace_pipe");
}


int main(int argc, char **argv)
{
	struct helloworld_bpf *obj;
	int err;
	pid_t pid;
	std::string cmd = "echo 'trace:on' > /sys/kernel/debug/mtkfb";

	/* Set up libbpf errors and debug info callback */
	libbpf_set_print(libbpf_print_fn);

	/* Load and verify BPF application */

	obj = helloworld_bpf__open();
	if (!obj) {
		fprintf(stderr, "Failed to open BPF object\n");
		return 1;
	}

	bpf_program__set_autoload(obj->progs.spi_spi_message_start, true);

	obj->rodata->test_int = 11;
	err = helloworld_bpf__load(obj);
	if (err) {
		fprintf(stderr, "Failed to load BPF object: %d\n", err);
		goto cleanup;
	}

	// if (!obj->bss) {
	// 	fprintf(stderr, "Memory-mapping BPF maps is supported starting from Linux 5.7, please upgrade.\n");
	// 	goto cleanup;
	// }

	/* Attach tracepoint handler */
	err = helloworld_bpf__attach(obj);
	if (err) {
		fprintf(stderr, "Failed to attach BPF skeleton\n");
		goto cleanup;
	}

	printf("pid = %d\n", pid);
	printf("Successfully started! Please run `sudo cat /sys/kernel/debug/tracing/trace_pipe` "
	       "to see output of the BPF programs.\n");

	

	read_trace_pipe();

	// for(;;){
	// 	err = bpf_map__lookup_elem(skel->maps.my_data_map, &index, sizeof(index), &value, sizeof(value), NULL);
	// 	if (err)
	// 	{
	// 		sleep(1);
	// 		continue;
	// 	}
	// 	printf("pid = %d, count = %d\n",value.pid, value.count);
	// }

cleanup:
	helloworld_bpf__destroy(obj);
	return -err;
}
