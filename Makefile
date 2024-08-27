


%.build: 
	cd ${CURDIR}/bcc_src/libbpf-tools && make $* V=1 -j20 && file $*

LIBBPF_BPFTOOLS_TARGETS := memleak cpufreq

libbpftools.release:
	mkdir -p ${CURDIR}/out
	-cd ${CURDIR}/bcc_src/libbpf-tools && cp ${LIBBPF_BPFTOOLS_TARGETS} ${CURDIR}/out -v 

libbpftools: ${LIBBPF_BPFTOOLS_TARGETS:=.build} libbpftools.release

release: libbpftools.release

build: libbpftools


# memleak:
# 	cd ${CURDIR}/bcc_src/libbpf-tools && make memleak V=1 -j20 && file memleak