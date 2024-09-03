
.DEFAULT_GOAL = build


%.build: 
	cd ${CURDIR}/bcc_src/libbpf-tools && make $* V=1 -j20 && file $*

# LIBBPF_BPFTOOLS_TARGETS := memleak 
# LIBBPF_BPFTOOLS_TARGETS += cpufreq 
# LIBBPF_BPFTOOLS_TARGETS += cachestat
# LIBBPF_BPFTOOLS_TARGETS += biotop
# LIBBPF_BPFTOOLS_TARGETS += biopattern
LIBBPF_BPFTOOLS_TARGETS += funclatency

libbpftools.release:
	mkdir -p ${CURDIR}/out
	-cd ${CURDIR}/bcc_src/libbpf-tools && cp ${LIBBPF_BPFTOOLS_TARGETS} ${CURDIR}/out -v 

libbpftools: ${LIBBPF_BPFTOOLS_TARGETS:=.build} libbpftools.release

release: libbpftools.release

build: libbpftools

clean:
	cd ${CURDIR}/bcc_src/libbpf-tools && make clean V=1 

# memleak:
# 	cd ${CURDIR}/bcc_src/libbpf-tools && make memleak V=1 -j20 && file memleak