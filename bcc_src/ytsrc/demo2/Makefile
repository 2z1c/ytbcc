BCC_WORK_SRC := $(patsubst %/,%,$(dir $(CURDIR)))
BCC_WORK_SRC := $(patsubst %/,%,$(dir $(BCC_WORK_SRC)))



LIBBPF_SRC := ${BCC_WORK_SRC}/src/cc/libbpf/src


OUTPUT := $(abspath .output)
LIBBPF_OBJ := $(abspath $(OUTPUT)/libbpf.a)

CLANG ?= clang-14
LLVM_STRIP ?= llvm-strip-14

INCLUDES := -I$(OUTPUT) -I${BCC_WORK_SRC}/src/cc/libbpf/include/uapi
CFLAGS := -g -O2 -Wall -Wmissing-field-initializers -Werror
BPFCFLAGS := -g -O2 -Wall

ARCH := arm64
BPFTOOL_SRC := ${BCC_WORK_SRC}/libbpf-tools/bpftool/src
BPFTOOL_OUTPUT ?= $(abspath $(OUTPUT)/bpftool)
BPFTOOL ?= $(BPFTOOL_OUTPUT)/bootstrap/bpftool


msg = @printf '  %-8s %s%s\n' "$(1)" "$(notdir $(2))" "$(if $(3), $(3))";

$(OUTPUT)/helloworld.bpf.o: helloworld.bpf.c $(LIBBPF_OBJ) | $(OUTPUT)
	$(call msg,BPF,$@)
	$(Q)$(CLANG) $(BPFCFLAGS) -target bpf -D__TARGET_ARCH_$(ARCH)	      \
		     -I${BCC_WORK_SRC}/libbpf-tools/$(ARCH)/ $(INCLUDES) -c $(filter %.c,$^) -o $@ &&      \
	$(LLVM_STRIP) -g $@

$(OUTPUT)/helloworld.skel.h: $(OUTPUT)/helloworld.bpf.o | $(OUTPUT) $(BPFTOOL)
	$(call msg,GEN-SKEL,$@)
	$(Q)$(BPFTOOL) gen skeleton $< > $@

${OUTPUT}/helloworld.o: helloworld.c ${OUTPUT}/helloworld.skel.h
	$(call msg,CC,$@)
	$(Q)$(CC) $(CFLAGS) $(INCLUDES) -c $(filter %.c,$^) -o $@

$(BPFTOOL): | $(BPFTOOL_OUTPUT)
	$(call msg,BPFTOOL,$@)
	$(Q)$(MAKE) ARCH= CROSS_COMPILE=  OUTPUT=$(BPFTOOL_OUTPUT)/ -C $(BPFTOOL_SRC) bootstrap


$(LIBBPF_OBJ): $(wildcard $(LIBBPF_SRC)/*.[ch]) | $(OUTPUT)/libbpf
	$(call msg,LIB,$@)
	$(Q)$(MAKE) -C $(LIBBPF_SRC) BUILD_STATIC_ONLY=1		      \
		    OBJDIR=$(dir $@)libbpf DESTDIR=$(dir $@)		      \
		    INCLUDEDIR= LIBDIR= UAPIDIR=			      \
		    install

helloworld: ${OUTPUT}/helloworld.o ${OUTPUT}/helloworld.skel.h $(LIBBPF_OBJ)  | $(OUTPUT)
	$(call msg,BINARY,$@)
	$(Q)$(CC) --static $^ $(CFLAGS) $(LDFLAGS) -lelf -lz -o $@.out



${OUTPUT}/hello.o: hello.cpp
	$(call msg,CC,$@)
	$(Q)$(CC) $(CFLAGS) $(INCLUDES) -c $(filter %.cpp,$^) -o $@

$(LIBBPF_OBJ): $(wildcard $(LIBBPF_SRC)/*.[ch]) | $(OUTPUT)/libbpf

hello: ${OUTPUT}/hello.o $(LIBBPF_OBJ)  | $(OUTPUT)
	$(call msg,BINARY,$@)
	$(Q)g++ --static $^ $(CFLAGS) $(LDFLAGS) -lelf -lz --verbose -o $@.out

libbpf: $(LIBBPF_OBJ)

$(shell mkdir -p $(OUTPUT)/libbpf ${BPFTOOL_OUTPUT})

.DEFAULT_GOAL := helloworld
all: helloworld hello

.PHONY: clean
clean:
	$(call msg,CLEAN)
	$(Q)rm -rf *.out