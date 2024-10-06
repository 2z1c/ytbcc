BCC_WORK_SRC := $(patsubst %/,%,$(dir $(CURDIR)))
BCC_WORK_SRC := $(patsubst %/,%,$(dir $(BCC_WORK_SRC)))



LIBBPF_SRC := ${BCC_WORK_SRC}/src/cc/libbpf/src


OUTPUT := $(abspath .output)
LIBBPF_OBJ := $(abspath $(OUTPUT)/libbpf.a)

INCLUDES := -I$(OUTPUT) -I${BCC_WORK_SRC}/src/cc/libbpf/include/uapi
CFLAGS := -g -O2 -Wall -Wmissing-field-initializers -Werror
BPFCFLAGS := -g -O2 -Wall


msg = @printf '  %-8s %s%s\n' "$(1)" "$(notdir $(2))" "$(if $(3), $(3))";

${OUTPUT}/helloworld.o: helloworld.c

$(LIBBPF_OBJ): $(wildcard $(LIBBPF_SRC)/*.[ch]) | $(OUTPUT)/libbpf
	$(call msg,LIB,$@)
	$(Q)$(MAKE) -C $(LIBBPF_SRC) BUILD_STATIC_ONLY=1		      \
		    OBJDIR=$(dir $@)libbpf DESTDIR=$(dir $@)		      \
		    INCLUDEDIR= LIBDIR= UAPIDIR=			      \
		    install


helloworld: ${OUTPUT}/helloworld.o $(LIBBPF_OBJ)  | $(OUTPUT)
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

$(shell mkdir -p $(OUTPUT)/libbpf)


.DEFAULT_GOAL := helloworld
all: helloworld hello