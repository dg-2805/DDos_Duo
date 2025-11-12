CLANG ?= clang
LLC ?= llc
BPFDIR := ../../bpftool/libbpf
LIBBPF_SRC := $(BPFDIR)/src
LIBBPF_OBJ := $(LIBBPF_SRC)/libbpf.a
INCLUDES := -I$(LIBBPF_SRC) -I.
CFLAGS := -O2 -g -Wall -Werror
LDFLAGS := -lelf -lz
ARCH := $(shell uname -m)
SYSINCDIR := /usr/include/$(ARCH)-linux-gnu
KERN_UAPI := ../../bpftool/include/uapi
LIBBPF_UAPI := $(BPFDIR)/include/uapi

all: $(LIBBPF_OBJ) dns_lb_kern.o dns_lb_user

$(LIBBPF_OBJ):
	$(MAKE) -C $(LIBBPF_SRC)

dns_lb_kern.o: dns_lb_kern.c bpf_helpers.h bpf_endian.h
	$(CLANG) -target bpf -D__TARGET_ARCH_x86 -O2 -g -Wall \
		-I$(LIBBPF_SRC) -I$(LIBBPF_UAPI) -I$(KERN_UAPI) -I. \
		-I$(SYSINCDIR) -I/usr/include \
		-c $< -o $@

dns_lb_user: dns_lb_user.c
	$(CC) $(CFLAGS) $< -o $@ $(INCLUDES) $(LIBBPF_OBJ) $(LDFLAGS)

clean:
	$(RM) dns_lb_kern.o dns_lb_user
	$(MAKE) -C $(LIBBPF_SRC) clean || true

.PHONY: all clean


