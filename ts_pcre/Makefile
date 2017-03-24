CODE_WIDTH ?= 8
LIBC := ${PWD}/../libc
PCRE2 := ${PWD}/../pcre2

ifeq ($(strip $(DEBUG)),)
ccflags-y += -O2 -s
else
ccflags-y += -ggdb -DDEBUG
endif
ccflags-y += -I$(LIBC) -I$(PCRE2) \
    -DPCRE2_CODE_UNIT_WIDTH=${CODE_WIDTH}

MODULES_DIR := /lib/modules/$(shell uname -r)
KERNEL_DIR ?= ${MODULES_DIR}/build
KBUILD_EXTRA_SYMBOLS := ${PCRE2}/Module.symvers

obj-m := ts_pcre.o

all:
	make -C ${KERNEL_DIR} M=$$PWD;

modules:
	make -C ${KERNEL_DIR} M=$$PWD $@;

modules_install:
	make -C ${KERNEL_DIR} M=$$PWD $@;
	depmod -a;

clean:
	make -C ${KERNEL_DIR} M=$$PWD $@;
	rm -rf modules.order cscope.*
