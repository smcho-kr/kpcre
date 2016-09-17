KLIBS_DEBUG ?= 0

ifeq ($(KLIBS_DEBUG), 1)
ccflags-y += -ggdb -DDEBUG
else
ccflags-y += -O2 -s
endif

MODULES_DIR := /lib/modules/$(shell uname -r)
KERNEL_DIR ?= ${MODULES_DIR}/build

obj-m := libc.o

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
