KERNEL_DIR ?= /lib/modules/$(shell uname -r)/build
KPCRE_DIR ?= $(abspath ..)
ccflags-y += -I$(KPCRE_DIR)/pcre2 -DPCRE2_CODE_UNIT_WIDTH=8
KBUILD_EXTRA_SYMBOLS := $(KPCRE_DIR)/pcre2/Module.symvers
obj-m := kpcre_jit_test.o

modules clean:
	$(MAKE) -C $(KERNEL_DIR) M=$(CURDIR) KPCRE_DIR=$(KPCRE_DIR) $@

check:
	sh test_kernel_exec.sh
