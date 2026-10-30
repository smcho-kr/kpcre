KERNEL_DIR ?= /lib/modules/$(shell uname -r)/build
KPCRE_DIR ?= $(abspath ..)
NFT_PREFIX ?= $(abspath ..)/.build/nft-regex/nft
ccflags-y += -I$(KPCRE_DIR)/pcre2 -DPCRE2_CODE_UNIT_WIDTH=8
KBUILD_EXTRA_SYMBOLS := $(KPCRE_DIR)/pcre2/Module.symvers
obj-m := nft_regex.o

.PHONY: all modules modules_install userspace userspace-check check clean
all: modules

modules_install:
	$(MAKE) -C $(KERNEL_DIR) M=$(CURDIR) KPCRE_DIR=$(KPCRE_DIR) modules_install
	depmod -a

modules:
	$(MAKE) -C $(KERNEL_DIR) M=$(CURDIR) KPCRE_DIR=$(KPCRE_DIR) modules

userspace:
	NFT_PREFIX="$(NFT_PREFIX)" sh ../scripts/nft-regex-build-userspace.sh

userspace-check:
	$(MAKE) -C ../tests/nft_regex userspace-check NFT_PREFIX="$(NFT_PREFIX)"

check:
	sh ../tests/nft_regex/test_install.sh

clean:
	$(MAKE) -C $(KERNEL_DIR) M=$(CURDIR) clean
	$(MAKE) -C ../tests/nft_regex KERNEL_DIR=$(KERNEL_DIR) clean
