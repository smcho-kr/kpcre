KERNEL_DIR ?= /lib/modules/$(shell uname -r)/build
KPCRE_DIR ?= $(abspath ../..)
ccflags-y += -I$(KPCRE_DIR)/pcre2 -DPCRE2_CODE_UNIT_WIDTH=8
KBUILD_EXTRA_SYMBOLS := $(KPCRE_DIR)/pcre2/Module.symvers
obj-m := nft_regex_test.o nft_regex_window_test.o
BUILD_DIR := $(abspath ../../.build/nft-regex)

.PHONY: modules clean traffic userspace-check
traffic:
	mkdir -p $(BUILD_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) -Wall -Wextra -Werror -static regex_traffic.c -o $(BUILD_DIR)/regex_traffic
	$(CC) $(CPPFLAGS) $(CFLAGS) -Wall -Wextra -Werror -static ../ids_traffic.c -o $(BUILD_DIR)/window_traffic

modules clean:
	$(MAKE) -C $(KERNEL_DIR) M=$(CURDIR) KPCRE_DIR=$(KPCRE_DIR) $@

NFT_PREFIX ?= $(BUILD_DIR)/nft
userspace-check:
	mkdir -p $(BUILD_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) -Wall -Wextra -Werror -I$(NFT_PREFIX)/include userspace_regex_test.c $(NFT_PREFIX)/lib/libnftnl.a -l:libmnl.so.0 -o $(BUILD_DIR)/userspace_regex_test
	$(BUILD_DIR)/userspace_regex_test
