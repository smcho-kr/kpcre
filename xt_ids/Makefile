KERNEL_DIR ?= /lib/modules/$(shell uname -r)/build
KPCRE_DIR ?= $(abspath ..)
ccflags-y += -I$(KPCRE_DIR)/pcre2 -DPCRE2_CODE_UNIT_WIDTH=8
KBUILD_EXTRA_SYMBOLS := $(KPCRE_DIR)/pcre2/Module.symvers
obj-m := xt_ids.o

PKG_CONFIG ?= pkg-config
XTABLES_CFLAGS ?= $(shell $(PKG_CONFIG) --cflags xtables 2>/dev/null)
XTABLES_LIBDIR ?= $(shell $(PKG_CONFIG) --variable=xtlibdir xtables 2>/dev/null)

all: modules

modules:
	$(MAKE) -C $(KERNEL_DIR) M=$(CURDIR) KPCRE_DIR=$(KPCRE_DIR) $@

modules_install:
	$(MAKE) -C $(KERNEL_DIR) M=$(CURDIR) KPCRE_DIR=$(KPCRE_DIR) $@
	depmod -a

clean:
	$(MAKE) -C $(KERNEL_DIR) M=$(CURDIR) KPCRE_DIR=$(KPCRE_DIR) clean
	$(RM) libxt_ids.so

userspace: libxt_ids.so

libxt_ids.so: libxt_ids.c xt_ids.h
	$(CC) $(CPPFLAGS) $(CFLAGS) $(XTABLES_CFLAGS) -Wall -Wextra -Werror -fPIC -shared -nostartfiles -o $@ $<

userspace_install: userspace
	@case "$(XTABLES_LIBDIR)" in /*) ;; *) \
	    echo "Set XTABLES_LIBDIR to the absolute xtables plugin directory, or install pkg-config and xtables development files." >&2; \
	    exit 1 ;; esac
	install -D -m 755 libxt_ids.so "$(DESTDIR)$(XTABLES_LIBDIR)/libxt_ids.so"

.PHONY: all modules modules_install clean userspace userspace_install
