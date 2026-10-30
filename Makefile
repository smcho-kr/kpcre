ifeq ($(strip $(CODE_WIDTH)),)
	export CODE_WIDTH=8
endif

$(info CODE_WIDTH is $(CODE_WIDTH))

SUBDIRS = \
libc \
pcre2 \
ts_pcre \
ts_regex

ifeq ($(CODE_WIDTH),8)
SUBDIRS += xt_ids nft_regex
endif

all: modules

modules: kernel_modules
	$(MAKE) userspace

kernel_modules:
	@set -e; for d in $(SUBDIRS) ; do \
	    $(MAKE) -C $$d modules ; \
	done

modules_install: userspace_install
	@set -e; for d in $(SUBDIRS) ; do \
	    $(MAKE) -C $$d modules_install ; \
	done

userspace:
ifeq ($(CODE_WIDTH),8)
	$(MAKE) -C xt_ids userspace
endif

userspace_install: userspace
ifeq ($(CODE_WIDTH),8)
	$(MAKE) -C xt_ids userspace_install
endif

# Native nft embeds patched libraries; command replacement remains explicit.
nft_userspace:
	$(MAKE) -C nft_regex userspace

nft_userspace_check:
	$(MAKE) -C nft_regex userspace-check

nft_check:
	$(MAKE) -C nft_regex check

clean:
	@set -e; for d in $(SUBDIRS) ; do \
	    $(MAKE) -C $$d clean ; \
	done
	$(RM) cscope.*

.PHONY: all modules kernel_modules modules_install userspace userspace_install clean nft_userspace nft_userspace_check nft_check
