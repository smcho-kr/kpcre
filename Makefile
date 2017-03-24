ifeq ($(strip $(CODE_WIDTH)),)
	export CODE_WIDTH=8
endif

$(info CODE_WIDTH is $(CODE_WIDTH))

SUBDIRS = \
libc \
pcre2 \
ts_pcre \
ts_regex

all:
	@for d in $(SUBDIRS) ; do \
	    $(MAKE) -C $$d ; \
	done

modules:
	@for d in $(SUBDIRS) ; do \
	    $(MAKE) -C $$d modules ; \
	done

modules_install:
	@for d in $(SUBDIRS) ; do \
	    $(MAKE) -C $$d modules_install ; \
	done

clean:
	@for d in $(SUBDIRS) ; do \
	    $(MAKE) -C $$d clean ; \
	done
	$(RM) cscope.*
