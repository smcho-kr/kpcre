CODE_WIDTH ?= 8
LIBC := ${PWD}/../libc/

ifeq ($(strip $(DEBUG)),)
ccflags-y += -O3 -s
else
ccflags-y += -ggdb -DDEBUG
endif
ccflags-y += -I${LIBC} \
    -DHAVE_CONFIG_H -DPCRE2_CODE_UNIT_WIDTH=${CODE_WIDTH}

MODULES_DIR := /lib/modules/$(shell uname -r)
KERNEL_DIR ?= ${MODULES_DIR}/build
KBUILD_EXTRA_SYMBOLS = ${LIBC}/Module.symvers

obj-m := libpcre2-${CODE_WIDTH}.o 
libpcre2-${CODE_WIDTH}-y := main.o \
pcre2_auto_possess.o \
pcre2_chartables.o \
pcre2_compile.o \
pcre2_config.o \
pcre2_context.o \
pcre2_dfa_match.o \
pcre2_error.o \
pcre2_find_bracket.o \
pcre2_jit_compile.o \
pcre2_maketables.o \
pcre2_match_data.o \
pcre2_match.o \
pcre2_newline.o \
pcre2_ord2utf.o \
pcre2_pattern_info.o \
pcre2posix.o \
pcre2_serialize.o \
pcre2_string_utils.o \
pcre2_study.o \
pcre2_substitute.o \
pcre2_substring.o \
pcre2_tables.o \
pcre2_ucd.o \
pcre2_valid_utf.o \
pcre2_xclass.o

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
