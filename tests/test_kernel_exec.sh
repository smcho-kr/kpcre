#!/bin/sh
set -eu
cd "$(dirname "$0")"
test_dir=$(mktemp -d)
trap 'rm -rf "$test_dir"' EXIT HUP INT TERM
mkdir "$test_dir/linux"
for header in kprobes security vmalloc; do
    : > "$test_dir/linux/$header.h"
done
for config in '' '-DCONFIG_X86_KERNEL_IBT=1' '-DCONFIG_CFI_CLANG=1' '-DCONFIG_KPROBES=0'; do
    ${CC:-cc} -std=gnu11 -Wall -Wextra -Werror $config -I"$test_dir" \
        kernel_exec_test.c -o "$test_dir/test"
    "$test_dir/test"
done
