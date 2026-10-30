#!/bin/sh
# SPDX-License-Identifier: GPL-2.0-only
# Build an isolated nft command; do not install into system directories.
set -eu
project=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
base="$project/.build/nft-regex/userspace"
prefix=${NFT_PREFIX:-"$project/.build/nft-regex/nft"}
mkdir -p "$base/downloads"
work=$(mktemp -d "$base/build-XXXXXX")
printf 'Build logs and sources: %s\n' "$work"

fetch()
{
    name=$1
    url=$2
    digest=$3
    archive="$base/downloads/$name.tar.xz"
    if ! test -f "$archive"; then
        curl --fail --location --retry 2 --output "$archive.part" "$url"
        printf '%s  %s\n' "$digest" "$archive.part" | sha256sum -c -
        mv -- "$archive.part" "$archive"
    fi
    printf '%s  %s\n' "$digest" "$archive" | sha256sum -c -
    tar --no-same-owner -xf "$archive" -C "$work"
    patch -d "$work/$name" -p1 < "$project/nft_regex/userspace/patches/$name-regex.patch"
    cp -- "$project/nft_regex/nft_regex.h" "$work/$name/include/linux/netfilter/nft_regex.h"
}

fetch libnftnl-1.3.1 \
    https://www.netfilter.org/projects/libnftnl/files/libnftnl-1.3.1.tar.xz \
    607da28dba66fbdeccf8ef1395dded9077e8d19f2995f9a4d45a9c2f0bcffba8
fetch nftables-1.1.6 \
    https://www.netfilter.org/projects/nftables/files/nftables-1.1.6.tar.xz \
    372931bda8556b310636a2f9020adc710f9bab66f47efe0ce90bff800ac2530c

cd "$work/libnftnl-1.3.1"
./configure --prefix="$prefix" --disable-shared --enable-static > "$work/libnftnl-configure.log" 2>&1
make -j"${JOBS:-2}" > "$work/libnftnl-build.log" 2>&1
make install > "$work/libnftnl-install.log" 2>&1
make -j"${JOBS:-2}" check > "$work/libnftnl-check.log" 2>&1

export PKG_CONFIG_PATH="$prefix/lib/pkgconfig${PKG_CONFIG_PATH:+:$PKG_CONFIG_PATH}"
export LIBNFTNL_CFLAGS="-I$prefix/include"
export LIBNFTNL_LIBS="-L$prefix/lib -lnftnl"
cd "$work/nftables-1.1.6"
./configure --prefix="$prefix" --disable-shared --enable-static \
    --with-json --with-xtables --disable-man-doc > "$work/nftables-configure.log" 2>&1
make -j"${JOBS:-2}" > "$work/nftables-build.log" 2>&1
make install > "$work/nftables-install.log" 2>&1
mkdir -p "$prefix/share/nft-regex"
cp -- "$work/nftables-1.1.6/COPYING" "$prefix/share/nft-regex/nftables.COPYING"
cp -- "$work/libnftnl-1.3.1/COPYING" "$prefix/share/nft-regex/libnftnl.COPYING"
printf '%s\n' "$work" > "$base/last-build"
"$prefix/sbin/nft" --version
printf 'Ready: %s\n' "$prefix/sbin/nft"
