#!/bin/sh
# SPDX-License-Identifier: GPL-2.0-only
set -eu
project=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
work=$(mktemp -d "${TMPDIR:-/tmp}/nft backup-XXXXXX")
trap 'rm -rf -- "$work"' EXIT
trap 'exit 1' HUP INT TERM
for kind in file symlink; do
    root="$work/$kind"
    mkdir -p "$root"
    printf 'original nft\n' > "$root/original"
    chmod 751 "$root/original"
    if test "$kind" = symlink; then
        ln -s original "$root/nft"
    else
        cp -p "$root/original" "$root/nft"
    fi
    printf 'replacement nft\n' > "$root/new nft"
    chmod 755 "$root/new nft"
    backup=$(sh "$project/scripts/nft-regex-install-nft.sh" "$root/new nft" "$root/nft" "$root/backups")
    cmp "$root/nft" "$root/new nft"
    cmp "$backup/nft.resolved" "$root/original"
    test "$(stat -c %a "$backup")" = 700
    sh "$project/scripts/nft-regex-restore-nft.sh" "$backup"
    cmp "$root/nft" "$root/original"
    test "$(stat -Lc %a "$root/nft")" = 751
    if test "$kind" = symlink; then test -L "$root/nft"; else test ! -L "$root/nft"; fi
    printf 'later package update\n' > "$root/nft"
    if sh "$project/scripts/nft-regex-restore-nft.sh" "$backup" > "$root/refused.log" 2>&1; then
        echo 'Restoration overwrote a later replacement' >&2
        exit 1
    fi
    test "$(cat "$root/nft")" = 'later package update'
    printf 'NFT_REGEX_INSTALL_%s_PASSED\n' "$kind"
done
