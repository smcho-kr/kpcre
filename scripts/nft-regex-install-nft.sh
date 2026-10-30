#!/bin/sh
# SPDX-License-Identifier: GPL-2.0-only
# Replace only the command; the custom nft embeds its modified Netfilter libraries.
set -eu
umask 077
project=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
binary=${1:-"$project/.build/nft-regex/nft/sbin/nft"}
target=${2:-/usr/sbin/nft}
backup_root=${3:-/var/backups/nft-regex}
case "$target" in /*) ;; *) echo 'Target must be an absolute path' >&2; exit 1 ;; esac
test -x "$binary"
test -f "$target"
mkdir -p -- "$backup_root"
backup=$(mktemp -d "$backup_root/$(date -u +%Y%m%dT%H%M%SZ)-XXXXXX")
printf 'Backup: %s\n' "$backup" >&2
printf '%s\n' "$target" > "$backup/target"
readlink -f -- "$target" > "$backup/resolved-target"
cp -a -- "$target" "$backup/nft"
cp -pL -- "$target" "$backup/nft.resolved"
cmp -- "$target" "$backup/nft.resolved"
if ! test -L "$backup/nft"; then
    cmp -- "$backup/nft" "$backup/nft.resolved"
fi
(cd "$backup" && sha256sum nft.resolved > SHA256SUMS && sha256sum -c SHA256SUMS >&2)
staged=$(mktemp "$target.nft-regex.XXXXXX")
trap 'rm -f -- "$staged"' EXIT
trap 'exit 1' HUP INT TERM
install -m 755 -- "$binary" "$staged"
digest=$(sha256sum "$staged" | cut -d ' ' -f 1)
printf '%s  %s\n' "$digest" "$target" > "$backup/installed.sha256"
mv -fT -- "$staged" "$target"
sha256sum -c "$backup/installed.sha256" >&2
printf '%s\n' "$backup"
