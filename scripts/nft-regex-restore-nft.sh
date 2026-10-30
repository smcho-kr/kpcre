#!/bin/sh
# SPDX-License-Identifier: GPL-2.0-only
set -eu
backup=${1:?Usage: restore-nft.sh BACKUP_DIRECTORY}
backup=$(CDPATH= cd -- "$backup" && pwd)
(cd "$backup" && sha256sum -c SHA256SUMS >&2)
# Refuse to overwrite a package update or another administrator's replacement.
sha256sum -c "$backup/installed.sha256" >&2
target=$(cat "$backup/target")
case "$target" in /*) ;; *) echo 'Invalid backup target' >&2; exit 1 ;; esac
if test -L "$backup/nft"; then
    resolved=$(cat "$backup/resolved-target")
    cmp -- "$resolved" "$backup/nft.resolved"
else
    cmp -- "$backup/nft" "$backup/nft.resolved"
fi
staged=$(mktemp "$target.restore.XXXXXX")
trap 'rm -f -- "$staged"' EXIT
trap 'exit 1' HUP INT TERM
rm -f -- "$staged"
cp -a -- "$backup/nft" "$staged"
mv -fT -- "$staged" "$target"
cmp -- "$target" "$backup/nft.resolved"
printf 'Restored: %s\n' "$target"
