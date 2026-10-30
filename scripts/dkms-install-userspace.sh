#!/bin/sh
# Install the shared xtables plugin before DKMS installs per-kernel modules.
set -eu
kpcre_source=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
# Refresh against the current libxtables headers even after a userspace upgrade.
exec make -B -C "$kpcre_source" CODE_WIDTH=8 userspace_install
