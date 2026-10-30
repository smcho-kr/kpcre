#!/bin/sh
# SPDX-License-Identifier: GPL-2.0-only
# Package a diskless guest; all module and firewall operations run inside it.
set -eu
project=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
cd "$project"
kernel=$(uname -r)
nft_binary=${NFT_BIN:-"$project/.build/nft-regex/nft/sbin/nft"}
kpcre_build=${KPCRE_BUILD:-"$project"}
qemu_root=${QEMU_ROOT:-/}
work=$(mktemp -d "${TMPDIR:-/tmp}/nftables-regex-vm-XXXXXX")
chmod 755 "$work"
guest="$work/guest"
mkdir -p "$guest/bin" "$guest/sbin" "$guest/proc" "$guest/sys" "$guest/dev" \
    "$guest/run" "$guest/tmp" "$guest/modules" "$guest/tests" "$guest/project/scripts"
printf 'VM evidence: %s\n' "$work"
make -C tests/nft_regex traffic > "$work/traffic-build.log" 2>&1

copy()
{
    destination="$guest$2"
    mkdir -p "$(dirname -- "$destination")"
    cp -pL -- "$1" "$destination"
}

libraries()
{
    ldd "$1" > "$work/ldd.txt" 2>/dev/null || :
    awk '/=> \// {print $3} /^[ \t]*\// {print $1}' "$work/ldd.txt" > "$work/libraries.txt"
    while IFS= read -r library; do copy "$library" "$library"; done < "$work/libraries.txt"
}

copy "$(command -v busybox)" /bin/busybox
libraries "$(command -v busybox)"
for command in sh mount ip insmod rmmod dmesg poweroff mkdir mktemp date readlink \
    cp cmp sha256sum install cut mv rm cat dirname awk grep wc tail head; do
    ln -s busybox "$guest/bin/$command"
done
copy /usr/sbin/nft /usr/sbin/nft
libraries /usr/sbin/nft
copy "$nft_binary" /opt/nft-regex/sbin/nft
libraries "$nft_binary"
copy .build/nft-regex/regex_traffic /tests/regex_traffic
copy .build/nft-regex/window_traffic /tests/window_traffic
libraries .build/nft-regex/regex_traffic
copy tests/nft_regex/nft_vm.sh /tests/nft_vm.sh
copy tests/nft_regex/nft_window_vm.sh /tests/nft_window_vm.sh
for script in install-nft.sh restore-nft.sh; do
    copy "scripts/nft-regex-$script" "/project/scripts/$script"
done
copy "$kpcre_build/libc/libc.ko" /modules/libc.ko
copy "$kpcre_build/pcre2/libpcre2-8.ko" /modules/libpcre2-8.ko
copy nft_regex/nft_regex.ko /modules/nft_regex.ko
copy tests/nft_regex/nft_regex_test.ko /modules/nft_regex_test.ko
copy tests/nft_regex/nft_regex_window_test.ko /modules/nft_regex_window_test.ko

cat > "$guest/init" <<'EOF'
#!/bin/sh
set -e
export PATH=/bin:/sbin:/usr/bin:/usr/sbin
mount -t proc proc /proc
mount -t sysfs sysfs /sys
mount -t devtmpfs devtmpfs /dev
EOF
modprobe -S "$kernel" -a --show-depends nf_tables nft_ct nft_chain_nat nft_nat \
    nft_limit nf_log_syslog nft_log > "$work/dependencies.txt"
awk '$1 == "insmod" && !seen[$2]++ {print $2}' "$work/dependencies.txt" > "$work/module-paths.txt"
while IFS= read -r source; do
    name=$(basename -- "$source")
    case "$name" in
        *.zst) name=${name%.zst}; zstd -d -c "$source" > "$guest/modules/$name" ;;
        *.xz) name=${name%.xz}; xz -d -c "$source" > "$guest/modules/$name" ;;
        *) copy "$source" "/modules/$name" ;;
    esac
    printf 'insmod /modules/%s\n' "$name" >> "$guest/init"
done < "$work/module-paths.txt"
cat >> "$guest/init" <<'EOF'
ip link set lo up
if sh /tests/nft_vm.sh && sh /tests/nft_window_vm.sh; then
    echo NFT_REGEX_VM_SUCCESS
else
    echo NFT_REGEX_VM_FAILED
fi
dmesg
poweroff -f
EOF
chmod 755 "$guest/init"
cp "/boot/vmlinuz-$kernel" "$work/vmlinuz"
chmod 644 "$work/vmlinuz"
(cd "$guest" && find . -print0 | cpio --null -o -H newc) > "$work/initramfs.cpio" 2> "$work/cpio.log"

set -- "$qemu_root/usr/bin/qemu-system-x86_64" -machine pc -accel tcg,thread=single \
    -cpu max -smp 2 -m 512 -nodefaults -display none -serial stdio -monitor none \
    -nic none -no-reboot \
    -sandbox on,obsolete=deny,elevateprivileges=deny,spawn=deny,resourcecontrol=deny \
    -bios "$qemu_root/usr/share/seabios/bios-256k.bin" -L "$qemu_root/usr/share/qemu" \
    -kernel "$work/vmlinuz" -initrd "$work/initramfs.cpio" \
    -append 'console=ttyS0 rdinit=/init panic=1 oops=panic panic_on_warn=1 loglevel=6 nft_regex.test_vm=1'
if test "$(id -u)" = 0; then
    set -- setpriv --reuid=65534 --regid=65534 --clear-groups "$@"
fi
status=0
(
    ulimit -c 0
    ulimit -t 360
    if test "$qemu_root" != /; then
        export LD_LIBRARY_PATH="$qemu_root/usr/lib/x86_64-linux-gnu"
    fi
    nice -n 19 timeout --kill-after=5 420 "$@"
) > "$work/serial.log" 2>&1 || status=$?
grep -E 'NFT_REGEX|NATIVE_REGEX|nft_regex(_window)?_test:|BUG:|WARNING:|UBSAN:|Kernel panic' "$work/serial.log" || :
test "$status" = 0
for marker in NFT_REGEX_VM_PASSED NFT_REGEX_VM_SUCCESS NFT_REGEX_LEGACY_COMPAT_PASSED \
    NFT_REGEX_INSTALL_BACKUP_PASSED NFT_REGEX_WINDOW_VM_PASSED; do
    grep -q "$marker" "$work/serial.log"
done
test "$(grep -c '^NATIVE_REGEX_TRAFFIC cycle=' "$work/serial.log")" = 8
test "$(grep -c '^NATIVE_REGEX_VERDICT cycle=' "$work/serial.log")" = 4
test "$(grep -c '^NFT_REGEX_TEXT_JSON_ROUNDTRIP cycle=' "$work/serial.log")" = 2
test "$(grep -c 'nft_regex_test: PASS' "$work/serial.log")" -ge 2
test "$(grep -c '^NFT_REGEX_WINDOW cycle=' "$work/serial.log")" = 20
grep -q 'nft_regex_window_test: PASS' "$work/serial.log"
if grep -E 'BUG:|WARNING:|UBSAN:|Kernel panic|NFT_REGEX_VM_FAILED' "$work/serial.log"; then exit 1; fi
{
    printf 'Kernel: %s\nEvidence: %s\n' "$kernel" "$work"
    sha256sum "$nft_binary" nft_regex/nft_regex.ko tests/nft_regex/nft_regex_test.ko .build/nft-regex/regex_traffic \
        tests/nft_regex/run_vm.sh tests/nft_regex/nft_vm.sh tests/nft_regex/nft_window_vm.sh \
        tests/nft_regex/nft_regex_window_test.c tests/nft_regex/regex_traffic.c tests/ids_traffic.c \
        tests/nft_regex/nft_regex_window_test.ko .build/nft-regex/window_traffic \
        scripts/nft-regex-install-nft.sh scripts/nft-regex-restore-nft.sh "$work/serial.log"
} > "$work/validation.txt"
printf '%s\n' "$work" > .build/nft-regex/last-vm
echo 'PASS: native nft, real traffic, persistence, compatibility, backup/restore and kernel checks'
