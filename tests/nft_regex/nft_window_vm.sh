#!/bin/sh
# Run only in the disposable guest prepared by run_vm.sh.
set -eu
grep -q 'nft_regex.test_vm=1' /proc/cmdline
NFT=/opt/nft-regex/sbin/nft
packets()
{
    "$NFT" -nn list chain inet window_test inspect | awk '/counter packets/ {
        for (i = 1; i < NF; i++) if ($i == "packets") print $(i + 1)
    }'
}
insmod /modules/libc.ko
insmod /modules/libpcre2-8.ko
insmod /modules/nft_regex_window_test.ko
rmmod nft_regex_window_test
if insmod /modules/nft_regex.ko window_packets=0; then exit 1; fi
if insmod /modules/nft_regex.ko window_packets=9; then exit 1; fi
if insmod /modules/nft_regex.ko max_flows=0; then exit 1; fi
if insmod /modules/nft_regex.ko idle_seconds=0; then exit 1; fi
for cycle in 1 2; do
    for n in 1 2 3 4 8; do
        if test "$n" = 1; then
            insmod /modules/nft_regex.ko
        else
            insmod /modules/nft_regex.ko window_packets="$n"
        fi
        test "$(cat /sys/module/nft_regex/parameters/window_packets)" = "$n"
        "$NFT" -f - <<'RULES'
table inet window_test {
    chain inspect { }
    chain output { type filter hook output priority 0; policy accept;
        meta l4proto { tcp, udp } th dport 49001 jump inspect
    }
}
RULES
        if test "$n" != 1; then
            "$NFT" 'add chain inet window_test bad { type filter hook prerouting priority 0; }'
            if "$NFT" 'add rule inet window_test bad regex "abc" counter'; then exit 1; fi
            # A regular chain reached from an unsupported hook must also be rejected.
            if "$NFT" 'add rule inet window_test inspect regex "abc" counter; add rule inet window_test bad jump inspect'; then exit 1; fi
            "$NFT" delete chain inet window_test bad
        fi
        for family in 4 6; do
            pattern=$(awk -v n="$n" 'BEGIN {s="abcdefghi"; printf "%s|%s",substr(s,1,n),substr(s,2,n)}')
            "$NFT" "add rule inet window_test inspect regex \"$pattern\" counter"
            "$NFT" -s list table inet window_test > /run/window.nft
            "$NFT" delete table inet window_test
            "$NFT" -f /run/window.nft
            /tests/window_traffic "$family" 49001 letters
            test "$(packets)" = 2
            "$NFT" flush chain inet window_test inspect
            pattern=$(awk -v n="$n" 'BEGIN {printf "%s",substr("abcdefghi",1,n+1)}')
            "$NFT" "add rule inet window_test inspect regex \"$pattern\" counter"
            /tests/window_traffic "$family" 49001 letters
            test "$(packets)" = 0
            "$NFT" flush chain inet window_test inspect
            "$NFT" 'add rule inet window_test inspect regex "^hello[0-9]+\\x00world$" counter'
            /tests/regex_traffic "$family" udp
            test "$(packets)" = 1
            "$NFT" flush chain inet window_test inspect
            echo "NFT_REGEX_WINDOW cycle=$cycle n=$n family=$family matches=2 over_window=0 udp=1"
        done
        "$NFT" delete table inet window_test
        rmmod nft_regex
    done
done
rmmod libpcre2_8
rmmod libc
echo NFT_REGEX_WINDOW_VM_PASSED
