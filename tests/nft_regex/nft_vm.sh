#!/bin/sh
# SPDX-License-Identifier: GPL-2.0-only
# Run only inside the disposable guest prepared by run_vm.sh.
set -eu
grep -q 'nft_regex.test_vm=1' /proc/cmdline
NFT=/opt/nft-regex/sbin/nft
STOCK=/usr/sbin/nft

handle()
{
    "$NFT" -a list chain inet regex_test inspect | awk '/counter.*# handle/ {print $NF}'
}

packets()
{
    "$NFT" -nn list chain inet regex_test inspect | awk '/counter packets/ {
        for (i = 1; i < NF; i++) if ($i == "packets") print $(i + 1)
    }'
}

round_trip()
{
    "$NFT" -s list table inet regex_test > /run/rules-before.nft
    "$NFT" delete table inet regex_test
    "$NFT" -f /run/rules-before.nft
    "$NFT" -s list table inet regex_test > /run/rules-after.nft
    cmp /run/rules-before.nft /run/rules-after.nft
}

reject()
{
    if printf '%s\n' "$1" | "$NFT" -f - > /run/rejected.log 2>&1; then
        echo 'Accepted an invalid regex rule' >&2
        exit 1
    fi
    test "$(packets)" = 0
}

"$STOCK" -f - <<'EOF'
table inet regex_legacy {
    set blocked { type ipv4_addr; flags interval; elements = { 192.0.2.0/24, 198.51.100.0/24 } }
    map port_marks { type inet_service : mark; elements = { 80 : 0x1, 443 : 0x2 } }
    chain output { type filter hook output priority -10; policy accept;
        ip daddr @blocked counter drop
        ip6 daddr 2001:db8::/32 counter drop
        ct state invalid counter drop
        tcp dport { 80, 443 } meta mark set tcp dport map @port_marks counter accept
        tcp dport 9 limit rate 1/second log prefix "legacy " counter accept
    }
}
table ip regex_legacy_nat {
    chain postrouting { type nat hook postrouting priority srcnat; policy accept;
        ip saddr 192.0.2.0/24 snat to 198.51.100.1
    }
}
EOF
"$STOCK" -nn list ruleset > /run/stock.nft
"$NFT" -nn list ruleset > /run/custom.nft
cmp /run/stock.nft /run/custom.nft
echo NFT_REGEX_LEGACY_COMPAT_PASSED

for cycle in 0 1; do
    insmod /modules/libc.ko
    insmod /modules/libpcre2-8.ko
    insmod /modules/nft_regex_test.ko
    rmmod nft_regex_test
    insmod /modules/nft_regex.ko
    "$NFT" -f - <<'EOF'
table inet regex_test {
    chain inspect { }
    chain output { type filter hook output priority 0; policy accept;
        meta l4proto { tcp, udp } th dport 49001 jump inspect
    }
}
EOF
    for family in 4 6; do
        for protocol in tcp udp; do
            "$NFT" 'add rule inet regex_test inspect regex "^hello[0-9]+\\x00world$" counter'
            if test "$family:$protocol" = 4:tcp; then
                reject 'add rule inet regex_test inspect regex "" counter'
                reject 'add rule inet regex_test inspect regex "[" counter'
                reject 'add rule inet regex_test inspect regex "(*UTF)abc" counter'
                long=$(awk 'BEGIN {for (i = 0; i < 256; i++) printf "a"}')
                reject "add rule inet regex_test inspect regex \"$long\" counter"
                printf '%s\n' '{"nftables":[{"add":{"rule":{"family":"inet","table":"regex_test","chain":"inspect","expr":[{"regex":{"pattern":"a\u0000b"}}]}}}]}' > /run/invalid.json
                if "$NFT" -j -f /run/invalid.json > /run/rejected.log 2>&1; then exit 1; fi
                test "$(packets)" = 0
                maximum=$(awk 'BEGIN {for (i = 0; i < 255; i++) printf "a"}')
                "$NFT" "add rule inet regex_test inspect regex \"$maximum\" counter"
                test "$(handle | wc -l)" = 2
                "$NFT" delete rule inet regex_test inspect handle "$(handle | tail -n 1)"
                "$NFT" "replace rule inet regex_test inspect handle $(handle) regex \"(?i)^HELLO[0-9]+\\\\x00WORLD$\" counter"
            fi
            round_trip
            if rmmod nft_regex > /run/busy.log 2>&1; then exit 1; fi
            /tests/regex_traffic "$family" "$protocol"
            test "$(packets)" = 1
            "$NFT" delete rule inet regex_test inspect handle "$(handle)"
            test -z "$(handle)"
            echo "NATIVE_REGEX_TRAFFIC cycle=$cycle family=$family protocol=$protocol matches=1"
        done
    done

    "$NFT" -f - <<'EOF'
add rule inet regex_test inspect regex "^(a\"b\\\\c|\\d+)$" counter
add rule inet regex_test inspect regex "(?i)word\\b" counter
add rule inet regex_test inspect regex "a;b#c" counter
add rule inet regex_test inspect regex "line
break" counter
EOF
    round_trip
    "$NFT" flush chain inet regex_test inspect
    "$NFT" 'add table inet regex; add chain inet regex regex; add rule inet regex regex counter'
    "$NFT" delete table inet regex
    for family in ip ip6; do
        "$NFT" "add table $family regex_family; add chain $family regex_family inspect; add rule $family regex_family inspect regex \"abc\" counter"
        "$NFT" list table "$family" regex_family | grep -F 'regex "abc"'
        "$NFT" delete table "$family" regex_family
    done

    "$NFT" 'add rule inet regex_test inspect regex "^hello[0-9]+\\x00world$" counter'
    "$NFT" -s list ruleset > /run/mixed-before.nft
    "$NFT" -j list ruleset > /run/rules.json
    "$NFT" flush ruleset
    "$NFT" -j -f /run/rules.json
    "$NFT" -s list ruleset > /run/mixed-after.nft
    cmp /run/mixed-before.nft /run/mixed-after.nft
    "$NFT" flush chain inet regex_test inspect
    echo "NFT_REGEX_TEXT_JSON_ROUNDTRIP cycle=$cycle PASSED"

    for verdict in drop accept; do
        "$NFT" "add rule inet regex_test inspect regex \"^hello[0-9]+\\\\x00world$\" counter $verdict"
        if test "$verdict" = accept; then "$NFT" add rule inet regex_test inspect counter drop; fi
        for family in 4 6; do /tests/regex_traffic "$family" udp "$verdict"; done
        test "$(packets | head -n 1)" = 2
        "$NFT" flush chain inet regex_test inspect
        echo "NATIVE_REGEX_VERDICT cycle=$cycle verdict=$verdict IPV4_IPV6_PASSED"
    done
    "$NFT" delete table inet regex_test
    rmmod nft_regex
    rmmod libpcre2_8
    rmmod libc
done

cp -p "$STOCK" /run/original-nft
backup=$(sh /project/scripts/install-nft.sh "$NFT" "$STOCK" /run/nft-backups)
cmp /run/original-nft "$backup/nft.resolved"
cmp "$NFT" "$STOCK"
"$STOCK" --version
sh /project/scripts/restore-nft.sh "$backup"
cmp /run/original-nft "$STOCK"
"$STOCK" -nn list ruleset > /run/stock.nft
"$NFT" -nn list ruleset > /run/custom.nft
cmp /run/stock.nft /run/custom.nft
echo NFT_REGEX_INSTALL_BACKUP_PASSED
"$NFT" flush ruleset
echo NFT_REGEX_VM_PASSED
