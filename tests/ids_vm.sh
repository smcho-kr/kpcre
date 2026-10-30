#!/bin/sh
# Run only inside the disposable VM prepared as described in docs/two-packet-ids.md.
set -eu
grep -q 'kpcre.ids_vm=1' /proc/cmdline || {
    echo 'Refusing to run without the disposable-VM boot marker' >&2
    exit 1
}

for cycle in 1 2 3; do
    echo "IDS_VM_CYCLE=$cycle"
    insmod /modules/libc.ko
    insmod /modules/libpcre2-8.ko
    insmod /modules/kpcre_ids_test.ko
    rmmod kpcre_ids_test
    if insmod /modules/xt_ids.ko window_packets=0; then exit 1; fi
    if insmod /modules/xt_ids.ko window_packets=9; then exit 1; fi
    for packets in 1 2 3 4 8; do
        if [ "$packets" = 2 ]; then
            insmod /modules/xt_ids.ko
        else
            insmod /modules/xt_ids.ko window_packets="$packets"
        fi
        test "$(cat /sys/module/xt_ids/parameters/window_packets)" = "$packets"
        for family in 4 6; do
            if [ "$family" = 4 ]; then command=iptables-legacy; else command=ip6tables-legacy; fi
            "$command" -N IDS_TEST
            "$command" -A OUTPUT -p tcp --dport 49001 -j IDS_TEST
            "$command" -A IDS_TEST -p tcp -m ids --regex 'abcdef|ghijkl' -j RETURN
            "${command}-save" -t filter > /run/ids-rules
            "${command}-restore" < /run/ids-rules
            /tests/ids_traffic "$family" 49001
            count=$("$command" -L IDS_TEST -n -v -x | awk '$3 == "RETURN" {print $1}')
            if [ "$packets" = 1 ]; then expected=0; else expected=2; fi
            test "$count" = "$expected"
            "$command" -S IDS_TEST
            "$command" -F IDS_TEST
            pattern=$(awk -v n="$packets" 'BEGIN { s="abcdefghi"; printf "%s|%s", substr(s,1,n), substr(s,2,n) }')
            "$command" -A IDS_TEST -p tcp -m ids --regex "$pattern" -j RETURN
            /tests/ids_traffic "$family" 49001 letters
            count=$("$command" -L IDS_TEST -n -v -x | awk '$3 == "RETURN" {print $1}')
            test "$count" = 2
            echo "IDS_WINDOW=$packets IPV=$family MATCHES=$count"
            "$command" -F IDS_TEST
            pattern=$(awk -v n="$packets" 'BEGIN { printf "%s", substr("abcdefghi",1,n+1) }')
            "$command" -A IDS_TEST -p tcp -m ids --regex "$pattern" -j RETURN
            /tests/ids_traffic "$family" 49001 letters
            count=$("$command" -L IDS_TEST -n -v -x | awk '$3 == "RETURN" {print $1}')
            test "$count" = 0
            echo "IDS_WINDOW=$packets IPV=$family OVER_WINDOW_MATCHES=$count"
            if "$command" -A IDS_TEST -p tcp -m ids --regex '[' -j RETURN; then exit 1; fi
            if "$command" -A IDS_TEST -p udp -m ids --regex abc -j RETURN; then exit 1; fi
            if "$command" -A IDS_TEST -p tcp -m ids --regex '' -j RETURN; then exit 1; fi
            long_pattern=$(awk 'BEGIN { for (i = 0; i < 256; i++) printf "a" }')
            if "$command" -A IDS_TEST -p tcp -m ids --regex "$long_pattern" -j RETURN; then exit 1; fi
            "$command" -D OUTPUT -p tcp --dport 49001 -j IDS_TEST
            "$command" -F IDS_TEST
            "$command" -X IDS_TEST
            echo "IDS_WINDOW_${packets}_IPV${family}_PASSED"
        done
        rmmod xt_ids
    done
    rmmod libpcre2_8
    rmmod libc
done
echo IDS_VM_TEST_PASSED
