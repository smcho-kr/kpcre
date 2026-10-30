# Native nftables Regex Design Notes

The native `regex` expression uses the shared 8-bit PCRE2 kernel library and
requires successful JIT compilation before a rule becomes active. Matching and
verdict selection are separate: a match allows the following expressions to run,
a normal nonmatch skips the rest of the rule, and an inspection error drops the
packet independently of the configured verdict.

## Input validation

Patterns contain 1–255 bytes and cannot contain embedded NULs or enable UTF mode.
The kernel independently validates Netlink lengths and termination. Matching
uses validated TCP/UDP payload offsets and copies non-linear packet data with
`skb_copy_bits()`. Residual fragments, malformed headers, and oversized payloads
are inspection errors. No encrypted-content decoding is performed.

## TCP windows and UDP boundaries

`window_packets` defaults to 1. Values 2–8 retain sequence-adjacent TCP payloads
for each expression, conntrack connection, and direction. UDP remains
per-datagram. Native parameters and cached state are independent from `xt_ids`.

ACK-only packets preserve history. Exact retransmissions of the last cached
payload retain its verdict without advancing the window. Gaps, overlaps,
conflicting retransmissions, and out-of-order packets restart inspection at the
current payload. SYN/RST/FIN and idle expiry limit history lifetime. This bounded
window does not implement full endpoint TCP semantics.

A reported match must consume current payload bytes. In window mode, a final
PCRE callout rejects history-only candidates while allowing alternative matches.
Explicit callouts and ACCEPT constructs are rejected in this mode to prevent
bypassing that check. The original pattern is returned when listing a rule;
internal pointers and generated code are never included.

## Ownership and resource bounds

Pattern code is immutable after rule creation. Each possible CPU owns its
scratch buffer, match data, context, and JIT stack. Bottom-half/preemption
exclusion and a reentry guard protect CPU-local resources; bucket locks protect
connection history. Rule destruction cancels pending cache cleanup and releases
payloads, conntrack references, and generated code.

Pattern size, payload size, matching work, cached flow count, and idle lifetime
are bounded. Native windowing uses INPUT, FORWARD, or OUTPUT after conntrack.
Missing TCP state, allocation/capacity failures, and regex execution limits drop
the packet. Increasing N increases memory and search work; fixed execution limits
can be reached earlier with a larger window.

See the [usage guide](nftables-regex.md) for supported values, installation,
configuration, rule examples, and operating limitations.
