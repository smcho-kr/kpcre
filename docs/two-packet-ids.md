# Configurable TCP Payload Windows with xt_ids

Recorded: 2026-10-22. Validated: `7.0.0-38-generic`, x86-64,
iptables-legacy/ip6tables-legacy 1.8.11.
Configurable-window update: 2026-10-31.

## Scope and interface

`xt_ids.ko` adds a separate `-m ids --regex PATTERN` match. It uses the existing
8-bit PCRE2 kernel library and its JIT allocator. The distribution kernel and
the existing `ts_pcre`, `ts_regex`, and `-m string` interfaces are unchanged.

For each rule, connection, and direction, inspection retains up to N−1 TCP
payloads. When the next observed payload starts at the expected TCP sequence
number, the matcher searches the retained history plus the current payload.
It then evicts the oldest payload if necessary. The default N=2 behaves as follows:

| Arrival | Payload | Subject searched | Retained afterward |
| --- | --- | --- | --- |
| 1 | `abc` | `abc` | `abc` |
| 2 | `defghi` | `abcdefghi` | `defghi` |
| 3 | `jkl` | `defghijkl` | `jkl` |

The pattern `abcdef|ghijkl` matches arrivals 2 and 3. A pattern requiring bytes
from all three payloads, such as `abcdefghij`, does not match this sequence at
N=2; N=3 can detect it.
Current-payload-only matches also count. Empty matches do not count.

`window_packets` is a read-only module parameter with range 1–8 and default 2.
It applies to every `ids` rule and namespace using that loaded module. For N=4,
the windows grow as `1`, `1+2`, `1+2+3`, `1+2+3+4`, then slide to `2+3+4+5`.
Inspection begins immediately; it does not wait for N arrivals. ACK-only packets
and exact retransmissions of the cached last payload do not consume slots.
N=1 searches only the current payload but retains its bytes and verdict for
retransmission handling. Existing rule syntax and the userspace/kernel ABI remain
unchanged; the userspace extension has no new required option.

For a freshly loaded module in the disposable test VM:

```sh
modprobe xt_ids window_packets=4
cat /sys/module/xt_ids/parameters/window_packets
```

For persistence, put `options xt_ids window_packets=4` in
`/etc/modprobe.d/kpcre-ids.conf`. This setting takes effect on the next module
load. Changing it while loaded requires removing all `ids` rules, unloading
`xt_ids`, and loading it with the new value before restoring rules. Reloading
clears cached history. `iptables-save` preserves rules, not module parameters;
keep the modprobe configuration with the firewall configuration.

**Inspection failures drop the packet independently of the selected target.**
This includes missing conntrack state, oversized payloads, memory/capacity
failures, and JIT execution limits. A rule with `-j LOG` is therefore not a
guaranteed passive monitor. Normal successful inspection with no match simply
continues rule traversal. This fail-closed choice prevents inspection failures
from silently becoming successful passes through a blocking rule.

## Why a separate match is needed

The text-search callback used by `ts_pcre` receives byte blocks, not the TCP
connection, sequence numbers, or conntrack direction. It cannot safely associate
payloads from different packets with a TCP stream. The new xtables callback has
the `sk_buff` and transport offset needed for this association.

Three different boundaries matter:

- A single skb can contain linear data and non-linear page fragments. These are
  memory-layout boundaries; `skb_copy_bits()` copies them into one subject.
- IP fragmentation divides an IP datagram. Normal conntrack processing enables
  defragmentation before the supported filter hooks. This module does not
  implement IP reassembly; residual fragment offsets or invalid headers fail.
- TCP segmentation divides the byte stream. The module joins at most N
  sequence-adjacent payloads observed at its hook.

GRO/GSO can change skb boundaries. Here, N counts observed payload-bearing skbs,
not necessarily packets on the wire. A coalesced skb
may already contain several original TCP segments or exceed the payload limit.
[Linux segmentation offload documentation](https://docs.kernel.org/networking/segmentation-offloads.html)

## Build and installation

Use matching kernel headers, a C toolchain, `CODE_WIDTH=8`, xtables development
headers (`libxtables-dev` on Debian/Ubuntu), and pkg-config. Root builds include
`xt_ids` and the userspace extension for the default 8-bit configuration. Root
`make modules_install` installs both components. DKMS uses an executable
`PRE_INSTALL` hook to build/install the extension before installing its six
kernel modules; it also runs during kernel-update autoinstall.

Build the default package with matching kernel headers:

```sh
make CODE_WIDTH=8 modules
```

The build stops on submodule errors and includes the userspace extension.

Install and execute first **inside a disposable test VM**:

```sh
sudo make modules_install
sudo modprobe xt_ids
```

The automatic installer uses `pkg-config --variable=xtlibdir xtables`. When that is
unavailable, supply the extension directory used by the intended iptables
binary, for example `XTABLES_LIBDIR=/usr/lib/x86_64-linux-gnu/xtables` on the
tested distribution. `DESTDIR` only redirects userspace plugin installation; it does not redirect
kernel-module installation or `depmod`.
Do not copy a plugin built against an incompatible libxtables ABI.

JIT compilation is mandatory: unavailable JIT rejects rule insertion. The
existing [executable-memory requirements](kernel-jit-executable-memory.md)
apply, including the modern allocator's x86-64/Kprobes requirements and IBT/CFI
restrictions. The pre-5.8 allocator code is unchanged; this new match has not
been built or executed on pre-5.8 kernels. Secure Boot signing policy still
applies. The new match additionally requires conntrack and legacy IPv4/IPv6
xtables filter support. Native nftables syntax and iptables-nft compatibility
have not been validated.

## Rule examples and placement

After installing both components in the test VM:

```sh
iptables-legacy -A FORWARD -p tcp --dport 8080 \
  -m ids --regex '(?i)blocked-pattern' -j DROP
ip6tables-legacy -A FORWARD -p tcp --dport 8080 \
  -m ids --regex '(?i)blocked-pattern' -j DROP
```

The match is restricted to TCP in the `filter` table and the `INPUT`, `FORWARD`,
and `OUTPUT` paths, including user chains reached from those hooks. Negation of
`--regex` is unsupported. `--regex` accepts 1–255 pattern bytes, without the
`/pattern/flags` delimiters used by the older text-search engine. Use inline
options such as `(?i)`, and `\x00` for a NUL byte. Subjects are binary bytes;
UTF mode is disabled.

Every payload needed for a window must reach the same rule. Place inspection
before an unconditional established-connection ACCEPT and use consistent
interface/port selection. A `--ctstate NEW` restriction alone misses subsequent
stream data. Rate-limiting before `-m ids` skips cache updates for skipped
packets; rate-limit an alert target after inspection instead. The first payload
may already have been forwarded when a boundary signature is discovered in the
second. A DROP target acts on the current packet, not retroactively on the first.

Rule state is independent for each rule. Table replacement, rule reload, or
module reload rebuilds that state, including when legacy iptables reconstructs
otherwise unchanged rules. Remove all rules referencing `ids` before unloading
`xt_ids`; unload the PCRE library only after its other users are removed.

## State, ordering, and lifetime

Each rule owns a 64-bucket hash table keyed by a referenced conntrack object.
This separates connections, namespaces, and conntrack zones without inventing
a second five-tuple lifetime mechanism. Each entry holds independent original
and reply directions. Holding a conntrack reference prevents pointer reuse
while cached state exists.

| Event | Behavior |
| --- | --- |
| First payload | Search it alone, then cache it. |
| Exactly adjacent sequence number | Search retained history plus current; retain the latest N−1 payloads (at least one for N=1 retransmission handling). |
| ACK without payload | Preserve the cache; do not refresh its payload idle timer. |
| Exact retransmission of cached sequence, length, and bytes | Return the cached match verdict; preserve the window. |
| Gap, out-of-order arrival, overlap, or changed retransmission | Search current alone and restart that direction's window. |
| SYN | Clear both cached directions for that connection before processing payload. |
| RST | Discard the entry; do not search its payload. |
| FIN | Process any payload, then close that direction to further concatenation. Retain the last verdict for exact retransmissions. |
| Idle expiry | Discard both directions. |

Adjacency arithmetic uses 32-bit TCP sequence wraparound and accounts for SYN's
sequence consumption. This is not endpoint TCP validation: there is no overlap
policy matching a particular OS, reorder queue, ACK-based reconstruction, or
full TCP Fast Open handling. An attacker can evade signatures by arranging
segmentation or ordering outside the configured window. Cached retransmission
verdicts prevent a simple resend of the last blocked boundary packet from
changing to a nonmatch; they do not provide a complete retransmission history.

A delayed worker removes idle or dying conntrack entries every five seconds.
Packet lookup also checks idle expiry. Rule destruction cancels the worker,
releases conntrack references and cached buffers, and frees the JIT code after
xtables has stopped using that rule.

## Matching semantics and CPU ownership

The pattern is validated independently, then compiled as
`(?:PATTERN)(?C254)` with automatic callouts. The final callout rejects a
candidate ending wholly within the retained history, allowing PCRE to try
another alternative or later position. For example, `abc|abcdef` can reject
the old-only `abc` candidate and still report `abcdef` across the boundary.
PCRE callouts support candidate rejection through positive return values and
abort through negative values in JIT matching.
[PCRE2 callout documentation](https://pcre.org/current/doc/html/pcre2callout.html)

Patterns containing `(*ACCEPT` or `(?C` are rejected because they can bypass or
impersonate the final callout. Validation of the raw pattern prevents unmatched
parentheses from escaping the wrapper. Some other PCRE constructs are less
useful with a sliding window: start-only directives may fail wrapped compilation,
whole-pattern recursion includes the wrapper, and `^`, `$`, `\A`, and `\z`
refer to the current window rather than the full stream. Test actual signatures.

Only nonempty matches **consuming bytes in the current payload** count.
`(?<=abc)def` can match with `abc` in the previous payload. Conversely,
`abc(?=def)` is not reported when only its lookahead reaches the current
payload, because its consumed match ends in the previous one. A match already
reported solely in the previous payload is not reported again on a new payload.

Each possible CPU owns its match context, match data, JIT stack, and scratch
buffer. Bottom halves and preemption are disabled while these objects are in
use; a reentry guard rejects recursive use. A bucket lock serializes inspection
and state replacement for entries in that bucket. Pattern code is immutable
after compilation. No executable memory is allocated during packet inspection.
Cached-payload allocations use `GFP_ATOMIC`.
History consists of separately allocated payloads and a bounded array of at most
seven descriptors per direction. Advancing the window copies descriptor metadata
and frees the oldest payload; it does not allocate a large contiguous history
buffer in packet context. The contiguous search buffer is allocated at module
initialization and sized for N maximum-size payloads.

## Resource bounds and failure policy

Read-only module parameters are set at load time:

| Parameter | Default | Accepted range | Meaning |
| --- | --- | --- | --- |
| `window_packets` | 2 | 1–8 | Maximum adjacent payload-bearing skbs searched together. |
| `payload_limit` | 16384 | 256–65535 | Maximum bytes in one observed TCP payload. |
| `max_flows` | 4096 | 1–65536 | Maximum cached rule/connection entries across all rules and namespaces. |
| `idle_seconds` | 30 | 1–3600 | Idle time since the last payload, across either direction. |

There is no arbitrary tail truncation: payloads exceeding the configured limit
are dropped. GRO/GSO makes this possible even when the wire MTU is small.
Inspect the expected traffic and offload behavior before setting this limit.
Even a 65535-byte limit does not support arbitrarily large aggregated skbs.

Cached payload storage is bounded by approximately
`max_flows * 2 * max(1, N-1) * payload_limit`, or 128 MiB at defaults, plus entry metadata,
allocator overhead, held conntrack objects, and transient replacement buffers.
Each possible CPU also reserves an `N * payload_limit` scratch buffer and a JIT
stack with a 64 KiB backing allocation, plus PCRE context data. Rules additionally
consume hash-table and compiled-code storage. Restrict inspected traffic and
rule count; these defaults are limits, not a throughput or memory recommendation.

With `max_flows=4096` and `payload_limit=16384`, the payload-cache ceilings for
N=2, 4, and 8 are respectively 128, 384, and 896 MiB, before the other costs
above. These bytes are allocated as traffic arrives, not reserved at load time.
Reduce `max_flows` when increasing N if the available cache budget is unchanged.

Each packet search has a PCRE match limit of 10000, a 100000-callout budget,
and a 64 KiB maximum JIT stack. These bound selected matching operations, not
wall-clock latency. Automatic callouts, copying, allocations, and bucket locks
have a cost; no speed advantage over `ts_pcre` is claimed.
For similarly sized payloads, copying grows approximately with N. Search time
also depends on the pattern, match location, and backtracking; it is not
guaranteed to grow linearly. JIT does not remove these costs. Increasing N can
make a previously acceptable signature hit an execution limit and drop traffic.
The limits are intentionally unchanged; throughput has not been benchmarked.

Capacity exhaustion does not evict an arbitrary active flow. It drops packets
requiring another entry until capacity is available. Invalid/missing conntrack,
malformed packets, oversized payloads, allocation failures, reentry, or negative
JIT results similarly set xtables `hotdrop`. Matching errors discard that flow's
cache. Diagnostics are rate limited and include the error code. Normal matches
return true and let the selected target decide what happens next.

## Compatibility and operating limits

The implementation was checked with `7.0.0-38-generic`, x86-64, and
iptables-legacy/ip6tables-legacy 1.8.11. Checks covered sliding windows N=1–8,
connection/direction isolation, retransmissions, sequence wraparound, binary and
non-linear payloads, control-packet transitions, resource limits, and cleanup.

Real IPv4/IPv6 loopback OUTPUT checks covered N=1, 2, 3, 4, and 8 over three
cycles, totaling 90 TCP sessions. For N=4, nine individual payloads `a` through
`i` produced two matches for `abcd|bcde` and none for `abcde`. Rule save/restore,
invalid input rejection, and module unload were also checked without kernel
faults or sanitizer reports.

These traffic checks used RETURN counters. They do not validate physical NICs,
FORWARD or DROP delivery, sustained load, throughput, other kernels, nftables
compatibility, PREEMPT_RT, concurrent rule replacement, or forced allocation
failure. The window does not implement full TCP reassembly, application parsing,
or encrypted-content inspection.
