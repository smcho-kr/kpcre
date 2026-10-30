# nftables Payload Regex

`nft_regex.ko` implements a native nftables expression named `regex`. It searches
TCP and UDP application payloads using the **8-bit PCRE2 kernel library in
[this repository](../README.md)**. The existing kpcre engine is linked as a separate
module; its sources and interfaces are not modified or duplicated by the native nftables module.

The patched `nft` command supports `regex "PATTERN"` directly, including standard
conditions, counters, verdicts, rule handles, and text/JSON ruleset save/restore.
The patches target nftables **1.1.6** and libnftnl **1.3.1**, matching the tested
system packages. The modified libraries are statically linked into the new
executable; it uses the system's ordinary runtime dependencies without replacing
system Netfilter shared libraries. All configuration uses the native command.

The system command is replaced only by an explicit installation that preserves
and verifies a timestamped backup. Use the regex-enabled native command for
creating, listing, saving, and restoring rules containing this expression.

## Matching semantics

- Supported table families: `ip`, `ip6`, and `inet`.
- TCP: inspect bytes after the TCP header and its declared options.
- UDP: inspect bytes after the UDP header, up to the declared UDP length.
- A match must consume at least one byte. Empty payloads do not match, though
  empty TCP control packets update window state when N>1. Unsupported transport
  protocols do not match. Anchors refer to the current payload/window.
- By default (`window_packets=1`), each skb is inspected independently and no
  TCP payload history is retained. With N=2–8, TCP uses an independent sliding
  window for each regex expression, conntrack connection, and direction. UDP
  always remains per-datagram. This is bounded inspection, not full TCP stream
  reassembly or application decoding; signatures spanning more than N observed
  payloads, gaps, or unsupported overlap/reordering patterns can evade a rule.
- Matching is binary-safe, including embedded NUL payload bytes. Patterns are
  byte-oriented PCRE2 10.23 expressions from kpcre. Use inline modifiers such
  as `(?i)` for case-insensitive matching. UTF mode is rejected. The frontend
  passes pattern bytes to the kernel without Unicode matching semantics.
- Non-linear skb memory is copied with `skb_copy_bits()` into a bounded buffer.
  GRO/GSO can change the inspected skb boundaries; they are not necessarily
  individual wire packets. Inspecting encrypted traffic does not reveal plaintext.
- Unreassembled IPv4 fragments and IPv6 fragment headers are inspection errors.
  IPv6 extension headers are walked to validate the transport offset. Jumbograms
  are unsupported. At N=1 this expression does not enable defragmentation itself.
  At N>1, acquiring conntrack enables its normal tracking/defragmentation hooks;
  any residual fragments still fail inspection.

**Inspection errors drop the packet, even when the rule uses `continue` or
`accept`.** Errors include malformed or truncated headers, unsupported
fragmentation, oversized payloads, reentry, and regex execution limits. The
following counter and verdict do not execute for those errors. A normal nonmatch
skips the remaining expressions in that rule and continues rule traversal.
A normal match continues to the counter and selected verdict.

Use existing nftables conditions to restrict which traffic reaches an inspection
chain. A `continue` rule is not a guaranteed passive monitoring rule because of
the error policy above.

## Bounds and kernel requirements

| Resource | Limit |
| --- | --- |
| Pattern | 1–255 bytes, with no embedded NUL |
| Inspected payload | 16,384 bytes per skb; larger payloads are dropped |
| Pattern nesting | 32 levels |
| JIT backtracking match limit | 10,000 |
| Callout budget | 10,000 per inspection, with automatic callouts |
| JIT stack | Fixed 65,536 bytes per possible CPU |
| Payload scratch | N × 16,384 bytes per possible CPU |

Patterns compile during rule creation. JIT compilation must succeed; there is
no interpreter fallback in packet processing. Each possible CPU owns its scratch
buffer, match data, match context, and JIT stack. Packet processing disables bottom
halves and preemption while using these objects and rejects reentry. Executable
memory is never allocated in the packet path. At N=1 there are no
packet-path payload allocations; at N>1 the TCP cache copies payloads with
`GFP_ATOMIC`, and allocation failure drops the packet. Pattern code is immutable;
nftables controls rule lifetime and module references.

The module rejects PREEMPT_RT kernels. The current kpcre JIT allocator requires
x86-64, Kprobes, no kernel IBT/CFI, and permission to resolve its JIT helpers.
Lockdown can prevent JIT initialization; rule creation then fails. These are
inherited engine constraints. Do not disable host protections to run the tests.
Kernel-internal interfaces and kpcre's helper lookup need revalidation for each
kernel/configuration. Runtime testing must use a disposable VM.

## Configurable TCP inspection windows

The module accepts read-only load-time parameters:

| Parameter | Default | Range | Scope |
| --- | --- | --- | --- |
| `window_packets` | 1 | 1–8 | Maximum adjacent TCP payloads searched together; UDP remains per-datagram. |
| `max_flows` | 4096 | 1–65536 | Cached expression/connection pairs across all native regex expressions and namespaces. |
| `idle_seconds` | 30 | 1–3600 | Idle time since the last TCP payload in either direction of a cached connection. |

On a target VM with the rebuilt modules installed:

```sh
modprobe nft_regex window_packets=4
cat /sys/module/nft_regex/parameters/window_packets
```

For persistence, put `options nft_regex window_packets=4` in
`/etc/modprobe.d/kpcre-nft-regex.conf`. It applies on the next module load. Remove
all rules holding the expression before unloading/reloading to change the value.
History is lost on rule replacement/recreation and module reload. Save the module
configuration alongside text/JSON rulesets: N is not a Netlink rule attribute.
Existing native nft command syntax and frontend patches need no changes.
`xt_ids` has its own independent parameters and still defaults to N=2.

For N=4, searches grow as `1`, `1+2`, `1+2+3`, `1+2+3+4`, then slide to
`2+3+4+5`. Inspection starts immediately, before the window is full. Each
expression holds at most N−1 previous TCP payloads per connection/direction.
Conntrack references prevent object reuse while cache entries exist and separate
connections, namespaces, and zones. N=1 retains no TCP history.

| TCP event | Window behavior for N>1 |
| --- | --- |
| Sequence-adjacent payload | Search history plus current; retain the latest N−1 payloads. |
| ACK without payload | Preserve history without refreshing the payload idle timer. |
| Exact retransmission of the last cached payload | Reuse its cached verdict without consuming a slot. |
| Gap, overlap, changed retransmission, or out-of-order arrival | Search current alone and restart that direction. |
| SYN / RST | Clear both directions; SYN may seed a new window, RST is not searched. |
| FIN | Search any payload and close that direction to concatenation; retain exact retransmission verdicts. |
| Idle or dying conntrack | Lookup discards idle entries; a worker discards idle/dying entries every five seconds. |

Only matches consuming bytes in the current payload count. Old-only candidates
are rejected inside PCRE so later alternatives can still match across the
boundary, as with `abc|abcdef`. Lookbehind may use retained bytes. A match such
as `abc(?=def)` ending entirely in history is ignored even when its lookahead
uses current bytes. The newest blocked payload's retransmission verdict is
remembered; older retransmissions and endpoint-specific overlap policies are
not fully reconstructed. Full TCP Fast Open behavior is not provided.

At N>1, patterns compile inside a noncapturing group followed by a final callout.
Patterns containing `(*ACCEPT` or `(?C` are rejected to protect that boundary
check. Some start-only directives fail wrapped compilation, whole-pattern
recursion includes the wrapper, and anchors describe the window rather than the
full stream. Raw-pattern validation rejects attempts to escape the wrapper.
These additional restrictions do not apply to the default N=1 mode.

Use N>1 expressions in filter chains reached from INPUT, FORWARD, or OUTPUT;
other hooks, including indirect jumps from them, are rejected at rule validation.
Use the normal filter priority (0), after conntrack has processed OUTPUT packets.
Every payload needed for a signature must reach the same expression: inspect
before broad established-connection accepts, and do not use a NAT chain that
only processes the initial packet. Missing/untracked TCP state is an inspection
error and drops the packet, including zero-length control packets. UDP does not
require conntrack state for matching even when N>1, although each expression in
that mode acquires a conntrack namespace reference.

For equally sized payloads, increasing N from 2 to 4 doubles maximum search
length and triples retained history. Copying grows with retained bytes; regex
search cost also depends on backtracking and match position. JIT does not remove
these costs. The existing 10,000 callout budget, 10,000 match limit, and 64 KiB
JIT stack remain unchanged; larger windows can hit a limit and drop traffic.
Rejecting history-only candidates also consumes the callout budget, even if
no candidate consumes current bytes. There is no throughput claim.

At N>1, payload-cache storage is bounded by approximately
`max_flows * 2 * (N-1) * 16384`, excluding metadata, conntrack references,
transient buffers, JIT storage, and per-CPU scratch. With default `max_flows`,
N=2/4/8 permit roughly 128/384/896 MiB of cached payloads. Memory is allocated
as traffic arrives. Reduce `max_flows` if increasing N under a fixed memory
budget. Capacity exhaustion drops packets requiring new entries without evicting
an arbitrary active connection. N=1 allocates no cache entries.

Pattern code is immutable. Per-CPU ownership guards and per-bucket locks protect
matching/cache updates, and rule destruction cancels its worker and releases all
payloads/conntrack references before code teardown. The native TCP policy follows
the existing `xt_ids` implementation; its storage and counters are independent.

## Build and install the kernel modules

Use matching kernel headers, GNU make, a compatible C compiler, and a POSIX shell.
For the default 8-bit package:

```sh
make CODE_WIDTH=8 modules
sudo make CODE_WIDTH=8 modules_install
```

This includes `nft_regex.ko` and the existing modules. DKMS also includes
`nft_regex.ko`; its installation hook handles `libxt_ids.so` automatically.
The regex-enabled native `nft` command is built and installed explicitly below.
Use `make clean` before rebuilding after a kernel or library ABI change.

## Build the native nft frontend

On Debian/Ubuntu, the build prerequisites are a C toolchain, make, curl, xz-utils,
patch, pkg-config, bison, flex, libmnl-dev, libgmp-dev, libjansson-dev, libedit-dev,
and libxtables-dev. The build script uses released source tarballs with pinned
SHA-256 checksums and applies the supplied patches. It does not require an
autotools bootstrap.

```sh
make nft_userspace
```

The command reports the generated executable's location. Set `NFT` to that
executable, or to an explicitly installed regex-enabled command:

```sh
NFT=/path/to/regex-enabled/nft
"$NFT" --version
```

The modified libnftables and libnftnl are embedded in the executable. The target
must provide compatible ordinary runtime libraries and modules matching its
kernel. Preserve source patches and upstream license notices when redistributing.

The frontend keeps upstream interactive editline, JSON, and xtables support.
Existing rule grammar is preserved; `regex` remains usable as an ordinary table
or chain name. The new clause requires an inline quoted pattern rather than a
variable or map. Pattern validation and compilation still occur in the kernel.

## Rule management with nft

Exercise rule changes in an isolated VM before deployment. After module
installation, run the following as root and use the regex-enabled command:

```sh
modprobe nft_regex

"$NFT" -f - <<'EOF'
table inet regex_demo {
    chain output {
        type filter hook output priority 0; policy accept;
        meta l4proto { tcp, udp } th dport 49001 regex "(?i)malware" counter drop
    }
}
EOF

"$NFT" -a list table inet regex_demo
```

Use normal nftables actions after the regex clause. `counter drop` counts and
blocks matches; `counter accept` counts and accepts matches. `counter` alone
counts matches and continues evaluation. Empty matches do not count. Inspection
errors still drop independently of the following action.

For a single command, preserve the nft string quotes through the shell:

```sh
"$NFT" 'add rule inet regex_demo output tcp dport 49002 regex "^GET[ ]" counter drop'
```

Inside the pattern quotes, `\\` represents one pattern backslash and `\"`
represents a double quote. Other backslash sequences such as `\d` and `\x00`
are passed to PCRE unchanged. Output escapes backslashes and quotes so saved
rules reproduce the original pattern. For example:

```nft
regex "^hello[0-9]+\\x00world$" counter drop
```

The pattern above matches a NUL byte between the digits and `world`. A single
backslash before `x00` is also accepted on input; listings use the escaped form.

Use handles printed by `-a` to replace or delete rules:

```sh
# Replace 3 with the actual rule handle.
"$NFT" 'replace rule inet regex_demo output handle 3 tcp dport 49001 regex "other" counter drop'
"$NFT" delete rule inet regex_demo output handle 3
```

Save and restore using the patched executable:

```sh
"$NFT" list ruleset > rules.nft
"$NFT" -c -f rules.nft
"$NFT" -f rules.nft
"$NFT" -j list ruleset > rules.json
```

Loading an existing ruleset dump adds its declarations and rules to the current
state; it does not automatically replace that state. Plan an explicit replacement
transaction when restoring over active rules to avoid duplicates. In the
isolated tests, tables are removed before text restoration and the guest ruleset
is cleared before JSON restoration. Do not flush a production ruleset merely to
try this example.

JSON uses `{"regex":{"pattern":"PATTERN"}}` as a rule statement. The JSON
frontend supports both input and output, including escaped strings. Embedded NUL
characters in the pattern text are rejected; use a PCRE byte escape to match a
NUL in packet payloads. Use the patched command to list or restore rulesets that
contain regex expressions; stock nft/libnftnl do not understand this extension.

Remove rules before unloading:

```sh
"$NFT" delete table inet regex_demo
rmmod nft_regex
```

Do not unload the library while another kpcre consumer uses it.

## Optional installation with a mandatory backup

Building and VM testing do not install anything on the host. To replace the
system command on an explicitly selected target machine:

```sh
sudo sh scripts/nft-regex-install-nft.sh "$NFT" /usr/sbin/nft /var/backups/nft-regex
```

The arguments select the new executable, installed command, and backup location.
Choose the regex-enabled executable reported by the build command and retain the
backup location printed by the installer.

Before replacement, the script creates a private timestamped backup directory,
preserves the original file or symlink and its resolved executable, records the
target path and SHA-256 checksums, and verifies that the copied bytes match the
original. It then stages the new binary in the target directory and atomically
replaces the command. Shared libraries and firewall rules are not changed. Keep
the printed backup directory; interrupted installations may leave a backup even
when replacement did not finish.

Restore a completed installation with:

```sh
sudo sh scripts/nft-regex-restore-nft.sh /var/backups/nft-regex/TIMESTAMP-SUFFIX
```

Restoration verifies the backup and installed checksum first. It refuses to
replace a binary changed by a later package update or another administrator.
For an original symlink, it also checks that the original resolved executable
has not changed. It restores the original entry and verifies the restored bytes.
Remove regex rules before returning to a stock command that cannot decode them.
Backups contain the command, not an automatic ruleset snapshot. Distribution
package upgrades can replace the custom command; retain this build and its source
patches for rebuilding and deployment.

## Netlink interface

The expression name is `regex`. Its `NFTA_EXPR_DATA` nests one required attribute:

| ID | Name | Wire representation |
| --- | --- | --- |
| 1 | `NFTA_REGEX_PATTERN` | Nonempty NUL-terminated string; at most 255 pattern bytes |

The kernel independently validates length and termination, rejects embedded
NULs, compiles the pattern, and requires JIT availability. Dumping a rule returns
the original pattern, without internal pointers or compiled code. The kernel
and native command use the same attribute IDs and bounds.

The native nft command batches mutations, checks kernel acknowledgements, and uses
multipart dumps to retrieve counters and handles. Interrupted dumps are reported
as errors. A timeout during a mutation has an uncertain outcome: list the chain
before deciding whether to retry.

## Compatibility and operating limits

Runtime checks covered the unmodified `7.0.0-38-generic` kernel on x86-64,
nftables 1.1.6, libnftnl 1.3.1, and the bundled 8-bit PCRE2 library. Existing
filter/set/map/conntrack/NAT rule output, text/JSON round trips, TCP/UDP counters,
and UDP ACCEPT/DROP delivery were checked. TCP windows were checked at N=1,
2, 3, 4, and 8 for both IPv4 and IPv6.

Coverage is limited to loopback OUTPUT traffic and targeted boundary conditions.
Other kernels, physical interfaces/offloads, sustained load, throughput, genuine
parallel stress, forced allocation failure, and the complete upstream nftables
suite remain unvalidated. Counter-based window checks do not establish TCP DROP
delivery behavior. These results do not imply full TCP reconstruction or
inspection of encrypted plaintext.

## License and references

This project's code is GPL-2.0-only; see [LICENSE](../nft_regex/LICENSE). The upstream
patches follow the licenses of their respective source files. The shared library
tree retains its own copyright and license notices, including those of PCRE2
and SLJIT. Do not remove those notices when packaging dependencies.

- [nf_tables Netlink specification](https://docs.kernel.org/netlink/specs/nftables.html)
- [Netfilter userspace architecture](https://wiki.nftables.org/wiki-nftables/index.php/Building_and_installing_nftables_from_sources)
- [PCRE2 JIT documentation](https://www.pcre.org/current/doc/html/pcre2jit.html)
