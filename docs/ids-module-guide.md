# IDS Module Guide: TCP Pattern Matching Across Packets

`xt_ids.ko` provides the iptables match `-m ids --regex PATTERN`. It searches a
sliding window of consecutive TCP payloads using the kernel PCRE2 JIT library.
Use it for bounded byte signatures split across TCP packets. Each rule tracks
each connection and traffic direction independently.

**Inspection errors drop the packet, including when the rule target is LOG.**
Oversized payloads, missing conntrack state, exhausted flow capacity, allocation
failures, and regex execution limits cause this behavior. Validate signatures,
limits, and rule ordering in a disposable VM before deployment.

## How the window works

The module parameter `window_packets` selects N, from 1 through 8. Its default
is 2. Inspection starts with the first payload and grows until the window is
full; each subsequent payload replaces the oldest one.

For N=4:

```text
Arrival 1:  1
Arrival 2:  1 + 2
Arrival 3:  1 + 2 + 3
Arrival 4:  1 + 2 + 3 + 4
Arrival 5:      2 + 3 + 4 + 5
```

Only sequence-contiguous payloads are joined. ACK-only packets preserve the
window, and exact retransmissions of the cached last payload reuse its verdict
without advancing it. Gaps, overlaps, changed retransmissions, or out-of-order
arrivals restart inspection at the current payload. Connections and opposite
directions never share payload history. Idle state expires automatically.

N counts payload-bearing skbs observed at the inspection hook. GRO/GSO can
change these boundaries, so N does not guarantee a particular number of wire
packets. The module does not perform complete TCP reassembly or decrypt traffic.

## Components and requirements

| Component | Purpose |
| --- | --- |
| `libc.ko`, `libpcre2-8.ko` | Kernel compatibility functions and 8-bit PCRE2 with JIT. |
| `xt_ids.ko` | Connection-aware kernel match and payload history. |
| `libxt_ids.so` | Userspace extension that parses `-m ids --regex`. |

Use matching kernel headers, a C toolchain, xtables development headers, and
pkg-config (`libxtables-dev` and `pkg-config` on Debian/Ubuntu). The tested backend
is iptables-legacy/ip6tables-legacy 1.8.11 on `7.0.0-38-generic`, x86-64.
Conntrack and IPv4/IPv6 xtables filter support are required. JIT is mandatory;
unsupported JIT configurations reject rule insertion. Review the
[kernel JIT requirements](kernel-jit-executable-memory.md) for Kprobes,
lockdown, IBT/CFI, and module signing restrictions.

`ts_pcre.ko` and `ts_regex.ko` remain separate text-search engines. Their existing
`-m string` commands keep their behavior; they do not enable the IDS window.

## Build and install

These commands stop on a submodule
failure and do not install or load modules:

```sh
make CODE_WIDTH=8 modules
```

Pass `KERNEL_DIR=/path/to/matching/kernel/build` to the root make command when
targeting another kernel. Run `make clean` before rebuilding after kernel or library ABI
changes. At `CODE_WIDTH=8`, the root build includes all six kernel modules and
`libxt_ids.so`. Root `modules_install` installs the plugin before installing the
kernel modules, and stops on failures. No separate userspace command is required.
`make kernel_modules` is available when only kernel artifacts are needed.

First install and execute **inside a disposable VM**:

```sh
sudo make modules_install
sudo modprobe xt_ids window_packets=4
cat /sys/module/xt_ids/parameters/window_packets
```

If plugin directory discovery fails, provide the directory used by the intended
iptables binary, for example
`sudo make modules_install XTABLES_LIBDIR=/usr/lib/x86_64-linux-gnu/xtables`
on the tested distribution. Match the plugin's libxtables ABI to that binary.

## Automatic installation with DKMS

Install DKMS, matching kernel headers, a C toolchain, xtables development headers,
and pkg-config before registering the source. For a fresh registration with the
source at `/usr/src/kpcre-1.0.0`:

```sh
sudo dkms add -m kpcre -v 1.0.0
sudo dkms build -m kpcre -v 1.0.0
sudo dkms install -m kpcre -v 1.0.0
```

DKMS builds the six kernel modules with `make kernel_modules`, including
`nft_regex.ko`. The [native nft frontend](nftables-regex.md) is built/deployed
separately and is never replaced by this hook. Its executable
`PRE_INSTALL` hook runs `make -B CODE_WIDTH=8 userspace_install` from the registered
source tree, building and installing `libxt_ids.so` automatically. The hook is
also used during kernel-update autoinstall. It always refreshes the plugin against
the current libxtables headers, even if an older `.so` already exists. Normally,
a hook failure aborts DKMS
installation before kernel modules are copied; do not use `--force` to bypass it.
Keep the source, compiler, headers, and pkg-config available for future updates.

The plugin is shared across kernels. It is intentionally retained when removing
one kernel's DKMS modules, since other kernels may still need it. An installation
failure after the hook does not roll back an already installed plugin. Loading
`xt_ids`, setting module parameters, and installing firewall rules remain explicit
administrative steps. See the [complete DKMS installation guide](https://github.com/smcho-kr/kpcre/wiki/Step-by-step-installation-guide).

## Configure the inspection window

All parameters are read-only after loading and apply across all IDS rules and
network namespaces using the module:

| Parameter | Default | Range | Meaning |
| --- | --- | --- | --- |
| `window_packets` | 2 | 1–8 | Maximum payloads in a search window. |
| `payload_limit` | 16384 | 256–65535 | Maximum bytes in one observed TCP payload. |
| `max_flows` | 4096 | 1–65536 | Maximum cached rule/connection entries. |
| `idle_seconds` | 30 | 1–3600 | Idle expiry since the last payload in either direction. |

For persistent load settings, create `/etc/modprobe.d/kpcre-ids.conf` with:

```conf
options xt_ids window_packets=4
```

This takes effect on the next module load. To change a loaded module, remove
every IPv4/IPv6 rule referencing `ids`, unload `xt_ids`, reload it with the new
parameters, and restore the intended rules. Reloading clears history.
`iptables-save` stores rules, so preserve module configuration separately.

N=1 searches only the current payload and retains the last payload for
retransmission verdicts. For similarly sized payloads, increasing N from 2 to 4
doubles the maximum subject length and triples retained payload history.
Search time also depends on regex structure, match position, and backtracking;
JIT does not guarantee linear or constant execution time.

At default payload and flow limits, the payload-cache ceilings for N=2, 4, and 8
are approximately 128, 384, and 896 MiB, plus metadata, conntrack references,
transient buffers, per-CPU scratch space, and JIT storage. Reduce `max_flows`
when increasing N if the memory budget is unchanged. Regex execution limits
remain fixed; increasing N can make a signature hit a limit and drop traffic.

## Patterns and example rules

Patterns contain 1–255 bytes and use raw PCRE2 syntax without `/.../` delimiters.
Use inline options such as `(?i)` for case-insensitive matching and `\x00` for a
NUL byte. UTF mode, explicit callouts `(?C...)`, and `(*ACCEPT...)` are rejected.
Some start-only directives fail wrapped compilation; anchors refer to the current
window, not the entire connection. Empty matches are ignored. A reported match
must consume bytes in the current payload; lookahead reaching into it alone
does not qualify. Negation of `--regex` is unsupported.

For an isolated VM with a routed plaintext TCP service on port 8080:

```sh
iptables-legacy -A FORWARD -p tcp --dport 8080 \
  -m ids --regex '(?i)blocked-pattern' -j DROP
ip6tables-legacy -A FORWARD -p tcp --dport 8080 \
  -m ids --regex '(?i)blocked-pattern' -j DROP
```

Choose the filter path containing the traffic: INPUT for a local service,
OUTPUT for locally generated traffic, or FORWARD for routed traffic. Every
payload needed for a signature must reach the same IDS rule. Place inspection
before broad ACCEPT rules, including established-connection accepts, while
retaining required cheap rejection rules ahead of it. Restrict interfaces,
addresses, and ports to the traffic actually intended for inspection.

A LOG target can report a match, but inspection failures still drop packets.
Rate-limit an alert after inspection; a limiting match before IDS skips payload
history updates. The first bytes of a boundary signature may already have been
forwarded when later bytes trigger detection. A DROP target acts on the current
packet and does not retract earlier data.

## Validation and limits

Kernel tests cover N=1 through 8, retransmissions, gaps, sequence wraparound,
non-linear skb data, isolation, full-size windows, eviction, limits, and cleanup.
The isolated VM traffic test covered N=1, 2, 3, 4, and 8 with IPv4 and IPv6 over
three cycles: 90 actual TCP sessions. For N=4, separate payloads `a` through `i`
matched `abcd|bcde` exactly twice, while `abcde` matched zero times. Corresponding
N-byte and N+1-byte patterns were checked for every tested window size.

The traffic tests used guest loopback OUTPUT and RETURN counters. Physical
NICs, FORWARD traffic, DROP delivery, throughput, sustained load, nftables
compatibility, and other kernel configurations remain unvalidated. The complete
VM log contained no UBSAN, BUG, WARNING stack diagnostic, or panic.

For matching semantics, state transitions, and resource bounds, see
[Configurable TCP Payload Windows](two-packet-ids.md).
