# PCRE Linux kernel modules for iptables and nftables

Keywords: Netfilter iptables PCRE REGEX Linux Kernel Module

### PCRE library kernel module (libpcre2-X.ko)

The PCRE library is a set of functions that implement regular expression pattern matching using the same syntax and semantics as Perl 5.
PCRE has its own native API, as well as a set of wrapper functions that correspond to the POSIX regular expression API. 

This is a PCRE2 library ported to linux kernel.
It is a full-fledged PCRE kernel module which supports JIT(Just-in-time) compilation.

Original sources: ftp://ftp.csx.cam.ac.uk/pub/software/programming/pcre

### PCRE text search engine (ts_pcre.ko)

This is a new text search engine based on the PCRE kernel module.

Support for JIT-enabled `ts_pcre.ko`, which had been unavailable on Linux kernel 5.8 and later, has now been restored on compatible kernels. For performance-sensitive workloads, I recommend testing `ts_pcre.ko` with JIT enabled before trying `ts_regex.ko`, as JIT compilation can provide much faster matching. See “JIT on distribution kernels (Linux 5.8+, x86-64)” below for requirements and compatibility limits.

### Getting the source code

To get the source code from the git repository

```
git clone https://github.com/smcho-kr/kpcre.git
```

### Installing

To install the modules follow these steps, always from the modules package root (i.e. where this file is located)

For the default 8-bit build, install a C toolchain, matching kernel headers,
xtables development headers, and pkg-config first. On Debian/Ubuntu:

```sh
sudo apt-get install build-essential linux-headers-$(uname -r) libxtables-dev pkg-config
```

To compile the kernel modules and the IDS userspace extension, type:

```
make modules
```

Then, as root type:

```
make modules_install
```

This installs all six kernel modules, including `xt_ids.ko` and `nft_regex.ko`, and automatically
installs `libxt_ids.so` into the xtables extension directory discovered through
pkg-config. Set `XTABLES_LIBDIR=/absolute/path` if discovery is unavailable.
Build/install failures stop the root Makefile immediately. Module loading and
firewall rules are separate; validate execution in a disposable VM first.

DKMS also installs the userspace extension automatically through a `PRE_INSTALL`
hook. Keep xtables development headers and pkg-config available for kernel
updates. `make kernel_modules` remains available for kernel-only builds.

For more detailed instructions on how to build and install the kernel modules, refer to [the installation guide](https://github.com/smcho-kr/kpcre/wiki/Step-by-step-installation-guide).

### Usage

Once you have installed both modules ("libpcre2-X.ko" and "ts_pcre.ko")
you should type (as root):

```
modprobe ts_pcre
```

If the module has been successfully loaded you shouldn't see any message.
After loading the kernel module you can use iptables to add a rule.

For example, on an IPv4 gateway, block clients from querying an external DNS resolver for `www.blocked.com` over ordinary DNS (as root). Replace `br-lan` with the interface on which client DNS traffic enters the gateway:

```sh
LAN_IF=br-lan
iptables -I FORWARD 1 -i "$LAN_IF" -p udp --dport 53 \
  -m string --algo pcre --string '/\x03www\x07blocked\x03com\x00/i' \
  -j DROP
iptables -I FORWARD 1 -i "$LAN_IF" -p tcp --dport 53 \
  -m string --algo pcre --string '/\x03www\x07blocked\x03com\x00/i' \
  -j DROP
```

DNS does **not** carry the dotted name `www.blocked.com` as one plaintext string. In the uncompressed [DNS wire format](https://www.rfc-editor.org/rfc/rfc1035#section-3.1), each label is preceded by its one-byte length, and a zero-length root label terminates the name:

```text
\x03www\x07blocked\x03com\x00
```

Here `\x03` means a label length of 3, `\x07` means 7, and the final `\x00` terminates the name. Do not replace every dot with one fixed character: the length byte depends on the following label, and the first label needs one too. Single quotes preserve the textual `\xNN` escapes for PCRE to interpret as bytes; `i` makes the label comparison case-insensitive. Both rules are needed to cover ordinary DNS over UDP and TCP, regardless of whether the question asks for an A or AAAA record.

These are packet-byte signatures, not a DNS parser: they also match a name such as `x.www.blocked.com`, whose encoded form contains the same suffix, or the same bytes elsewhere in the packet. Compressed names and matches split across packets or text-search blocks may evade detection. DROP causes a timeout rather than returning NXDOMAIN. For strict hostname policy, use a filtering DNS resolver.

`FORWARD` applies only to routed traffic. Queries sent to a DNS resolver running on the gateway traverse `INPUT` instead; that resolver's own outbound queries traverse `OUTPUT`. Review rule ordering before insertion: inspect before broad ACCEPT rules, but retain required cheap rejection rules ahead of inspection. Add corresponding IPv6 rules where needed. DNS over HTTPS/TLS/QUIC, cached answers, and direct-IP connections are not blocked by this example; it is not a complete website-access policy.

For practical filtering and alerting rules using `--algo pcre`, see [Practical iptables Examples with ts_pcre](https://github.com/smcho-kr/kpcre/wiki/Practical-iptables-Examples-with-ts_pcre). The guide includes nine common use cases, lightweight Snort-style IDS alerting, safe rule placement, testing, and important inspection limitations.

In case you want to stop using the ts_pcre kernel module, first remove every iptables rule for ts_pcre and then type (as root):

```
modprobe -r ts_pcre
```

There is also a REGEX text search engine. (ts_regex.ko)

### Configurable TCP packet-window matching (`-m ids`)

The separate `xt_ids.ko` match inspects up to N adjacent TCP payloads per connection
and direction. The module parameter `window_packets` accepts 1–8 and defaults to
2 (`1+2`, then `2+3`). Set `options xt_ids window_packets=4` in a modprobe
configuration file to inspect `1+2+3+4`, then `2+3+4+5` after the next module load.
Already loaded modules require removing their rules and reloading to change N.
Existing `-m string --algo pcre` commands retain
their behavior. The new match requires the 8-bit PCRE library, JIT, conntrack,
and the `libxt_ids.so` userspace extension, built with `make -C xt_ids userspace`
after installing the distribution's xtables development headers and pkg-config.

Example for an isolated test VM, after installing both components:

```sh
iptables-legacy -A FORWARD -p tcp --dport 8080 \
  -m ids --regex '(?i)blocked-pattern' -j DROP
```

Use raw PCRE patterns without `/.../` delimiters. This is bounded inspection,
not complete TCP reassembly: gaps and overlaps restart the window, and patterns
requiring more than N payloads can be missed. Larger N increases copying, search
work, and retained memory; JIT execution limits remain unchanged.
**Inspection errors and resource-limit
failures drop the packet, even with a LOG target.** The default payload limit
is 16 KiB per observed skb; GRO/GSO can produce larger skbs.

See the [IDS module guide](docs/ids-module-guide.md) or
[GitHub Wiki guide](https://github.com/smcho-kr/kpcre/wiki/IDS-Module-Guide)
for setup and usage. [Configurable TCP Payload Windows with xt_ids](docs/two-packet-ids.md)
records implementation details, state transitions, resource limits, and isolated VM tests.

### Native nftables payload regex (`nft_regex.ko`)

The native `regex "PATTERN"` expression inspects TCP/UDP payloads in nftables
`ip`, `ip6`, and `inet` tables.
The default 8-bit module build and DKMS include `nft_regex.ko`.

The native frontend requires the supplied patches for nftables 1.1.6 and
libnftnl 1.3.1. Build it explicitly with `make nft_userspace`; run its codec
check with `make nft_userspace_check` and backup/restore checks with
`make nft_check`. The build reports the generated executable's location.
Normal builds and DKMS do not replace the system `nft` command or its libraries.

| Interface | Inspection scope | Frontend |
| --- | --- | --- |
| `-m string --algo pcre` / `regex` | Text-search byte blocks | Existing iptables string extension |
| `-m ids --regex` | Up to N adjacent TCP payloads per connection/direction | `libxt_ids.so` |
| nftables `regex "PATTERN"` | TCP window of 1–8 payloads (default 1); UDP per payload | Patched native `nft` |

Set `options nft_regex window_packets=4` in a modprobe configuration file to
enable a native TCP sliding window after the next module load. Native parameters
and state are independent from `xt_ids`; UDP remains per-datagram. This is bounded
inspection and does not provide complete TCP reassembly.
Inspection errors drop packets independently of the following nftables verdict.
See the [native nftables guide](docs/nftables-regex.md) or
[GitHub Wiki](https://github.com/smcho-kr/kpcre/wiki/Native-nftables-Regex) for
requirements, backup-protected installation, examples, and limits. The
[design notes](docs/nftables-regex-design.md) explain matching and resource bounds.

### JIT on distribution kernels (Linux 5.8+, x86-64)

See [Restoring PCRE JIT Execution on Distribution Kernels](docs/kernel-jit-executable-memory.md)
for the root cause, implementation details, validation results, and compatibility limits.

The kernel JIT allocator uses separate pages for each generated function. Pages
start writable/non-executable and become read-only/executable after generation.
Allocation requires sleepable process context; matching remains usable in the
text-search packet path. Freeing is deferred through the kernel's own worker.
Each function also uses one writable metadata page, increasing memory usage.

Starting with Linux kernel 5.8, `__vmalloc()` no longer accepts the third (page-protection) argument, so the original allocator can no longer request `PAGE_KERNEL_EXEC` for JIT code. This port
resolves `set_memory_ro`, `set_memory_x`, `find_vm_area`, and `vfree_atomic` using
temporary disabled Kprobes during library initialization. No probe remains
installed, and no symbol lookup occurs while matching. This is an internal-API
compatibility workaround, not a stable kernel interface: revalidate after kernel
updates.

This path requires `CONFIG_X86_64=y`, `CONFIG_KPROBES=y`, permission to use Kprobes
under the kernel's lockdown policy, and IBT/CFI disabled in the kernel configuration.
The bundled SLJIT predates IBT/CFI support. Unsupported configurations or missing
helpers reject JIT compilation; `ts_regex` and non-JIT matching remain available.
Module signing requirements still apply. Kernels before 5.8 retain the old allocator.
Rebuild all modules from a clean tree (`make clean` followed by `make modules`)
after updating: the match-data layout now uses a flexible array, which also
avoids UBSAN bounds warnings and changes module symbol version checksums.

Runtime checks on `7.0.0-38-generic` (x86-64) covered three complete module
load/unload cycles and 96 test iterations without UBSAN reports or kernel faults.
This does not establish compatibility with other kernels or measure throughput
under production traffic.
