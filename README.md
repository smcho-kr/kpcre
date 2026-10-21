# PCRE linux kernel module &amp; PCRE/REGEX text search engine

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

To compile the modules first type:

```
make modules
```

Then, as root type:

```
make modules_install
```

That would install the pcre & ts_pcre modules for the given Linux kernel.

For more detailed instructions on how to build and install the kernel modules, refer to [the installation guide](https://github.com/xnsystems/kpcre/wiki/Step-by-step-installation-guide).

### Usage

Once you have installed both modules ("libpcre2-X.ko" and "ts_pcre.ko")
you should type (as root):

```
modprobe ts_pcre
```

If the module has been successfully loaded you shouldn't see any message.
After loading the kernel module you can use iptables to add a rule.

For example, block plaintext HTTP GET requests for the root-level `.env` file, which may contain application secrets (as root):

```sh
iptables -I INPUT 1 -p tcp --dport 80 \
  -m string --algo pcre --string '/GET[ \t]+\/\.env(?:[? \t])/i' \
  -j DROP
```

This matches requests such as `GET /.env HTTP/1.1` and `GET /.env?download=1 HTTP/1.1`. The `i` modifier makes matching case-insensitive. The rule is inserted before existing ACCEPT rules so they do not bypass inspection; review the ordering of your existing firewall first.

This is a defense-in-depth example, not a replacement for web-server access controls. It cannot inspect HTTPS or match a request split across packets or text-search blocks.

For practical filtering and alerting rules using `--algo pcre`, see [Practical iptables Examples with ts_pcre](https://github.com/smcho-kr/kpcre/wiki/Practical-iptables-Examples-with-ts_pcre). The guide includes nine common use cases, lightweight Snort-style IDS alerting, safe rule placement, testing, and important inspection limitations.

In case you want to stop using the ts_pcre kernel module, first remove every iptables rule for ts_pcre and then type (as root):

```
modprobe -r ts_pcre
```

There is also a REGEX text search engine. (ts_regex.ko)

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

Run the allocator's host tests with `make -C tests check` on x86-64 Linux. They use
simulated kernel APIs and real `mprotect` checks; they do not test kernel loading.

For integration testing, build the modules, then run `make -C tests clean`
and `make -C tests modules`.
In a disposable VM running the matching kernel, load:

```sh
insmod libc/libc.ko
insmod pcre2/libpcre2-8.ko
insmod ts_pcre/ts_pcre.ko jit=1
insmod ts_regex/ts_regex.ko
insmod tests/kpcre_jit_test.ko
dmesg | tail -30
```

The test calls `pcre2_jit_match` directly, checks partial and nonmatching inputs,
and exercises both text-search engines across 32 allocate/free cycles. Expect
`kpcre_jit_test: PASS`. Remove the test module and text-search modules before
unloading the library; remove any rules using those engines first.

Validated on `7.0.0-38-generic` (x86-64) in a diskless QEMU guest: three full
module load/unload cycles and 96 test iterations passed without UBSAN warnings
or kernel faults. This does not establish compatibility with other kernel
configurations or measure throughput under real packet traffic.
