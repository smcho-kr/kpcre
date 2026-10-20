# Restoring PCRE JIT Execution on Distribution Kernels

Recorded: 2026-10-20. Validated kernel: `7.0.0-38-generic`, x86-64.

## Outcome and scope

The PCRE JIT path now generates and executes code on the tested, unchanged
distribution kernel. The implementation allocates writable, non-executable
memory, generates the function, and changes its code pages to read-only and
executable before publishing the function pointer.

This resolves the executable-memory problem in `ts_pcre.ko` without rebuilding
the distribution kernel. It relies on internal kernel helpers resolved through
Kprobes, so it is a compatibility workaround with explicit configuration limits.
Selection of this path on Linux 5.8 and later does **not** establish support for
every kernel in that range. Runtime validation covered one kernel configuration
in an isolated VM; no project module was loaded into the host kernel.

## Problem and root cause

The original kernel allocator in
[`sljitExecAllocator.c`](../pcre2/sljit/sljitExecAllocator.c) used:

```c
__vmalloc(size, GFP_ATOMIC | __GFP_HIGHMEM, PAGE_KERNEL_EXEC);
```

For kernels starting at 5.8, the existing compatibility branch dropped the third
argument so that the source would compile:

```c
__vmalloc(size, GFP_ATOMIC | __GFP_HIGHMEM);
```

That change preserved compilation but lost executable permissions. The two-argument
API allocates with `PAGE_KERNEL`, which is non-executable on the target x86-64
kernel. Writing valid machine code into those pages does not make execution
permitted. Calling the resulting JIT function can cause an instruction-fetch
fault in kernel context. The upstream implementation confirms this allocation
path. [Linux 5.8 vmalloc source](https://raw.githubusercontent.com/torvalds/linux/v5.8/mm/vmalloc.c)

This explains why `ts_regex.ko`, which does not depend on this JIT execution
path, remained usable while `ts_pcre.ko` with JIT enabled did not. The reported
performance advantage of JIT motivated the fix; this work did not measure its
throughput advantage.

### Why a different allocation call was insufficient

| Candidate | Reason it was not used directly |
| --- | --- |
| Two-argument `__vmalloc()` | Produces ordinary data memory without executable permissions. |
| `__vmalloc_node_range()` | Retains a protection argument, but is not exported to external modules in the inspected kernels. |
| `vmap(..., PAGE_KERNEL_EXEC)` | The inspected implementation applies `pgprot_nx(prot)`, preventing this from being an executable mapping shortcut on x86. |
| `execmem_alloc()` | The newer executable-memory subsystem is not an exported module interface in the tested kernel. |
| Rebuilding the kernel to export helpers | Conflicts with the requirement to retain the distribution kernel. |

The export checks used the target headers' `Module.symvers`; the implementation
checks used upstream
[vmalloc](https://raw.githubusercontent.com/torvalds/linux/v7.0/mm/vmalloc.c) and
[execmem](https://raw.githubusercontent.com/torvalds/linux/v7.0/mm/execmem.c)
sources. Vendor kernels can differ and must be checked separately.

## Implementation

### Initialization and helper resolution

[`pcre2_internal.h`](../pcre2/pcre2_internal.h) selects `KPCRE_KERNEL_EXEC` for
kernel builds targeting Linux 5.8 or later.
[`sljitLir.c`](../pcre2/sljit/sljitLir.c) then includes the new
[`sljitKernelExecAllocator.c`](../pcre2/sljit/sljitKernelExecAllocator.c).
The earlier allocator remains selected for older kernels.

During library initialization, [`main.c`](../pcre2/main.c) calls
`kpcre_jit_exec_init()`. Initialization requires:

- `CONFIG_X86_64=y` and `CONFIG_KPROBES=y`.
- `CONFIG_X86_KERNEL_IBT`, `CONFIG_CFI_CLANG`, and `CONFIG_CFI` disabled.
- Permission from `security_locked_down(LOCKDOWN_KPROBES)`.
- Successful resolution of all four helpers below.

| Helper | Purpose |
| --- | --- |
| `set_memory_ro` | Remove write permission from completed code pages. |
| `set_memory_x` | Enable execution after write permission has been removed. |
| `find_vm_area` | Find the allocation's vmalloc metadata and mark its cleanup requirements. |
| `vfree_atomic` | Defer release to the kernel's own worker. |

Each lookup registers a temporary Kprobe with `symbol_name` and
`KPROBE_FLAG_DISABLED`, saves its resolved address, and immediately unregisters
it. Kprobes supports symbol-name resolution and disabled registration.
[Kprobes documentation](https://docs.kernel.org/trace/kprobes.html)

No probe remains registered, and matching performs no symbol lookup. Helper
pointers and readiness state use `__ro_after_init`. The bundled SLJIT predates
the required IBT/CFI support, so those configurations are rejected. The change
does not disable kernel protections or bypass module-signing requirements.

### Allocation and ownership

Each generated function receives its own `vmalloc()` allocation:

```text
Allocation base
    |
    +-- One metadata page: RW / NX
    |      Stores the number of code pages
    |
    +-- Page-aligned code region: RW / NX, then RO / X
           Returned to SLJIT for code generation
```

The code region is rounded up to whole pages and initially filled with `0xcc`
(x86 breakpoint instructions). Allocation rejects zero size, arithmetic overflow,
page counts exceeding `INT_MAX`, atomic context, and disabled interrupts.
Compilation therefore requires sleepable process context. Matching uses the
already compiled function and does not allocate executable pages.

The old allocator shared 64 KiB chunks between generated functions and updated
allocator metadata inside those chunks. Applying read-only permissions to a
shared page could interfere with another function's generation or reclamation.
Separate allocations remove that coupling and avoid performing sleepable
allocation or permission changes under the old allocator's spinlock.

Ownership is per generated function, not necessarily per regex: compiling
complete and partial matching modes can create multiple allocations. Each has
one metadata page plus page-rounded code storage. This increases memory usage,
especially for many small patterns; no shared executable-memory pool is retained.

### Finalization and publication

In [`pcre2_jit_compile.c`](../pcre2/pcre2_jit_compile.c), permission changes occur
after code generation and label-address updates, before the function is stored
in the compiled regex's executable-function table:

```text
RW / NX -- generate code --> RW / NX
        -- set_memory_ro --> RO / NX
        -- set_memory_x  --> RO / X
        -- publish function pointer --> matching may execute
```

Removing write permission first avoids a writable-and-executable phase for the
code mapping. The x86 helpers perform the underlying page-attribute changes.
[Linux x86 page-permission implementation](https://raw.githubusercontent.com/torvalds/linux/v7.0/arch/x86/mm/pat/set_memory.c)

If either helper fails, the generated allocation is released and compilation
returns an error. A function with incomplete permission changes is never
published. No code-patching interface is added after finalization.

### Release and permission cleanup

Allocation sets `VM_FLUSH_RESET_PERMS` on the associated `vm_struct`.
`sljit_free_exec()` passes the original allocation base to `vfree_atomic()`.
That helper writes a deferred-free list node at the allocation's beginning,
which is why the metadata page must remain writable. The flag requests mapping
flushes and direct-map permission restoration during release.
[Linux vmalloc cleanup implementation](https://raw.githubusercontent.com/torvalds/linux/v7.0/mm/vmalloc.c)

The queued worker belongs to the kernel rather than this module, avoiding a
module-owned callback that could outlive library unloading. Freeing one function
does not change another function's code permissions. Callers must still ensure
that no matching operation is using a function when it is destroyed; this change
does not add concurrent object-lifetime management. NMI use is unsupported.

### Failure behavior

| Condition | Result |
| --- | --- |
| Unsupported configuration, lockdown denial, or unavailable helper | JIT remains unavailable; compilation requiring JIT returns `PCRE2_ERROR_JIT_BADOPTION`. |
| Invalid allocation size/context or allocation failure | Allocation returns `NULL`; the compiler follows its existing memory-error path. |
| Permission finalization failure | Code is discarded; compilation returns `PCRE2_ERROR_NOMEMORY`, with a kernel diagnostic identifying permission failure. |
| JIT compilation failure in `ts_pcre` | Pattern initialization fails and logs `ts_pcre: JIT compilation failed (...)`. |

Library initialization can still succeed when JIT is unavailable, preserving
interpreter functionality. Existing explicit no-JIT requests retain their
behavior. A failed JIT compilation is not silently treated as successful JIT
execution.

## Related correctness fixes

### Error-path use after free

Two JIT compilation cleanup paths accessed `compiler->allocator_data` after
`sljit_free_compiler(compiler)`. They now use the previously saved
`allocator_data`. This also makes the newly introduced permission-failure cleanup
safe from that stale compiler access.

### UBSAN bounds reports

The first VM run exercised JIT successfully but reported
`UBSAN: array-index-out-of-bounds` in `pcre2_match.c` and `pcre2_substring.c`.
The internal match-data structure declared its variable-length offset vector as
`ovector[1]`. Accesses beyond that declared element triggered bounds checking.

[`pcre2_intmodedep.h`](../pcre2/pcre2_intmodedep.h) now declares `ovector[]` as a
flexible array. The existing allocator in
[`pcre2_match_data.c`](../pcre2/pcre2_match_data.c) already reserves storage for
`3 * oveccount` offset elements after the structure. This corrects the declaration
to describe that storage instead of suppressing UBSAN diagnostics.

### Module version consistency

The structure change also changed PCRE2 symbol version checksums. An incremental
build left dependent module artifacts inconsistent and produced
`disagrees about version of symbol` errors. A clean rebuild of the library,
both text-search modules, and the test module resolved the mismatch. Do not mix
old dependent modules with the rebuilt library or force version checks off.

## Validation performed

### Compilation

All five modules built successfully against the matching
`7.0.0-38-generic` headers: `libc.ko`, `libpcre2-8.ko`, `ts_pcre.ko`,
`ts_regex.ko`, and `kpcre_jit_test.ko`. The final build used a clean temporary
source copy.

This was not a warning-free build. Existing fallthrough and missing-prototype
warnings remained. Kbuild reported compiler-name and pahole differences, and
skipped BTF generation because `vmlinux` was unavailable. The compiler and kernel
build compiler both reported GCC 15.2.0.

### Allocator tests in userspace

[`kernel_exec_test.c`](../tests/kernel_exec_test.c) includes the production
allocator with simulated kernel APIs and real POSIX `mmap()`/`mprotect()` mappings.
The tests passed for:

- Execution faulting before finalization, successful execution afterward, and
  writes faulting after finalization.
- Independent allocations: freeing the first leaves the second executable.
- Invalid sizes, rejected contexts, allocation and metadata-lookup failures.
- Missing helpers, lockdown denial, and balanced probe registration/unregistration.
- Permission-helper failures, including errors reported after mappings changed.
- Configuration rejection with IBT enabled, CFI enabled, or Kprobes disabled.

These tests validate allocator logic and userspace page protections. They do not
establish actual kernel helper resolution, deferred-worker behavior, or kernel
cache/TLB correctness. Their successful runs preceded the VM validation.

### Isolated kernel integration tests

The VM booted a copy of the distribution's unmodified kernel image with a small
temporary initramfs containing BusyBox and the freshly built modules.

| Setting | Tested value |
| --- | --- |
| Kernel / architecture | `7.0.0-38-generic` / x86-64 |
| Emulation | QEMU TCG, one emulation thread, two virtual CPUs |
| Guest memory | 512 MiB |
| Process permissions | UID/GID 65534, no supplementary groups, nice level 19 |
| Isolation | No disks, network devices, shared directories, or device passthrough |
| QEMU restrictions | Seccomp sandbox; privilege elevation, process spawning, and resource-control operations denied |
| Limits | 180 seconds CPU time; 240 seconds runner timeout; core dumps disabled |
| Diagnostics | UBSAN bounds checks and strict kernel/module RWX enabled; IBT/CFI disabled |
| Failure handling | `oops=panic`, `panic_on_warn=1`, `panic=1`, and no automatic reboot |

QEMU and its dependencies were extracted into a temporary directory without
installing packages. The guest had no access to host storage through a shared
mount or block device. This isolates a test-module kernel crash to the guest;
QEMU still consumes host CPU and memory and is subject to ordinary virtualization
risks. The setup is not a claim of literally zero host impact.

[`kpcre_jit_test.c`](../tests/kpcre_jit_test.c) performs 32 iterations per load:

1. Compile complete and hard-partial JIT functions and confirm nonzero JIT size.
2. Call `pcre2_jit_match()` directly to ensure interpreter fallback cannot hide a
   failed JIT implementation.
3. Check captures, offsets, nonmatching input, partial matching, and an explicit
   interpreter call using `PCRE2_NO_JIT`.
4. Free one compiled regex and execute another independent regex.
5. Exercise matching and nonmatching inputs through both `pcre` and `regex`
   text-search engines, then release their configurations.

Three complete module load/unload cycles passed, totaling **96 iterations**.
The final serial log contained:

```text
KPCRE_VM_CYCLE=1
[    4.615202] kpcre_jit_test: PASS (JIT, partial match, free/reuse, pcre/regex engines)
KPCRE_VM_CYCLE=2
[    6.393318] kpcre_jit_test: PASS (JIT, partial match, free/reuse, pcre/regex engines)
KPCRE_VM_CYCLE=3
[    8.138494] kpcre_jit_test: PASS (JIT, partial match, free/reuse, pcre/regex engines)
KPCRE_VM_TEST_PASSED
```

QEMU exited successfully. The final log had no UBSAN report, `BUG`, `WARNING`
stack diagnostic, or kernel panic. It did contain the expected out-of-tree and
unsigned-module taint messages. The guest did not enforce signed-module loading;
this does not validate Secure Boot or lockdown-enabled deployment.

The original local evidence was retained at
`/tmp/kpcre-qemu-ixk7u52_/vm-final.log`, with build logs under
`/tmp/kpcre-jit-verified-hkcbtvgl/`. These temporary paths may be removed; the
results and excerpt above preserve the relevant record in the repository.

## Reproducing the checks

### Build all modules together

From a disposable source copy, use headers matching the intended guest kernel.
The following builds only; it does not install or load modules. Separate subdirectory
invocations stop on failure instead of relying on the root Makefile's shell loops,
which can mask an earlier submodule error.

```sh
(
    set -eu
    kpcre_kernel_dir=/lib/modules/7.0.0-38-generic/build
    for module in libc pcre2 ts_pcre ts_regex tests; do
        (cd "$module" && make KERNEL_DIR="$kpcre_kernel_dir" CODE_WIDTH=8 clean)
    done
    for module in libc pcre2 ts_pcre ts_regex tests; do
        (cd "$module" && make KERNEL_DIR="$kpcre_kernel_dir" CODE_WIDTH=8 modules)
    done
)
```

Run the userspace allocator tests on x86-64 Linux with 4 KiB pages:

```sh
make -C tests check
```

### Execute integration tests only inside a disposable VM

Copy the matching build into the isolated guest. Run the following as root
**inside that guest**, from the copied repository root:

```sh
set -e
for cycle in 1 2 3; do
    insmod libc/libc.ko
    insmod pcre2/libpcre2-8.ko
    insmod ts_pcre/ts_pcre.ko jit=1
    insmod ts_regex/ts_regex.ko
    insmod tests/kpcre_jit_test.ko
    rmmod kpcre_jit_test
    rmmod ts_regex
    rmmod ts_pcre
    rmmod libpcre2_8
    rmmod libc
    sleep 1
done
dmesg
```

Require three `kpcre_jit_test: PASS` messages, successful unloads, and no fault or
sanitizer diagnostics in the complete log. A successful `insmod` alone is
insufficient. This sequence assumes a fresh guest without firewall rules or
other users holding text-search configurations. The temporary VM provisioning
runner used for this validation is not part of the repository.

## Remaining limits and kernel updates

- Runtime evidence covers only the stated kernel and configuration. Older
  kernels, other architectures, other PCRE2 code widths, and IBT/CFI-enabled
  kernels were not validated. The pre-5.8 path was preserved but not retested.
- Kprobe resolution and the resolved helper contracts are internal interfaces.
  Kernel updates may change their names, availability, signatures, or behavior.
- The tests do not measure real Netfilter traffic throughput, long-running load,
  concurrent rule updates, memory pressure, or physical-CPU behavior. Two guest
  CPUs on a single TCG thread do not establish parallel stress coverage.
- No host module installation, host kernel execution, or production rollout was
  performed. Secure Boot and lockdown configurations require separate validation.

Before adopting a new kernel, inspect its configuration, symbol availability,
permission-changing semantics, and vmalloc cleanup behavior. Rebuild all modules
against its matching headers, rerun the allocator checks, and repeat the isolated
VM integration test using that exact distribution kernel. If the required
configuration or helpers are unavailable, retain non-JIT operation until a
compatible implementation has been validated.
