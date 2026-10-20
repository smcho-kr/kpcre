#define _GNU_SOURCE
#include <assert.h>
#include <errno.h>
#include <limits.h>
#include <stdbool.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <unistd.h>

/* Run the production allocator with POSIX mappings and simulated kernel APIs. */
#define CONFIG_X86_64 1
#ifndef CONFIG_KPROBES
#define CONFIG_KPROBES 1
#endif
#ifndef CONFIG_X86_KERNEL_IBT
#define CONFIG_X86_KERNEL_IBT 0
#endif
#ifndef CONFIG_CFI_CLANG
#define CONFIG_CFI_CLANG 0
#endif
#define CONFIG_CFI 0
#define IS_ENABLED(option) (option)
#define __ro_after_init
#define SLJIT_API_FUNC_ATTRIBUTE static
#define PAGE_SHIFT 12
#define PAGE_SIZE (1UL << PAGE_SHIFT)
#define PAGE_ALIGN(size) (((size) + PAGE_SIZE - 1) & ~(PAGE_SIZE - 1))
#define KPROBE_FLAG_DISABLED 1
#define VM_FLUSH_RESET_PERMS 0x100
#define LOCKDOWN_KPROBES 1
#define pr_warn(...) ((void)0)
typedef unsigned long sljit_uw;

struct vm_struct { unsigned long flags; };
struct kprobe { const char *symbol_name; unsigned int flags; void *addr; };
static struct allocation {
	void *base;
	size_t size;
	struct vm_struct area;
	int read_only;
} allocations[8];
static bool atomic_context, interrupts_disabled, deny_lookup, fail_alloc, fail_area;
static int fail_ro, fail_x, probes, unprobes, live_allocations;
static const char *missing_helper;

static int in_atomic(void) { return atomic_context; }
static int irqs_disabled(void) { return interrupts_disabled; }
static int security_locked_down(int reason)
{
	assert(reason == LOCKDOWN_KPROBES);
	return deny_lookup ? -EPERM : 0;
}

static struct allocation *allocation_at(const void *base)
{
	for (unsigned int i = 0; i < sizeof(allocations) / sizeof(*allocations); i++)
		if (allocations[i].base == base)
			return &allocations[i];
	assert(!"unknown allocation");
	return NULL;
}

static void *vmalloc(size_t size)
{
	struct allocation *allocation;
	void *base;
	if (fail_alloc)
		return NULL;
	allocation = allocation_at(NULL);
	base = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	assert(base != MAP_FAILED);
	*allocation = (struct allocation){ .base = base, .size = size };
	live_allocations++;
	return base;
}

static void vfree(const void *base)
{
	struct allocation *allocation = allocation_at(base);
	assert(munmap(allocation->base, allocation->size) == 0);
	allocation->base = NULL;
	live_allocations--;
}

static struct vm_struct *find_area(const void *base)
{
	return fail_area ? NULL : &allocation_at(base)->area;
}

static void free_atomic(const void *base)
{
	assert(allocation_at(base)->area.flags & VM_FLUSH_RESET_PERMS);
	/* The real kernel stores its deferred-free list node at this address. */
	*(void **)base = NULL;
	vfree(base);
}

static int make_ro(unsigned long address, int pages)
{
	struct allocation *allocation = allocation_at((char *)address - PAGE_SIZE);
	assert((size_t)pages * PAGE_SIZE == allocation->size - PAGE_SIZE);
	assert(mprotect((void *)address, pages * PAGE_SIZE, PROT_READ) == 0);
	allocation->read_only = 1;
	return fail_ro ? -EACCES : 0;
}

static int make_x(unsigned long address, int pages)
{
	assert(allocation_at((char *)address - PAGE_SIZE)->read_only);
	assert(mprotect((void *)address, pages * PAGE_SIZE, PROT_READ | PROT_EXEC) == 0);
	return fail_x ? -EACCES : 0;
}

static int register_kprobe(struct kprobe *probe)
{
	assert(probe->flags == KPROBE_FLAG_DISABLED);
	if (missing_helper && !strcmp(probe->symbol_name, missing_helper))
		return -ENOENT;
	if (!strcmp(probe->symbol_name, "set_memory_ro")) probe->addr = make_ro;
	else if (!strcmp(probe->symbol_name, "set_memory_x")) probe->addr = make_x;
	else if (!strcmp(probe->symbol_name, "find_vm_area")) probe->addr = find_area;
	else if (!strcmp(probe->symbol_name, "vfree_atomic")) probe->addr = free_atomic;
	else assert(!"unexpected helper");
	probes++;
	return 0;
}

static void unregister_kprobe(struct kprobe *probe)
{
	assert(probe->addr);
	unprobes++;
}

#include "../pcre2/sljit/sljitKernelExecAllocator.c"

static void expect_fault(void *code, bool write)
{
	pid_t child = fork();
	int status;
	assert(child >= 0);
	if (!child) {
		if (write) *(volatile unsigned char *)code = 0x90;
		else ((int (*)(void))code)();
		_exit(0);
	}
	assert(waitpid(child, &status, 0) == child);
	assert(WIFSIGNALED(status) && WTERMSIG(status) == SIGSEGV);
}

int main(void)
{
	const unsigned char return_42[] = { 0xb8, 42, 0, 0, 0, 0xc3 };
	const char *helpers[] = { "set_memory_ro", "set_memory_x", "find_vm_area", "vfree_atomic" };
	struct rlimit no_core = { 0, 0 };
	void *first, *second;
	assert(sysconf(_SC_PAGESIZE) == PAGE_SIZE);
	assert(setrlimit(RLIMIT_CORE, &no_core) == 0);
	kpcre_jit_exec_init();
	if (!CONFIG_KPROBES || CONFIG_X86_KERNEL_IBT || CONFIG_CFI_CLANG) {
		assert(!jit_exec_ready && !sljit_malloc_exec(1) && !probes);
		puts("kernel_exec: unsupported configuration rejected");
		return 0;
	}
	assert(jit_exec_ready && probes == unprobes);
	assert(!sljit_malloc_exec(0) && !sljit_malloc_exec(ULONG_MAX));
	atomic_context = true;
	assert(!sljit_malloc_exec(1));
	atomic_context = false;
	interrupts_disabled = true;
	assert(!sljit_malloc_exec(1));
	interrupts_disabled = false;
	fail_alloc = true;
	assert(!sljit_malloc_exec(1));
	fail_alloc = false;
	fail_area = true;
	assert(!sljit_malloc_exec(1) && !live_allocations);
	fail_area = false;

	first = sljit_malloc_exec(sizeof(return_42));
	second = sljit_malloc_exec(PAGE_SIZE + 1);
	assert(first && second && !((uintptr_t)first & (PAGE_SIZE - 1)));
	memcpy(first, return_42, sizeof(return_42));
	memcpy(second, return_42, sizeof(return_42));
	expect_fault(first, false);
	assert(!sljit_make_exec(first) && !sljit_make_exec(second));
	assert(((int (*)(void))first)() == 42);
	expect_fault(first, true);
	sljit_free_exec(first);
	assert(((int (*)(void))second)() == 42);
	sljit_free_exec(second);
	sljit_free_exec(NULL);
	sljit_free_unused_memory_exec();

	for (int i = 0; i < 2; i++) {
		fail_ro = !i;
		fail_x = i;
		first = sljit_malloc_exec(1);
		assert(first && sljit_make_exec(first) == -EACCES);
		sljit_free_exec(first);
	}
	assert(!live_allocations);
	for (unsigned int i = 0; i < sizeof(helpers) / sizeof(*helpers); i++) {
		missing_helper = helpers[i];
		kpcre_jit_exec_init();
		assert(!jit_exec_ready && !sljit_malloc_exec(1));
	}
	jit_exec_ready = false;
	deny_lookup = true;
	kpcre_jit_exec_init();
	assert(!jit_exec_ready && !sljit_malloc_exec(1) && probes == unprobes);
	puts("kernel_exec: W^X, independent pages, cleanup and failure paths passed");
	return 0;
}
