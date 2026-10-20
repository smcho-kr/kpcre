/* SPDX-License-Identifier: BSD-2-Clause */
/* Kernel JIT pages are writable during generation and read-only when executed. */

#include <linux/kprobes.h>
#include <linux/security.h>
#include <linux/vmalloc.h>

static int (*jit_set_memory_ro)(unsigned long, int) __ro_after_init;
static int (*jit_set_memory_x)(unsigned long, int) __ro_after_init;
static struct vm_struct *(*jit_find_vm_area)(const void *) __ro_after_init;
static void (*jit_vfree_atomic)(const void *) __ro_after_init;
static bool jit_exec_ready __ro_after_init;

/* shortcut: these x86 helpers are not exported; revalidate on kernel upgrades. */
static void *jit_lookup_helper(const char *name)
{
	struct kprobe probe = {
		.symbol_name = name,
		.flags = KPROBE_FLAG_DISABLED,
	};
	void *address;
	int error = register_kprobe(&probe);

	if (error) {
		pr_warn("libpcre2: cannot resolve JIT helper %s (%d)\n", name, error);
		return NULL;
	}
	address = probe.addr;
	unregister_kprobe(&probe);
	return address;
}

void kpcre_jit_exec_init(void)
{
	/* This SLJIT predates the IBT/CFI landing pads required by those kernels. */
	if (!IS_ENABLED(CONFIG_X86_64) || !IS_ENABLED(CONFIG_KPROBES) ||
	    IS_ENABLED(CONFIG_X86_KERNEL_IBT) || IS_ENABLED(CONFIG_CFI_CLANG) ||
	    IS_ENABLED(CONFIG_CFI)) {
		pr_warn("libpcre2: kernel JIT requires x86-64, Kprobes, and no IBT/CFI\n");
		return;
	}
	if (security_locked_down(LOCKDOWN_KPROBES)) {
		pr_warn("libpcre2: kernel lockdown prevents JIT helper lookup\n");
		return;
	}

	jit_set_memory_ro = jit_lookup_helper("set_memory_ro");
	jit_set_memory_x = jit_lookup_helper("set_memory_x");
	jit_find_vm_area = jit_lookup_helper("find_vm_area");
	jit_vfree_atomic = jit_lookup_helper("vfree_atomic");
	jit_exec_ready = jit_set_memory_ro && jit_set_memory_x &&
		jit_find_vm_area && jit_vfree_atomic;
}

SLJIT_API_FUNC_ATTRIBUTE void *sljit_malloc_exec(sljit_uw size)
{
	struct vm_struct *area;
	int *header;
	void *code;

	if (!jit_exec_ready || in_atomic() || irqs_disabled() || !size ||
	    size > ULONG_MAX - 2 * PAGE_SIZE)
		return NULL;
	size = PAGE_ALIGN(size);
	if ((size >> PAGE_SHIFT) > INT_MAX)
		return NULL;

	/* Keep the first page writable for vfree's deferred-free list node. */
	header = vmalloc(size + PAGE_SIZE);
	if (!header)
		return NULL;
	area = jit_find_vm_area(header);
	if (!area) {
		vfree(header);
		return NULL;
	}
	/* Reset direct-map aliases and flush stale executable mappings on free. */
	area->flags |= VM_FLUSH_RESET_PERMS;
	*header = size >> PAGE_SHIFT;
	code = (char *)header + PAGE_SIZE;
	memset(code, 0xcc, size);
	return code;
}

static int sljit_make_exec(void *code)
{
	int nr_pages = *(int *)((char *)code - PAGE_SIZE);
	int error;

	error = jit_set_memory_ro((unsigned long)code, nr_pages);
	if (!error)
		error = jit_set_memory_x((unsigned long)code, nr_pages);
	if (error)
		pr_warn("libpcre2: cannot finalize JIT page permissions (%d)\n", error);
	return error;
}

SLJIT_API_FUNC_ATTRIBUTE void sljit_free_exec(void *code)
{
	if (code)
		jit_vfree_atomic((char *)code - PAGE_SIZE);
}

SLJIT_API_FUNC_ATTRIBUTE void sljit_free_unused_memory_exec(void)
{
	/* Each compiled pattern owns its pages; there is no shared free list. */
}
