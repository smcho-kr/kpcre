/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef KPCRE_SCRATCH_ALLOC_TEST_H
#define KPCRE_SCRATCH_ALLOC_TEST_H

#include <assert.h>
#include <stddef.h>
#include <stdlib.h>

struct kmem_cache { unsigned int id; };
void *kmem_cache_alloc(struct kmem_cache *cache, unsigned int flags);
void kmem_cache_free(struct kmem_cache *cache, void *object);
extern unsigned int scratch_fpu_depth;

#define GFP_ATOMIC 0
#define unlikely(condition) (condition)
#define EXPORT_SYMBOL(symbol)
#define panic(...) abort()
#define KERNEL_VERSION(a, b, c) (((a) << 16) | ((b) << 8) | (c))
#define LINUX_VERSION_CODE KERNEL_VERSION(6, 1, 0)
#define kernel_fpu_begin() do { assert(scratch_fpu_depth++ == 0); } while (0)
#define kernel_fpu_end() do { assert(--scratch_fpu_depth == 0); } while (0)

#endif
