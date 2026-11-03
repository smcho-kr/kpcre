/* SPDX-License-Identifier: GPL-2.0-only */
#include <stdint.h>
#include <stdio.h>
#include "config.h"
#include "pcre2_internal.h"
#include "scratch_alloc_test.h"

static struct kmem_cache caches[7] = {{0}, {1}, {2}, {3}, {4}, {5}, {6}};
struct kmem_cache *local_space_cache = &caches[0];
struct kmem_cache *local_offsets_cache = &caches[1];
struct kmem_cache *local_workspace_cache = &caches[2];
struct kmem_cache *stack_groupinfo_cache = &caches[3];
struct kmem_cache *stack_parsed_pattern_cache = &caches[4];
struct kmem_cache *named_groups_cache = &caches[5];
struct kmem_cache *c16workspace_cache = &caches[6];
unsigned int scratch_fpu_depth;
static unsigned int attempts, fail_at, live[7], checks;

void *kmem_cache_alloc(struct kmem_cache *cache, unsigned int flags)
{
	void *object;
	assert(flags == GFP_ATOMIC);
	if (++attempts == fail_at)
		return NULL;
	/* Oversize buffers keep this shim focused on ownership and failures. */
	object = malloc(65536);
	assert(object);
	live[cache->id]++;
	return object;
}

void kmem_cache_free(struct kmem_cache *cache, void *object)
{
	assert(object && live[cache->id]);
	live[cache->id]--;
	free(object);
}

static void clean(void)
{
	for (unsigned int i = 0; i < 7; i++)
		assert(live[i] == 0);
	assert(scratch_fpu_depth == 0);
	checks++;
}

static void fault(unsigned int allocation)
{
	clean();
	attempts = 0;
	fail_at = allocation;
}

static pcre2_code *compile(const char *pattern)
{
	PCRE2_SIZE offset;
	int error;
	pcre2_code *code = pcre2_compile((PCRE2_SPTR)pattern,
		PCRE2_ZERO_TERMINATED, 0, &error, &offset, NULL);
	assert(code);
	clean();
	return code;
}

static void test_compile(void)
{
	PCRE2_SIZE offset;
	int error;
	pcre2_code *code;
	pcre2_compile_context *context = pcre2_compile_context_create(NULL);
	assert(context);
	for (unsigned int i = 1; i <= 4; i++) {
		fault(i);
		error = -1;
		offset = 99;
		code = pcre2_compile((PCRE2_SPTR)"(?<letter>a)+",
			PCRE2_ZERO_TERMINATED, 0, &error, &offset, NULL);
		assert(!code && error == COMPILE_ERROR_BASE + 21 && offset == 0);
		clean();
	}
	fault(0);
	code = compile("(?<letter>a)+");
	pcre2_code_free(code);
	assert(!pcre2_compile((PCRE2_SPTR)"(", PCRE2_ZERO_TERMINATED,
		0, &error, &offset, NULL));
	clean();
	assert(pcre2_set_max_pattern_length(context, 1) == 0);
	assert(!pcre2_compile((PCRE2_SPTR)"abc", PCRE2_ZERO_TERMINATED,
		0, &error, &offset, context));
	clean();
	pcre2_compile_context_free(context);
}

static void test_jit(void)
{
	pcre2_code *code = compile("^a+$");
	pcre2_match_data *data = pcre2_match_data_create(1, NULL);
	pcre2_match_context *context = pcre2_match_context_create(NULL);
	pcre2_jit_stack *stack = pcre2_jit_stack_create(32768, 32768, NULL);
	assert(data && context && stack);
	assert(pcre2_jit_compile(code, PCRE2_JIT_COMPLETE) == 0);
	fault(1);
	assert(pcre2_jit_match(code, (PCRE2_SPTR)"aaa", 3, 0, 0,
		data, NULL) == PCRE2_ERROR_NOMEMORY);
	clean();
	fault(1);
	assert(pcre2_match(code, (PCRE2_SPTR)"aaa", 3, 0, 0,
		data, NULL) == PCRE2_ERROR_NOMEMORY);
	clean();
	fault(0);
	assert(pcre2_jit_match(code, (PCRE2_SPTR)"aaa", 3, 0, 0, data, NULL) == 1);
	clean();
	assert(pcre2_jit_match(code, (PCRE2_SPTR)"b", 1, 0, 0,
		data, NULL) == PCRE2_ERROR_NOMATCH);
	clean();
	pcre2_jit_stack_assign(context, NULL, stack);
	fault(1);
	assert(pcre2_jit_match(code, (PCRE2_SPTR)"aaa", 3, 0, 0, data, context) == 1);
	assert(attempts == 0);
	clean();
	pcre2_jit_stack_free(stack);
	pcre2_match_context_free(context);
	pcre2_match_data_free(data);
	pcre2_code_free(code);
	fault(0);
}

static void test_dfa(const char *pattern)
{
	pcre2_code *code = compile(pattern);
	pcre2_match_data *data = pcre2_match_data_create(1, NULL);
	pcre2_match_context *context = pcre2_match_context_create(NULL);
	int workspace[1000];
	assert(data && context);
	for (unsigned int i = 1; i <= 4; i++) {
		fault(i);
		assert(pcre2_dfa_match(code, (PCRE2_SPTR)"a", 1, 0, 0,
			data, NULL, workspace, 1000) == PCRE2_ERROR_NOMEMORY);
		assert(attempts == i);
		clean();
	}
	fault(0);
	assert(pcre2_dfa_match(code, (PCRE2_SPTR)"a", 1, 0, 0,
		data, NULL, workspace, 1000) == 1);
	clean();
	assert(pcre2_dfa_match(code, (PCRE2_SPTR)"x", 1, 0, 0,
		data, NULL, workspace, 1000) == PCRE2_ERROR_NOMATCH);
	clean();
	assert(pcre2_set_recursion_limit(context, 0) == 0);
	fault(0);
	assert(pcre2_dfa_match(code, (PCRE2_SPTR)"a", 1, 0, 0,
		data, context, workspace, 1000) == PCRE2_ERROR_RECURSIONLIMIT);
	assert(attempts == 2);
	clean();
	pcre2_match_context_free(context);
	pcre2_match_data_free(data);
	pcre2_code_free(code);
}

int main(void)
{
	test_compile();
	test_jit();
	test_dfa("^(?=a)a$");
	test_dfa("^(?(?=a)a|b)$");
	printf("PASS: %u scratch allocation/cleanup checks (compile, JIT, recursive DFA)\n", checks);
	return 0;
}
