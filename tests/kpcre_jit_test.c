// SPDX-License-Identifier: GPL-2.0
/* Load only in a disposable VM: this test executes generated kernel code. */
#include <linux/module.h>
#include <linux/textsearch.h>
#include "pcre2.h"

static int test_jit(void)
{
	pcre2_code *first = NULL, *second = NULL;
	pcre2_match_data *data = NULL;
	PCRE2_SIZE offset, size, *ovector;
	int error, result = -EINVAL;

	first = pcre2_compile((PCRE2_SPTR)"^(ab+)(c)$", PCRE2_ZERO_TERMINATED,
			     0, &error, &offset, NULL);
	second = pcre2_compile((PCRE2_SPTR)"^x[0-9]+$", PCRE2_ZERO_TERMINATED,
			      0, &error, &offset, NULL);
	data = pcre2_match_data_create(4, NULL);
	if (!first || !second || !data)
		goto out;
	error = pcre2_jit_compile(first, PCRE2_JIT_COMPLETE | PCRE2_JIT_PARTIAL_HARD);
	if (error) {
		pr_err("kpcre_jit_test: compilation failed: %d\n", error);
		goto out;
	}
	if (pcre2_jit_compile(second, PCRE2_JIT_COMPLETE) ||
	    pcre2_pattern_info(first, PCRE2_INFO_JITSIZE, &size) || !size)
		goto out;
	/* Explicit JIT entry points prevent an interpreter fallback hiding failure. */
	if (pcre2_jit_match(first, (PCRE2_SPTR)"abbbc", 5, 0, 0, data, NULL) != 3)
		goto out;
	ovector = pcre2_get_ovector_pointer(data);
	if (ovector[0] != 0 || ovector[1] != 5 || ovector[2] != 0 ||
	    ovector[3] != 4 || ovector[4] != 4 || ovector[5] != 5)
		goto out;
	if (pcre2_match(first, (PCRE2_SPTR)"abbbc", 5, 0, PCRE2_NO_JIT, data, NULL) != 3 ||
	    pcre2_jit_match(first, (PCRE2_SPTR)"abd", 3, 0, 0, data, NULL) != PCRE2_ERROR_NOMATCH ||
	    pcre2_jit_match(first, (PCRE2_SPTR)"ab", 2, 0, PCRE2_PARTIAL_HARD, data, NULL) != PCRE2_ERROR_PARTIAL)
		goto out;
	pcre2_code_free(first);
	first = NULL;
	if (pcre2_jit_match(second, (PCRE2_SPTR)"x123", 4, 0, 0, data, NULL) != 1)
		goto out;
	result = 0;
out:
	pcre2_match_data_free(data);
	pcre2_code_free(second);
	pcre2_code_free(first);
	return result;
}

static int test_textsearch(const char *engine)
{
	const char pattern[] = "/^ab+c$/";
	struct ts_state state = {};
	struct ts_config *conf;
	int result = -EINVAL;

	conf = textsearch_prepare(engine, pattern, sizeof(pattern) - 1, GFP_KERNEL, 0);
	if (IS_ERR(conf))
		return PTR_ERR(conf);
	if (textsearch_find_continuous(conf, &state, "abbbc", 5) != 0)
		goto out;
	memset(&state, 0, sizeof(state));
	if (textsearch_find_continuous(conf, &state, "abd", 3) != UINT_MAX)
		goto out;
	result = 0;
out:
	textsearch_destroy(conf);
	return result;
}

static int __init kpcre_jit_test_init(void)
{
	int i, error;

	for (i = 0; i < 32; i++) {
		error = test_jit();
		if (!error)
			error = test_textsearch("pcre");
		if (!error)
			error = test_textsearch("regex");
		if (error) {
			pr_err("kpcre_jit_test: FAIL at iteration %d (%d)\n", i, error);
			return error;
		}
	}
	pr_info("kpcre_jit_test: PASS (JIT, partial match, free/reuse, pcre/regex engines)\n");
	return 0;
}

static void __exit kpcre_jit_test_exit(void) {}
module_init(kpcre_jit_test_init);
module_exit(kpcre_jit_test_exit);
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("PCRE JIT and text-search integration test");
