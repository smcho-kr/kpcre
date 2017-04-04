/*
 * ts_pcre.c		PCRE search implementation
 *
 * Copyright (C) 2016 Seongmyun Cho <highsky@gmail.com>
 * 
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; version 2 of the License.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
 *
 * =====================================================================
 * 
 *   Implements PCRE matching algorithm:
 *
 *   Note: Obviously, it's possible that a matching could be spread over 
 *   multiple blocks, in that case this code won't find any coincidence.
 *   
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/types.h>
#include <linux/string.h>
#include <linux/ctype.h>
#include <linux/stddef.h>
#include <linux/interrupt.h>
#include <linux/textsearch.h>

#include "libc.h"
#include "pcre2.h"

MODULE_LICENSE("Dual BSD/GPL");
MODULE_AUTHOR("Seongmyun Cho <highsky@gmail.com>");
MODULE_DESCRIPTION("PCRE text search engine");

#define PARSE_REGEX         "(?<!\\\\)/(.*(?<!(?<!\\\\)\\\\))/([^\"]*)"
#define OVECTOR_SIZE 4

static pcre2_code *parse_regex;

static bool jit_enable __read_mostly = true;
module_param_named(jit, jit_enable, bool, 0444);
MODULE_PARM_DESC(jit, " enable JIT(just in time) compilation.");

static unsigned int jit_stack_start __read_mostly = 1; /* bytes */
module_param_named(start, jit_stack_start, uint, 0444);
MODULE_PARM_DESC(start, " set a starting size of the JIT stack.");

static unsigned int jit_stack_max __read_mostly = 512 * 1024; /* bytes */
module_param_named(max, jit_stack_max, uint, 0444);
MODULE_PARM_DESC(max, " set a maximum size to which the JIT stack is allowed to grow.");

struct ts_pcre {
	u8 *pattern;
	unsigned int patlen;
	PCRE2_UCHAR *pcre_str;
	PCRE2_UCHAR *op_str;
	pcre2_code *re;
	int opts;
};

static DEFINE_PER_CPU(pcre2_match_data *, match_data);
static DEFINE_PER_CPU(pcre2_match_context *, match_context);
static DEFINE_PER_CPU(pcre2_jit_stack *, jit_stack);

#ifndef __get_cpu_var
#define __get_cpu_var(var)	*this_cpu_ptr(&(var))
#endif

static unsigned int pcre_find(struct ts_config *conf, struct ts_state *state)
{
	pcre2_match_data *_match_data;
	pcre2_match_context *_match_context;
	PCRE2_SIZE *ovector;
	struct ts_pcre *pcre;
	const u8 *text;
	unsigned int match, text_len, consumed;
	int rc;

	pcre = ts_config_priv(conf);
	consumed = state->offset;

	preempt_disable();

	_match_data = __get_cpu_var(match_data);
	_match_context = __get_cpu_var(match_context);

	for (;;) {
		text_len = conf->get_next_block(consumed, &text, conf, state);

		if (unlikely(text_len == 0))
			break;

		rc = pcre2_match(pcre->re, text, text_len, 0, 0,
				 _match_data, _match_context);

		if (unlikely(rc >= 0)) {
#ifdef DEBUG
			PCRE2_UCHAR *str;
			PCRE2_SIZE	slen;
			int i;

			rc = pcre2_substring_get_bynumber(_match_data, 0, \
					&str, &slen);

			if (rc < 0) {
				pr_debug("%s: pcre2_substring_get_bynumber(pcre) failed",
					 __func__);
				break;
			} else {
				printk("\n");
				for (i = 0; i < slen; i++) {
					if (isprint(str[i]))
						printk("%c", str[i]);
					else
						printk("|%02X|", str[i]);
				}
				printk("\n");

				pcre2_substring_free(str);
			}
#endif
			ovector = pcre2_get_ovector_pointer(_match_data);
			match = consumed + ovector[0];
//			state->offset = consumed + ovector[1];
			pr_debug("%s: matched |%s| at offset %u", __func__, pcre->pcre_str, match);
			goto found;
		}

		consumed += text_len;
//		state->offset = consumed;
	}

	match = UINT_MAX;

found:
	preempt_enable();
	return match;
}

static inline int
pattern_parse(const char *pattern, PCRE2_UCHAR ** pcre, PCRE2_UCHAR ** op_str)
{
	PCRE2_SIZE relen, oplen;
	pcre2_match_data *match_data;
	int res, rc;

	match_data = pcre2_match_data_create(4, NULL);
	if (IS_ERR_OR_NULL(match_data)) {
		return -ENOMEM;
	}

	res = pcre2_match(parse_regex, pattern, -1, 0, 0, match_data, NULL);
	if (res <= 0) {
		pr_debug("%s: pcre2_match failed", __func__);
		pcre2_match_data_free(match_data);
		return -EINVAL;
	}

	relen = 0;
	oplen = 0;

	rc = pcre2_substring_get_bynumber(match_data, 1, pcre, &relen);
	if (rc < 0) {
		pr_debug("%s: pcre2_substring_get_bynumber(pcre) failed",
			 __func__);
		return -EINVAL;
	}

	if (res > 2) {
		rc = pcre2_substring_get_bynumber(match_data, 2, op_str,
						  &oplen);
		if (rc < 0) {
			pr_debug
			    ("%s: pcre2_substring_get_bynumber(opts) failed",
			     __func__);
			return -EINVAL;
		}
	}
#ifdef DEBUG
	if (relen > 0) {
		pr_debug("pcre: %lu|%s|", relen, *pcre);
	}

	if (oplen > 0) {
		pr_debug("opts: %lu|%s|", oplen, *op_str);
	}
#endif

	pcre2_match_data_free(match_data);

	return 0;
}

static inline void opts_parse(char *op_str, int *_opts)
{
	char *op = NULL;
	int opts = 0;

	op = op_str;
	*_opts = 0;

	if (op != NULL) {
		while (*op) {
			switch (*op) {
			case 'A':
				opts |= PCRE2_ANCHORED;
				break;
			case 'E':
				opts |= PCRE2_DOLLAR_ENDONLY;
				break;
			case 'G':
				opts |= PCRE2_UNGREEDY;
				break;

			case 'i':
				opts |= PCRE2_CASELESS;
				break;
			case 'm':
				opts |= PCRE2_MULTILINE;
				break;
			case 's':
				opts |= PCRE2_DOTALL;
				break;
			case 'x':
				opts |= PCRE2_EXTENDED;
				break;

			default:
				pr_info("%s: unknown regex modifier '%c'",
					 __func__, *op);
				break;
			}
			op++;
		}
	}

	*_opts = opts;
}

static struct ts_config *pcre_init(const void *pattern, unsigned int len,
				   gfp_t gfp_mask, int flags)
{
	struct ts_config *conf = ERR_PTR(-EINVAL);
	struct ts_pcre pcre;
	PCRE2_SIZE erroffset;
	int errorcode, rc;
	size_t priv_size = sizeof(struct ts_pcre);

	pr_debug("%s: |%s|", __func__, (char *)pattern);

	pcre.patlen = len;
	pcre.pattern = calloc(len + 1, sizeof(u8));

	if (IS_ERR_OR_NULL(pcre.pattern)) {
		pr_debug("%s: %s", __func__, "err_pattern");
		goto err_pattern;
	}

	memcpy(pcre.pattern, pattern, len);

	rc = pattern_parse((char *)pattern, &pcre.pcre_str, &pcre.op_str);
	if (rc < 0) {
		pr_debug("%s: %s", __func__, "err_pattern_parse");
		goto err_pattern_parse;
	}
	pr_debug("%s: |%s|%s|", __func__, pcre.pcre_str, pcre.op_str);

	opts_parse(pcre.op_str, &pcre.opts);

	pcre.re = pcre2_compile(pcre.pcre_str, PCRE2_ZERO_TERMINATED, pcre.opts,
				 &errorcode, &erroffset, NULL);
	if (IS_ERR_OR_NULL(pcre.re)) {
		pr_debug("%s: %s", __func__, "err_pcre_compile");
		goto err_pcre_compile;
	}

	if (jit_enable) {

		rc = pcre2_jit_compile(pcre.re, PCRE2_JIT_COMPLETE);
		if (rc < 0) {
			pr_debug("%s: %s", __func__, "err_jit_compile");
			goto err_jit_compile;
		}

	}

	conf = alloc_ts_config(priv_size, gfp_mask);
	if (IS_ERR(conf)) {
		pr_debug("%s: %s", __func__, "err_alloc_conf");
		goto err_alloc_conf;
	}

	conf->flags = flags;
	memcpy(ts_config_priv(conf), &pcre, priv_size);

	return conf;

 err_alloc_conf:
 err_jit_compile:
	pcre2_code_free(pcre.re);

 err_pcre_compile:
 err_pattern_parse:
 err_pattern:
	free(pcre.pattern);

	pr_info("%s failed: it's probably a regex pattern error", __func__);
	return conf;
}

static void pcre_destroy(struct ts_config *conf)
{
	struct ts_pcre *pcre;

	pcre = ts_config_priv(conf);

	pr_debug("%s: |%s|", __func__, pcre->pattern);

	if (pcre->pattern)
		free(pcre->pattern);

	if (pcre->re)
		pcre2_code_free(pcre->re);

	if (pcre->pcre_str)
		pcre2_substring_free(pcre->pcre_str);

	if (pcre->op_str)
		pcre2_substring_free(pcre->op_str);

}

static void *pcre_get_pattern(struct ts_config *conf)
{
	struct ts_pcre *pcre = ts_config_priv(conf);
	return pcre->pattern;
}

static unsigned int pcre_get_pattern_len(struct ts_config *conf)
{
	struct ts_pcre *pcre = ts_config_priv(conf);
	return pcre->patlen;
}

static struct ts_ops pcre_ops = {
	.name = "pcre",
	.find = pcre_find,
	.init = pcre_init,
	.destroy = pcre_destroy,
	.get_pattern = pcre_get_pattern,
	.get_pattern_len = pcre_get_pattern_len,
	.owner = THIS_MODULE,
	.list = LIST_HEAD_INIT(pcre_ops.list)
};

static int __init ts_pcre_init(void)
{
	PCRE2_SIZE erroffset;
	int errorcode;
	int i;

	if (jit_stack_start > jit_stack_max)
		jit_stack_max = jit_stack_start;

	pr_debug("%s j: %u s: %u m: %u", \
			__func__, jit_enable, jit_stack_start, jit_stack_max);

	parse_regex = pcre2_compile(PARSE_REGEX,
				    PCRE2_ZERO_TERMINATED, 0, &errorcode,
				    &erroffset, NULL);

	if (parse_regex == NULL)
		goto err_compile;

    for_each_online_cpu(i) {

		pcre2_match_data *_match_data = pcre2_match_data_create(OVECTOR_SIZE, NULL);
		pcre2_match_context *_match_context = pcre2_match_context_create(NULL);

		pcre2_jit_stack *_jit_stack = pcre2_jit_stack_create(jit_stack_start, jit_stack_max, NULL);

		pcre2_jit_stack_assign(_match_context, NULL, _jit_stack);

		per_cpu(match_data, i) = _match_data;
		per_cpu(match_context, i) = _match_context;
		per_cpu(jit_stack, i) = _jit_stack;

    }   

	return textsearch_register(&pcre_ops);

err_compile:
	return -ENOMEM;
}

static void __exit ts_pcre_exit(void)
{
	int i;
	pr_debug("%s", __func__);

    for_each_online_cpu(i) {
		pcre2_match_data *_match_data = per_cpu(match_data, i);
		pcre2_match_context *_match_context = per_cpu(match_context, i);
		pcre2_jit_stack *_jit_stack = per_cpu(jit_stack, i);

		pcre2_match_data_free(_match_data);
		pcre2_match_context_free(_match_context);
		pcre2_jit_stack_free(_jit_stack);
    }   

	if (parse_regex)
		pcre2_code_free(parse_regex);

	pcre2_jit_free_unused_memory(NULL);

	textsearch_unregister(&pcre_ops);
}

module_init(ts_pcre_init);
module_exit(ts_pcre_exit);
