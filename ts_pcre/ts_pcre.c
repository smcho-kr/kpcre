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
#include <linux/textsearch.h>

#include "libc.h"
#include "pcre2.h"

MODULE_LICENSE("Dual BSD/GPL");
MODULE_AUTHOR("Seongmyun Cho <highsky@gmail.com>");
MODULE_DESCRIPTION("ts_pcre");

#define PARSE_REGEX         "(?<!\\\\)/(.*(?<!(?<!\\\\)\\\\))/([^\"]*)"

static pcre2_code *parse_regex;
static bool sysctl_jit_enable = true;
static int sysctl_jit_stack_start = 16; /* KB */
static int sysctl_jit_stack_max = 64; /* KB */

struct ts_pcre {
	u8 *pattern;
	unsigned int patlen;
	PCRE2_UCHAR *pcre;
	PCRE2_UCHAR *op_str;
	pcre2_code *re;
	pcre2_match_data *match_data;
	pcre2_match_context *mcontext;
	pcre2_jit_stack *jit_stack;
	int opts;
};

static unsigned int pcre_find(struct ts_config *conf, struct ts_state *state)
{
	PCRE2_SIZE *ovector;
	struct ts_pcre *pcre = ts_config_priv(conf);
	const u8 *text;
	unsigned int match, text_len, consumed = state->offset;
	int rc;

	pr_debug("%s: finding |%s| at offset %u", __func__, pcre->pcre, consumed);

	for (;;) {
		text_len = conf->get_next_block(consumed, &text, conf, state);

		if (unlikely(text_len == 0))
			break;

		rc = pcre2_match(pcre->re, text, text_len, 0, 0,
				 pcre->match_data, pcre->mcontext);

		if (unlikely(rc > 0)) {
			ovector = pcre2_get_ovector_pointer(pcre->match_data);
			match = consumed + ovector[0];
//			state->offset = consumed + ovector[1];
			pr_debug("%s: matched |%s| at offset %u", __func__, pcre->pcre, match);
			return match;
		}

		consumed += text_len;
//		state->offset = consumed;
	}

	return UINT_MAX;
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
		pr_debug("%s: invalid pattern", __func__);
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
				pr_debug("%s: unknown regex modifier '%c'",
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
	struct ts_config *conf;
	struct ts_pcre *pcre;
	PCRE2_SIZE erroffset;
	int errorcode, rc;
	size_t priv_size = sizeof(struct ts_pcre);

	pr_debug("%s: %d|%s|", __func__, len, (char *)pattern);

	conf = alloc_ts_config(priv_size, gfp_mask);
	if (IS_ERR(conf))
		return conf;

	conf->flags = flags;
	pcre = ts_config_priv(conf);
	pcre->patlen = len;
	pcre->pattern = calloc(len + 1, sizeof(u8));

	if (IS_ERR_OR_NULL(pcre->pattern))
		goto err_pattern;

	memcpy(pcre->pattern, pattern, len);

	rc = pattern_parse((char *)pattern, &pcre->pcre, &pcre->op_str);
	if (rc < 0)
		goto err_pattern;

	opts_parse(pcre->op_str, &pcre->opts);

	pcre->re = pcre2_compile(pcre->pcre, PCRE2_ZERO_TERMINATED, pcre->opts,
				 &errorcode, &erroffset, NULL);
	if (IS_ERR_OR_NULL(pcre->re))
		goto err_code;

	if (sysctl_jit_enable) {
		pcre->mcontext = pcre2_match_context_create(NULL);
		if (IS_ERR_OR_NULL(pcre->mcontext))
			goto err_match_context;

		rc = pcre2_jit_compile(pcre->re, PCRE2_JIT_COMPLETE);
		if (rc < 0)
			goto err_match_context;

		pcre->jit_stack = pcre2_jit_stack_create(\
			sysctl_jit_stack_start * 1024,
			sysctl_jit_stack_max * 1024, NULL);
		if (IS_ERR_OR_NULL(pcre->jit_stack))
			goto err_jit_stack;

		pcre2_jit_stack_assign(pcre->mcontext, NULL, pcre->jit_stack);
	}

	pcre->match_data = pcre2_match_data_create(1, NULL);
	if (IS_ERR_OR_NULL(pcre->match_data))
		goto err_match_data;

	return conf;

 err_match_data:
	pr_info("%s: %s", __func__, "err_match_data");
	if (sysctl_jit_enable)
		pcre2_jit_stack_free(pcre->jit_stack);

 err_jit_stack:
	pr_info("%s: %s", __func__, "err_jit_stack");
	if (sysctl_jit_enable)
		pcre2_match_context_free(pcre->mcontext);

 err_match_context:
	pr_info("%s: %s", __func__, "err_match_context");
	pcre2_code_free(pcre->re);

 err_code:
	pr_info("%s: %s", __func__, "err_code");

 err_pattern:
	pr_info("%s: %s", __func__, "err_pattern");
	free(pcre->pattern);
	kfree(conf);

	return ERR_PTR(-EINVAL);
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

	if (pcre->match_data)
		pcre2_match_data_free(pcre->match_data);

	if (pcre->mcontext)
		pcre2_match_context_free(pcre->mcontext);

	if (pcre->jit_stack)
		pcre2_jit_stack_free(pcre->jit_stack);

	if (pcre->pcre)
		pcre2_substring_free(pcre->pcre);

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

static int sysctl_pcre_jit(struct ctl_table *ctl, int write,
                  void __user *buffer,
                  size_t *lenp, loff_t *ppos)
{
    int ret = proc_dointvec(ctl, write, buffer, lenp, ppos);
	
	if (sysctl_jit_enable)
		sysctl_jit_enable = true;

	if (sysctl_jit_stack_start < 8)
		sysctl_jit_stack_start = 8;

	if (sysctl_jit_stack_start > sysctl_jit_stack_max)
		sysctl_jit_stack_max = sysctl_jit_stack_start;

	return ret;
}

static struct ctl_table_header *pcre_table_header;

static struct ctl_table pcre_table[] = {
    {
        .procname   = "jit_enable",
        .data       = &sysctl_jit_enable,
        .maxlen     = sizeof(int),
        .mode       = S_IRUGO|S_IWUSR,
        .proc_handler   = sysctl_pcre_jit,
    },
    {
        .procname   = "jit_stack_start",
        .data       = &sysctl_jit_stack_start,
        .maxlen     = sizeof(int),
        .mode       = S_IRUGO|S_IWUSR,
        .proc_handler   = sysctl_pcre_jit,
    },
    {
        .procname   = "jit_stack_max",
        .data       = &sysctl_jit_stack_max,
        .maxlen     = sizeof(int),
        .mode       = S_IRUGO|S_IWUSR,
        .proc_handler   = sysctl_pcre_jit,
    },
    { }
};

static struct ctl_table pcre_dir_table[] = {
    {
        .procname   = "pcre",
        .maxlen     = 0,
        .mode       = S_IRUGO|S_IXUGO,
        .child      = pcre_table,
    },
    { }
};

static int __init ts_pcre_init(void)
{
	PCRE2_SIZE erroffset;
	int errorcode;

	pr_debug("%s", __func__);

	parse_regex = pcre2_compile(PARSE_REGEX,
				    PCRE2_ZERO_TERMINATED, 0, &errorcode,
				    &erroffset, NULL);

	if (IS_ERR_OR_NULL(parse_regex)) {
#ifdef DEBUG
		PCRE2_UCHAR8 buffer[120];
		(void)pcre2_get_error_message(errorcode, buffer, 120);
		pr_debug("%s: %s", __func__, buffer);
#endif
		return -ENOMEM;
	}

	pcre_table_header = register_sysctl_table(pcre_dir_table);
	return textsearch_register(&pcre_ops);
}

static void __exit ts_pcre_exit(void)
{
	pr_debug("%s", __func__);

	if (parse_regex)
		pcre2_code_free(parse_regex);

	unregister_sysctl_table(pcre_table_header);
	textsearch_unregister(&pcre_ops);
}

module_init(ts_pcre_init);
module_exit(ts_pcre_exit);
