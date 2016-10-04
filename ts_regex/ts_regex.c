/*
 * ts_regex.c		REGEX search implementation
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
 *   Implements REGEX matching algorithm:
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
#include "pcre2posix.h"

MODULE_LICENSE("Dual BSD/GPL");
MODULE_AUTHOR("Seongmyun Cho <highsky@gmail.com>");
MODULE_DESCRIPTION("REGEX text search engine");

#define PARSE_REGEX         "(?<!\\\\)/(.*(?<!(?<!\\\\)\\\\))/([^\"]*)"

static pcre2_code *parse_regex;

#define NS 1
struct ts_regex {
	u8 *pattern;
	unsigned int patlen;
	PCRE2_UCHAR	*regex_str;
	PCRE2_UCHAR	*op_str;
	regex_t re;
	regmatch_t subs[NS];
	int copts, eopts;
};

static unsigned int regex_find(struct ts_config *conf, struct ts_state *state)
{
	struct ts_regex *regex = ts_config_priv(conf);
	unsigned int text_len, consumed = state->offset;
	int rc;
	const u8 *text;
	unsigned int slen;

	pr_debug("%s: finding |%s| at offset %u", __func__, regex->pattern, consumed);

	/* POSIX regex functions deal with only null-terminated strings.   */
	/* They can't properly handle patterns with null character inside. */
	for (;;) {

		text_len = conf->get_next_block(consumed, &text, conf, state);
		slen = strlen(text);

		pr_debug("next block size: %u(%u)", text_len, slen);

		if (unlikely(text_len == 0))
			break;

		rc = regexec(&regex->re, (char *) text, NS, regex->subs, regex->eopts);

		if (unlikely(rc == 0)) {
			consumed += regex->subs[0].rm_so;
			pr_debug("%s: matched |%s| at offset %u", __func__, regex->pattern, consumed);
			return consumed;
		}

		while (!text[slen])
			slen++;

		consumed += min(slen, text_len) ;
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

static inline void opts_parse(char *op_str, int *copts, int *eopts)
{
    char *op = NULL;
    int _copts = 0;
    int _eopts = 0;

    op = op_str;

    if (op != NULL) {
        while (*op) {
            switch (*op) {
            case 'N':
                _copts |= REG_NOSUB;
                break;
            case 'G':
                _copts |= REG_UNGREEDY;
                break;

            case 'f':
                _copts |= REG_UTF;
                break;
            case 'p':
                _copts |= REG_UCP;
                break;
            case 'i':
                _copts |= REG_ICASE;
                break;
            case 'm':
                _copts |= REG_NEWLINE;
                break;
            case 's':
                _copts |= REG_DOTALL;
                break;
            case 'x':
                _copts |= REG_EXTENDED;
                break;

            case '1':
                _eopts |= REG_NOTBOL;
                break;
            case '2':
                _eopts |= REG_NOTEOL;
                break;
            case '3':
                _eopts |= REG_NOTEMPTY;
                break;

            default:
                pr_info("%s: unknown regex modifier '%c'",
                     __func__, *op);
                break;
            }
            op++;
        }
    }

    *copts = _copts;
    *eopts = _eopts;
}


static struct ts_config *regex_init(const void *pattern, unsigned int len,
				    gfp_t gfp_mask, int flags)
{
	struct ts_config *conf = ERR_PTR(-EINVAL);
	struct ts_regex regex;
	size_t priv_size = sizeof(struct ts_regex);
	int rc;

	pr_debug("%s: |%s|", __func__, (char *)pattern);

	regex.copts = REG_EXTENDED;
	regex.eopts = 0;
	regex.patlen = len;
	regex.pattern = calloc(len + 1, sizeof(u8));

	if (IS_ERR_OR_NULL(regex.pattern)) {
		pr_debug("%s: %s", __func__, "err_pattern");
		goto err_pattern;
	}

	memcpy(regex.pattern, pattern, len);

    rc = pattern_parse((char *)pattern, &regex.regex_str, &regex.op_str);
    if (rc < 0) {
		pr_debug("%s: %s", __func__, "err_pattern_parse");
        goto err_pattern_parse;
	}
	pr_debug("%s: |%s|%s|", __func__, regex.regex_str, regex.op_str);

    opts_parse(regex.op_str, &regex.copts, &regex.eopts);

	rc = regcomp(&regex.re, regex.regex_str, regex.copts);
	if (rc) {
		pr_debug("%s: %s", __func__, "err_regcomp");
		goto err_regcomp;
	}

	conf = alloc_ts_config(priv_size, gfp_mask);
	if (IS_ERR(conf)) {
		goto err_alloc_conf;
	}

	conf->flags = flags;
	memcpy(ts_config_priv(conf), &regex, priv_size);

	return conf;

 err_alloc_conf:
 err_regcomp:
 err_pattern_parse:
 err_pattern:
	free(regex.pattern);

	pr_info("%s failed: it's probably a regex pattern error", __func__);
	return conf;
}

static void regex_destroy(struct ts_config *conf)
{
	struct ts_regex *regex;

	regex = ts_config_priv(conf);

	pr_debug("%s: %s", __func__, regex->pattern);

    if (regex->pattern)
		free(regex->pattern);

    if (regex->regex_str)
		pcre2_substring_free(regex->regex_str);

    if (regex->op_str)
		pcre2_substring_free(regex->op_str);

	regfree(&regex->re);
}

static void *regex_get_pattern(struct ts_config *conf)
{
	struct ts_regex *regex = ts_config_priv(conf);
	return regex->pattern;
}

static unsigned int regex_get_pattern_len(struct ts_config *conf)
{
	struct ts_regex *regex = ts_config_priv(conf);
	return regex->patlen;
}

static struct ts_ops regex_ops = {
	.name = "regex",
	.find = regex_find,
	.init = regex_init,
	.destroy = regex_destroy,
	.get_pattern = regex_get_pattern,
	.get_pattern_len = regex_get_pattern_len,
	.owner = THIS_MODULE,
	.list = LIST_HEAD_INIT(regex_ops.list)
};

static int __init ts_regex_init(void)
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

    return textsearch_register(&regex_ops);
}

static void __exit ts_regex_exit(void)
{
    pr_debug("%s", __func__);

    if (parse_regex)
        pcre2_code_free(parse_regex);

    textsearch_unregister(&regex_ops);
}

module_init(ts_regex_init);
module_exit(ts_regex_exit);
