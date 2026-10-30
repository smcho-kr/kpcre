// SPDX-License-Identifier: GPL-2.0-only
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <netinet/in.h>
#include <linux/netlink.h>
#include <linux/netfilter/nf_tables.h>
#include <libnftnl/expr.h>
#include <libnftnl/rule.h>

int main(void)
{
	struct nftnl_rule *a = nftnl_rule_alloc(), *b = nftnl_rule_alloc();
	struct nftnl_expr *expr = nftnl_expr_alloc("regex"), *decoded;
	struct nftnl_expr_iter *iter;
	struct nlmsghdr *nlh;
	char wire[4096], pattern[257];

	assert(a && b && expr);
	assert(nftnl_expr_set_str(expr, NFTNL_EXPR_REGEX_PATTERN, "") < 0);
	assert(nftnl_expr_set(expr, NFTNL_EXPR_REGEX_PATTERN, "a\0b", 4) < 0);
	assert(nftnl_expr_set(expr, NFTNL_EXPR_REGEX_PATTERN, "abc", 3) < 0);
	memset(pattern, 'a', 256);
	pattern[256] = 0;
	assert(nftnl_expr_set_str(expr, NFTNL_EXPR_REGEX_PATTERN, pattern) < 0);
	pattern[255] = 0;
	assert(nftnl_expr_set_str(expr, NFTNL_EXPR_REGEX_PATTERN, pattern) == 0);
	assert(nftnl_expr_set_str(expr, NFTNL_EXPR_REGEX_PATTERN, "^a\\x00\"b\\\\$") == 0);
	nftnl_rule_add_expr(a, expr);
	nlh = nftnl_nlmsg_build_hdr(wire, NFT_MSG_NEWRULE, AF_INET, 0, 1);
	nftnl_rule_nlmsg_build_payload(nlh, a);
	assert(nftnl_rule_nlmsg_parse(nlh, b) == 0);
	iter = nftnl_expr_iter_create(b);
	assert(iter);
	decoded = nftnl_expr_iter_next(iter);
	assert(decoded);
	assert(!strcmp(nftnl_expr_get_str(decoded, NFTNL_EXPR_REGEX_PATTERN),
		       "^a\\x00\"b\\\\$"));
	assert(!nftnl_expr_iter_next(iter));
	nftnl_expr_iter_destroy(iter);
	nftnl_rule_free(a);
	nftnl_rule_free(b);
	puts("NFT_REGEX_LIBNFTNL_PASSED");
	return 0;
}
