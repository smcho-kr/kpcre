// SPDX-License-Identifier: GPL-2.0-only
/* Load only inside the disposable test VM. */
#define NFT_REGEX_TEST
#include "../../nft_regex/nft_regex.c"

static int checks;
#define CHECK(condition) do { \
	checks++; \
	if (!(condition)) { \
		pr_err("nft_regex_test: FAIL at line %d\n", __LINE__); \
		error = -EINVAL; \
		goto out; \
	} \
} while (0)

static int init_rule(struct nft_expr *expr, const char *pattern)
{
	struct nft_ctx ctx = { .family = NFPROTO_INET };
	const struct nlattr *tb[NFTA_REGEX_MAX + 1] = {};
	struct sk_buff *attrs = alloc_skb(512, GFP_KERNEL);
	int error;

	if (!attrs)
		return -ENOMEM;
	if (pattern) {
		if (nla_put_string(attrs, NFTA_REGEX_PATTERN, pattern)) {
			kfree_skb(attrs);
			return -EMSGSIZE;
		}
		tb[NFTA_REGEX_PATTERN] = (const void *)attrs->data;
	}
	error = nft_regex_init(&ctx, expr, tb);
	kfree_skb(attrs);
	return error;
}

static struct sk_buff *packet(u8 family, u8 proto, unsigned int length, bool nonlinear)
{
	unsigned int ip_len = family == NFPROTO_IPV4 ? sizeof(struct iphdr) : sizeof(struct ipv6hdr);
	unsigned int transport = proto == IPPROTO_TCP ? sizeof(struct tcphdr) : sizeof(struct udphdr);
	struct sk_buff *skb = alloc_skb(ip_len + transport + length, GFP_KERNEL);

	if (!skb)
		return NULL;
	skb_put_zero(skb, ip_len + transport);
	skb_reset_network_header(skb);
	skb_set_transport_header(skb, ip_len);
	if (family == NFPROTO_IPV4) {
		struct iphdr *ip = ip_hdr(skb);

		ip->version = 4;
		ip->ihl = 5;
		ip->tot_len = htons(ip_len + transport + length);
		ip->protocol = proto;
	} else {
		struct ipv6hdr *ip = ipv6_hdr(skb);

		ip->version = 6;
		ip->payload_len = htons(transport + length);
		ip->nexthdr = proto;
	}
	if (proto == IPPROTO_TCP)
		tcp_hdr(skb)->doff = 5;
	else
		udp_hdr(skb)->len = htons(transport + length);
	if (nonlinear && length) {
		struct page *page = alloc_page(GFP_KERNEL);

		if (!page || length > PAGE_SIZE) {
			if (page)
				__free_page(page);
			kfree_skb(skb);
			return NULL;
		}
		memset(page_address(page), 'A', length);
		skb_add_rx_frag(skb, 0, page, 0, length, PAGE_SIZE);
	} else {
		memset(skb_put(skb, length), 'A', length);
	}
	return skb;
}

static u32 evaluate(struct nft_expr *expr, struct sk_buff *skb, u8 family, u8 proto)
{
	struct nf_hook_state state = { .pf = family };
	struct nft_pktinfo pkt = {
		.skb = skb, .state = &state, .flags = NFT_PKTINFO_L4PROTO,
		.tprot = proto, .thoff = skb_transport_offset(skb),
	};
	struct nft_regs regs = { .verdict.code = NFT_CONTINUE };

	nft_regex_eval(expr, &regs, &pkt);
	return regs.verdict.code;
}

static struct sk_buff *add_ipv6_extension(struct sk_buff *old, u8 type)
{
	struct sk_buff *skb = skb_copy_expand(old, 0, 8, GFP_KERNEL);
	struct ipv6_opt_hdr *extension;

	kfree_skb(old);
	if (!skb)
		return NULL;
	skb_put(skb, 8);
	memmove(skb->data + 48, skb->data + 40, skb->len - 48);
	memset(skb->data + 40, 0, 8);
	extension = (void *)(skb->data + 40);
	extension->nexthdr = ipv6_hdr(skb)->nexthdr;
	ipv6_hdr(skb)->nexthdr = type;
	ipv6_hdr(skb)->payload_len = htons(ntohs(ipv6_hdr(skb)->payload_len) + 8);
	skb_set_transport_header(skb, 48);
	return skb;
}

static int __init regex_test_init(void)
{
	struct nft_expr *expr = NULL;
	struct sk_buff *skb = NULL, *dump = NULL;
	struct nft_ctx ctx = { .family = NFPROTO_INET };
	char pattern[NFT_REGEX_PATTERN_MAX + 2];
	u8 families[] = { NFPROTO_IPV4, NFPROTO_IPV6 };
	u8 protocols[] = { IPPROTO_TCP, IPPROTO_UDP };
	bool live = false;
	int i, j, error;

	error = regex_alloc_cpus();
	if (error)
		return error;
	expr = kzalloc(NFT_EXPR_SIZE(sizeof(struct nft_regex)), GFP_KERNEL);
	CHECK(expr);
	CHECK(init_rule(expr, NULL) == -EINVAL);
	CHECK(init_rule(expr, "") == -EINVAL);
	CHECK(init_rule(expr, "[") == -EINVAL);
	CHECK(init_rule(expr, "(*UTF)abc") == -EINVAL);
	memset(pattern, 'A', sizeof(pattern) - 1);
	pattern[sizeof(pattern) - 1] = 0;
	CHECK(init_rule(expr, pattern) == -EINVAL);
	pattern[NFT_REGEX_PATTERN_MAX] = 0;
	CHECK(init_rule(expr, pattern) == 0);
	live = true;
	CHECK(nft_regex_validate(&ctx, expr) == 0);
	nft_regex_destroy(&ctx, expr);
	live = false;
	CHECK(init_rule(expr, "^(A+)\\x00B$") == 0);
	live = true;
	dump = alloc_skb(512, GFP_KERNEL);
	CHECK(dump && nft_regex_dump(dump, expr, false) == 0);
	CHECK(!strcmp(nla_data((struct nlattr *)dump->data), "^(A+)\\x00B$"));
	for (i = 0; i < ARRAY_SIZE(families); i++) {
		for (j = 0; j < ARRAY_SIZE(protocols); j++) {
			skb = packet(families[i], protocols[j], 5, true);
			CHECK(skb);
			CHECK(evaluate(expr, skb, families[i], protocols[j]) == NFT_BREAK);
			((char *)page_address(skb_frag_page(&skb_shinfo(skb)->frags[0])))[3] = 0;
			((char *)page_address(skb_frag_page(&skb_shinfo(skb)->frags[0])))[4] = 'B';
			CHECK(evaluate(expr, skb, families[i], protocols[j]) == NFT_CONTINUE);
			kfree_skb(skb);
			skb = NULL;
		}
	}
	nft_regex_destroy(&ctx, expr);
	live = false;
	CHECK(init_rule(expr, "^A+$") == 0);
	live = true;
	skb = packet(NFPROTO_IPV6, IPPROTO_TCP, 8, false);
	CHECK(skb);
	skb = add_ipv6_extension(skb, IPPROTO_HOPOPTS);
	CHECK(skb);
	CHECK(evaluate(expr, skb, NFPROTO_IPV6, IPPROTO_TCP) == NFT_CONTINUE);
	kfree_skb(skb);
	skb = packet(NFPROTO_IPV6, IPPROTO_UDP, 8, false);
	CHECK(skb);
	skb = add_ipv6_extension(skb, IPPROTO_FRAGMENT);
	CHECK(skb);
	CHECK(evaluate(expr, skb, NFPROTO_IPV6, IPPROTO_UDP) == NF_DROP);
	kfree_skb(skb);
	skb = packet(NFPROTO_IPV4, IPPROTO_TCP, NFT_REGEX_PAYLOAD_MAX, false);
	CHECK(skb);
	CHECK(evaluate(expr, skb, NFPROTO_IPV4, IPPROTO_TCP) == NFT_CONTINUE);
	ip_hdr(skb)->frag_off = htons(IP_MF);
	CHECK(evaluate(expr, skb, NFPROTO_IPV4, IPPROTO_TCP) == NF_DROP);
	ip_hdr(skb)->frag_off = 0;
	tcp_hdr(skb)->doff = 4;
	CHECK(evaluate(expr, skb, NFPROTO_IPV4, IPPROTO_TCP) == NF_DROP);
	tcp_hdr(skb)->doff = 15;
	CHECK(evaluate(expr, skb, NFPROTO_IPV4, IPPROTO_TCP) == NFT_CONTINUE);
	ip_hdr(skb)->tot_len = htons(10);
	CHECK(evaluate(expr, skb, NFPROTO_IPV4, IPPROTO_TCP) == NF_DROP);
	kfree_skb(skb);
	skb = packet(NFPROTO_IPV6, IPPROTO_UDP, NFT_REGEX_PAYLOAD_MAX + 1, false);
	CHECK(skb);
	CHECK(evaluate(expr, skb, NFPROTO_IPV6, IPPROTO_UDP) == NF_DROP);
	udp_hdr(skb)->len = htons(sizeof(struct udphdr) + 2);
	CHECK(evaluate(expr, skb, NFPROTO_IPV6, IPPROTO_UDP) == NFT_CONTINUE);
	udp_hdr(skb)->len = htons(7);
	CHECK(evaluate(expr, skb, NFPROTO_IPV6, IPPROTO_UDP) == NF_DROP);
	kfree_skb(skb);
	skb = packet(NFPROTO_IPV4, IPPROTO_TCP, 0, false);
	CHECK(skb);
	CHECK(evaluate(expr, skb, NFPROTO_IPV4, IPPROTO_TCP) == NFT_BREAK);
	kfree_skb(skb);
	skb = NULL;
	nft_regex_destroy(&ctx, expr);
	live = false;
	CHECK(init_rule(expr, "(?=A)") == 0);
	live = true;
	skb = packet(NFPROTO_IPV4, IPPROTO_TCP, 1, false);
	CHECK(skb);
	CHECK(evaluate(expr, skb, NFPROTO_IPV4, IPPROTO_TCP) == NFT_BREAK);
	kfree_skb(skb);
	skb = NULL;
	nft_regex_destroy(&ctx, expr);
	live = false;
	CHECK(init_rule(expr, "^(A+)+$") == 0);
	live = true;
	skb = packet(NFPROTO_IPV4, IPPROTO_TCP, 1000, false);
	CHECK(skb);
	skb->data[skb->len - 1] = 'B';
	CHECK(evaluate(expr, skb, NFPROTO_IPV4, IPPROTO_TCP) == NF_DROP);
	error = 0;
	pr_info("nft_regex_test: PASS (%d checks)\n", checks);
out:
	if (live)
		nft_regex_destroy(&ctx, expr);
	kfree_skb(skb);
	kfree_skb(dump);
	kfree(expr);
	regex_free_cpus();
	return error;
}

static void __exit regex_test_exit(void) {}
module_init(regex_test_init);
module_exit(regex_test_exit);
