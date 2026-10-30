// SPDX-License-Identifier: GPL-2.0-only
/* Load only in a disposable VM; exercise the production native evaluator. */
#define NFT_REGEX_TEST
#include "../../nft_regex/nft_regex.c"
#include <net/netfilter/nf_conntrack_zones.h>

static struct nft_expr *expression;
static bool live;
static int checks;
static struct nft_ctx context = { .net = &init_net, .family = NFPROTO_INET };

static void clear_rule(void)
{
	if (live)
		nft_regex_destroy(&context, expression);
	live = false;
}

static int create_rule(struct nft_expr *expr, const char *pattern)
{
	struct sk_buff *attrs;
	const struct nlattr *tb[NFTA_REGEX_MAX + 1] = {};
	int result;

	attrs = alloc_skb(512, GFP_KERNEL);
	if (!attrs)
		return -ENOMEM;
	result = nla_put_string(attrs, NFTA_REGEX_PATTERN, pattern);
	if (!result) {
		tb[NFTA_REGEX_PATTERN] = (const void *)attrs->data;
		result = nft_regex_init(&context, expr, tb);
	}
	kfree_skb(attrs);
	return result;
}

static int set_rule(const char *pattern)
{
	int result;

	clear_rule();
	memset(expression, 0, NFT_EXPR_SIZE(sizeof(struct nft_regex)));
	result = create_rule(expression, pattern);
	live = !result;
	return result;
}

static struct nf_conn *connection(unsigned int port)
{
	struct nf_conntrack_tuple a = {}, b = {};
	struct nf_conn *ct;

	a.src.l3num = b.src.l3num = NFPROTO_IPV4;
	a.dst.protonum = b.dst.protonum = IPPROTO_TCP;
	a.src.u.tcp.port = htons(port);
	b.dst.u.tcp.port = htons(port);
	ct = nf_conntrack_alloc(&init_net, &nf_ct_zone_dflt, &a, &b, GFP_KERNEL);
	if (!IS_ERR(ct))
		refcount_set(&ct->ct_general.use, 1);
	return ct;
}

static int send_to_rule(struct nft_expr *expr, struct nf_conn *ct, unsigned int direction, u32 seq,
		       const void *data, unsigned int length, unsigned int flags,
		       bool nonlinear, bool udp)
{
	struct sk_buff *skb;
	struct nf_hook_state state = { .pf = NFPROTO_IPV4 };
	struct nft_pktinfo pkt = { .state = &state, .flags = NFT_PKTINFO_L4PROTO,
		.thoff = sizeof(struct iphdr), .tprot = udp ? IPPROTO_UDP : IPPROTO_TCP };
	struct nft_regs regs = { .verdict.code = NFT_CONTINUE };
	unsigned int head = nonlinear ? length / 2 : length;
	unsigned int transport = udp ? sizeof(struct udphdr) : sizeof(struct tcphdr);
	struct iphdr *ip;

	skb = alloc_skb(sizeof(*ip) + transport + head, GFP_KERNEL);
	if (!skb)
		return -ENOMEM;
	ip = skb_put_zero(skb, sizeof(*ip));
	skb_reset_network_header(skb);
	ip->version = 4;
	ip->ihl = 5;
	ip->tot_len = htons(sizeof(*ip) + transport + length);
	ip->protocol = pkt.tprot;
	if (udp) {
		struct udphdr *header = skb_put_zero(skb, transport);
		header->len = htons(transport + length);
	} else {
		struct tcphdr *header = skb_put_zero(skb, transport);
		header->doff = 5;
		header->seq = htonl(seq);
		header->syn = !!(flags & 1);
		header->fin = !!(flags & 2);
		header->rst = !!(flags & 4);
	}
	if (head)
		skb_put_data(skb, data, head);
	if (head < length) {
		struct page *page = alloc_page(GFP_KERNEL);
		if (!page || length - head > PAGE_SIZE) {
			if (page)
				__free_page(page);
			kfree_skb(skb);
			return -ENOMEM;
		}
		memcpy(page_address(page), (const u8 *)data + head, length - head);
		skb_add_rx_frag(skb, 0, page, 0, length - head, PAGE_SIZE);
	}
	if (ct) {
		nf_conntrack_get(&ct->ct_general);
		nf_ct_set(skb, ct, direction ? IP_CT_ESTABLISHED_REPLY : IP_CT_ESTABLISHED);
	}
	pkt.skb = skb;
	nft_regex_eval(expr, &regs, &pkt);
	kfree_skb(skb);
	return regs.verdict.code;
}

#define CHECK(value) do { \
	checks++; \
	if (!(value)) { \
		pr_err("nft_regex_window_test: FAIL line %d: %s\n", __LINE__, #value); \
		error = -EINVAL; \
		goto out; \
	} \
} while (0)
#define send_packet(...) send_to_rule(expression, __VA_ARGS__)
#define TCP(ct, dir, seq, data, len, flags) \
	send_packet(ct, dir, seq, data, len, flags, true, false)

static int __init window_test_init(void)
{
	struct nf_conn *first = NULL, *second = NULL;
	struct nft_base_chain base = { .chain.flags = NFT_CHAIN_BASE };
	struct nft_ctx validation = context;
	struct regex_flow *flow;
	struct nft_regex *priv;
	struct nft_expr *other = NULL;
	bool other_live = false;
	struct sk_buff *dump = NULL;
	char pattern[64];
	const char *letters = "abcdefghi";
	char *full = NULL;
	unsigned int n, i;
	int error;

	error = nf_ct_netns_get(&init_net, NFPROTO_INET);
	if (error)
		return error;
	expression = kzalloc(NFT_EXPR_SIZE(sizeof(struct nft_regex)), GFP_KERNEL);
	other = kzalloc(NFT_EXPR_SIZE(sizeof(struct nft_regex)), GFP_KERNEL);
	first = connection(1100);
	second = connection(1101);
	full = kmalloc(NFT_REGEX_PAYLOAD_MAX, GFP_KERNEL);
	dump = alloc_skb(512, GFP_KERNEL);
	CHECK(expression && other && full && dump && !IS_ERR(first) && !IS_ERR(second));
	memset(full, 'a', NFT_REGEX_PAYLOAD_MAX);
	window_packets = 0;
	CHECK(regex_alloc_cpus() == -EINVAL);
	window_packets = REGEX_MAX_WINDOW + 1;
	CHECK(regex_alloc_cpus() == -EINVAL);
	for (n = 1; n <= REGEX_MAX_WINDOW; n++) {
		clear_rule();
		CHECK(!atomic_read(&regex_flows));
		regex_free_cpus();
		window_packets = n;
		CHECK(!regex_alloc_cpus());
		snprintf(pattern, sizeof(pattern), "%.*s|%.*s", n, letters, n, letters + 1);
		CHECK(!set_rule(pattern));
		skb_trim(dump, 0);
		CHECK(!nft_regex_dump(dump, expression, false));
		CHECK(!strcmp(nla_data((struct nlattr *)dump->data), pattern));
		validation.chain = &base.chain;
		base.ops.hooknum = NF_INET_LOCAL_OUT;
		CHECK(!nft_regex_validate(&validation, expression));
		base.ops.hooknum = NF_INET_PRE_ROUTING;
		CHECK((nft_regex_validate(&validation, expression) == 0) == (n == 1));
		for (i = 0; i <= n; i++) {
			u32 seq = 0xfffffffcU + i;
			int expected = i + 1 >= n ? NFT_CONTINUE : NFT_BREAK;
			CHECK(TCP(first, 0, seq, letters + i, 1, 0) == expected);
			CHECK(TCP(first, 0, seq, letters + i, 1, 0) == expected);
			CHECK(TCP(first, 0, seq + 1, "", 0, 0) == NFT_BREAK);
		}
		CHECK(TCP(first, 0, 0xfffffffcU + n + 1, "X", 1, 0) == NFT_BREAK);
		snprintf(pattern, sizeof(pattern), "%.*s", n + 1, letters);
		CHECK(!set_rule(pattern));
		for (i = 0; i <= n; i++)
			CHECK(TCP(first, 0, 100 + i, letters + i, 1, 0) == NFT_BREAK);
		/* Full-size windows and eviction use the entire per-CPU search buffer. */
		snprintf(pattern, sizeof(pattern), "^(?:a{%u}){%u}$", NFT_REGEX_PAYLOAD_MAX, n);
		CHECK(!set_rule(pattern));
		for (i = 0; i < n + 3; i++)
			CHECK(send_packet(first, 0, 100 + i * NFT_REGEX_PAYLOAD_MAX, full,
				NFT_REGEX_PAYLOAD_MAX, 0, false, false) ==
			      (i + 1 >= n ? NFT_CONTINUE : NFT_BREAK));
		CHECK(!set_rule("abc"));
		CHECK(send_packet(NULL, 0, 100, "abc", 3, 0, true, true) == NFT_CONTINUE);
		CHECK(send_packet(NULL, 0, 100, "a", 1, 0, true, true) == NFT_BREAK);
		CHECK(send_packet(NULL, 0, 101, "bc", 2, 0, true, true) == NFT_BREAK);
		CHECK(TCP(NULL, 0, 100, "abc", 3, 0) == (n > 1 ? NF_DROP : NFT_CONTINUE));
		if (n == 1) {
			CHECK(!set_rule("a(?C254)"));
			CHECK(TCP(NULL, 0, 100, "a", 1, 0) == NFT_CONTINUE);
			CHECK(!set_rule("(*ACCEPT)"));
			continue;
		}
		CHECK(set_rule("(*ACCEPT)") == -EINVAL);
		CHECK(set_rule("(?C254)") == -EINVAL);
		CHECK(set_rule("a)|(?:b") == -EINVAL);
		CHECK(!set_rule("abcdef"));
		CHECK(TCP(first, 0, 100, "abc", 3, 0) == NFT_BREAK);
		CHECK(!create_rule(other, "abcdef"));
		other_live = true;
		CHECK(send_to_rule(other, first, 0, 103, "def", 3, 0, true, false) == NFT_BREAK);
		CHECK(TCP(first, 0, 103, "def", 3, 0) == NFT_CONTINUE);
		nft_regex_destroy(&context, other);
		other_live = false;
		CHECK(!set_rule("abc|abcdef"));
		CHECK(TCP(first, 0, 100, "abc", 3, 0) == NFT_CONTINUE);
		CHECK(TCP(first, 0, 103, "def", 3, 0) == NFT_CONTINUE);
		CHECK(!set_rule("abc"));
		CHECK(TCP(first, 0, 100, "abc", 3, 0) == NFT_CONTINUE);
		CHECK(TCP(first, 0, 103, "xyz", 3, 0) == NFT_BREAK);
		CHECK(!set_rule("abcdef"));
		CHECK(TCP(first, 0, 100, "abc", 3, 0) == NFT_BREAK);
		CHECK(TCP(first, 1, 103, "def", 3, 0) == NFT_BREAK);
		CHECK(TCP(second, 0, 103, "def", 3, 0) == NFT_BREAK);
		CHECK(TCP(first, 0, 103, "def", 3, 2) == NFT_CONTINUE);
		CHECK(TCP(first, 0, 103, "def", 3, 2) == NFT_CONTINUE);
		CHECK(TCP(first, 0, 103, "xxx", 3, 0) == NFT_BREAK);
		CHECK(TCP(first, 0, 200, "abc", 3, 0) == NFT_BREAK);
		CHECK(TCP(first, 0, 204, "def", 3, 0) == NFT_BREAK);
		CHECK(TCP(first, 0, 300, "def", 3, 0) == NFT_BREAK);
		CHECK(TCP(first, 0, 297, "abc", 3, 0) == NFT_BREAK);
		CHECK(TCP(first, 0, 300, "def", 3, 0) == NFT_CONTINUE);
		CHECK(TCP(first, 0, 400, "abc", 3, 0) == NFT_BREAK);
		CHECK(TCP(first, 0, 402, "def", 3, 1) == NFT_BREAK);
		CHECK(TCP(first, 0, 500, "abc", 3, 0) == NFT_BREAK);
		CHECK(TCP(first, 0, 503, "", 0, 4) == NFT_BREAK);
		CHECK(TCP(first, 0, 503, "def", 3, 0) == NFT_BREAK);
		CHECK(TCP(first, 0, 600, "abc", 3, 0) == NFT_BREAK);
		CHECK(TCP(first, 0, 603, "", 0, 2) == NFT_BREAK);
		CHECK(TCP(first, 0, 603, "def", 3, 0) == NFT_BREAK);
		CHECK(!set_rule("(?<=abc)def"));
		CHECK(TCP(first, 0, 100, "abc", 3, 0) == NFT_BREAK);
		CHECK(TCP(first, 0, 103, "def", 3, 0) == NFT_CONTINUE);
		CHECK(!set_rule("abc\\x00def"));
		CHECK(TCP(first, 0, 100, "abc\0", 4, 0) == NFT_BREAK);
		CHECK(TCP(first, 0, 104, "def", 3, 0) == NFT_CONTINUE);
		CHECK(!set_rule("abc(?=def)"));
		CHECK(TCP(first, 0, 100, "abc", 3, 0) == NFT_BREAK);
		CHECK(TCP(first, 0, 103, "def", 3, 0) == NFT_BREAK);
		CHECK(!set_rule("^(a+)+$"));
		CHECK(TCP(first, 0, 100, full, 100, 0) == NFT_CONTINUE);
		full[100] = '!';
		CHECK(TCP(first, 0, 200, full, 101, 0) == NF_DROP);
		full[100] = 'a';
		CHECK(!atomic_read(&regex_flows));
		CHECK(!set_rule("abcdef"));
		max_flows = 1;
		CHECK(TCP(first, 0, 100, "abc", 3, 0) == NFT_BREAK);
		CHECK(TCP(second, 0, 100, "abc", 3, 0) == NF_DROP);
		priv = nft_expr_priv(expression);
		for (i = 0; i < REGEX_BUCKETS; i++) {
			spin_lock_bh(&priv->window->buckets[i].lock);
			hlist_for_each_entry(flow, &priv->window->buckets[i].flows, node)
				flow->seen = jiffies - idle_seconds * HZ;
			spin_unlock_bh(&priv->window->buckets[i].lock);
		}
		mod_delayed_work(system_wq, &priv->window->gc, 0);
		flush_delayed_work(&priv->window->gc);
		CHECK(!atomic_read(&regex_flows));
		CHECK(TCP(second, 0, 103, "def", 3, 0) == NFT_BREAK);
		max_flows = 4096;
	}
	clear_rule();
	CHECK(!atomic_read(&regex_flows));
	pr_info("nft_regex_window_test: PASS (%d checks, N=1..8)\n", checks);
	error = 0;
out:
	if (other_live)
		nft_regex_destroy(&context, other);
	kfree(other);
	clear_rule();
	kfree(expression);
	kfree(full);
	kfree_skb(dump);
	if (!IS_ERR_OR_NULL(first))
		nf_conntrack_put(&first->ct_general);
	if (!IS_ERR_OR_NULL(second))
		nf_conntrack_put(&second->ct_general);
	regex_free_cpus();
	nf_ct_netns_put(&init_net, NFPROTO_INET);
	return error;
}

static void __exit window_test_exit(void) {}
module_init(window_test_init);
module_exit(window_test_exit);
