// SPDX-License-Identifier: GPL-2.0
/* Load only in a disposable VM. Exercise the production matcher with real skbs. */
#define IDS_TEST
#include "../xt_ids/xt_ids.c"
#include <net/netfilter/nf_conntrack_zones.h>
#include <linux/completion.h>
#include <linux/kthread.h>

static struct xt_ids_info test_info;
static bool test_ready;

static void clear_rule(void)
{
	struct xt_mtdtor_param par = {
		.net = &init_net, .family = NFPROTO_IPV4, .matchinfo = &test_info,
	};
	if (test_ready)
		ids_destroy(&par);
	test_ready = false;
}

static int set_rule(const char *pattern)
{
	struct xt_mtchk_param par = {
		.net = &init_net, .family = NFPROTO_IPV4, .matchinfo = &test_info,
	};
	int error;
	clear_rule();
	memset(&test_info, 0, sizeof(test_info));
	strscpy(test_info.regex, pattern, sizeof(test_info.regex));
	error = ids_check(&par);
	test_ready = !error;
	return error;
}

static struct nf_conn *new_connection(unsigned int port)
{
	struct nf_conntrack_tuple original = {}, reply = {};
	struct nf_conn *ct;
	original.src.l3num = reply.src.l3num = NFPROTO_IPV4;
	original.dst.protonum = reply.dst.protonum = IPPROTO_TCP;
	original.src.u.tcp.port = htons(port);
	reply.dst.u.tcp.port = htons(port);
	ct = nf_conntrack_alloc(&init_net, &nf_ct_zone_dflt, &original, &reply, GFP_KERNEL);
	if (!IS_ERR(ct))
		refcount_set(&ct->ct_general.use, 1);
	return ct;
}

static int packet(struct nf_conn *ct, unsigned int direction, u32 seq,
		  const char *data, unsigned int length, unsigned int flags,
		  bool nonlinear)
{
	struct sk_buff *skb;
	struct tcphdr *tcp;
	struct xt_action_param par = { .matchinfo = &test_info };
	unsigned int head = nonlinear ? length / 2 : length;
	bool matched;

	skb = alloc_skb(sizeof(*tcp) + head, GFP_KERNEL);
	if (!skb)
		return -ENOMEM;
	tcp = skb_put_zero(skb, sizeof(*tcp));
	tcp->doff = flags & 8 ? 1 : 5;
	tcp->seq = htonl(seq);
	tcp->syn = !!(flags & 1);
	tcp->fin = !!(flags & 2);
	tcp->rst = !!(flags & 4);
	if (head)
		skb_put_data(skb, data, head);
	if (head < length) {
		struct page *page = alloc_page(GFP_KERNEL);
		if (!page) {
			kfree_skb(skb);
			return -ENOMEM;
		}
		memcpy(page_address(page), data + head, length - head);
		skb_add_rx_frag(skb, 0, page, 0, length - head, PAGE_SIZE);
	}
	if (ct) {
		nf_conntrack_get(&ct->ct_general);
		nf_ct_set(skb, ct, direction ? IP_CT_ESTABLISHED_REPLY : IP_CT_ESTABLISHED);
	}
	matched = ids_match(skb, &par);
	kfree_skb(skb);
	return par.hotdrop ? -EPERM : matched;
}

struct concurrent_test {
	struct completion started;
	struct completion *go;
	struct nf_conn *ct;
	unsigned int direction;
};

static int concurrent_packets(void *data)
{
	struct concurrent_test *test = data;
	unsigned int i;

	complete(&test->started);
	wait_for_completion(test->go);
	for (i = 0; i < 128; i++) {
		if (packet(test->ct, test->direction, 1000 + i * 6, "abc", 3, 0, true) != 0 ||
		    packet(test->ct, test->direction, 1003 + i * 6, "def", 3, 0, true) != 1)
			return -EINVAL;
	}
	return 0;
}

static int concurrent_test(struct nf_conn *first, struct nf_conn *second)
{
	DECLARE_COMPLETION_ONSTACK(go);
	struct concurrent_test tests[2];
	struct task_struct *tasks[2];
	unsigned int i, count = 0;
	int error = 0;

	for (i = 0; i < 2; i++) {
		init_completion(&tests[i].started);
		tests[i].go = &go;
		tests[i].ct = i ? second : first;
		tests[i].direction = i;
		tasks[i] = kthread_run(concurrent_packets, &tests[i], "kpcre_ids_%u", i);
		if (IS_ERR(tasks[i])) {
			error = PTR_ERR(tasks[i]);
			break;
		}
		count++;
		/* The callback must start before kthread_stop, which otherwise skips it. */
		wait_for_completion(&tests[i].started);
		get_task_struct(tasks[i]);
	}
	complete_all(&go);
	for (i = 0; i < count; i++) {
		if (kthread_stop(tasks[i]))
			error = -EINVAL;
		put_task_struct(tasks[i]);
	}
	return error;
}

#define CHECK(expression) do { \
	if (!(expression)) { \
		pr_err("kpcre_ids_test: FAIL at line %d: %s\n", __LINE__, #expression); \
		error = -EINVAL; \
		goto out; \
	} \
} while (0)

static int __init ids_test_init(void)
{
	struct nf_conn *first = NULL, *second = NULL;
	struct ids_rule *rule;
	struct ids_flow *flow;
	char oversized[513];
	char pattern[64];
	const char *letters = "abcdefghi";
	unsigned int i, n;
	int error;

	payload_limit = 512;
	max_flows = 8;
	window_packets = 0;
	if (ids_alloc_cpus() != -EINVAL)
		return -EINVAL;
	window_packets = IDS_MAX_WINDOW + 1;
	if (ids_alloc_cpus() != -EINVAL)
		return -EINVAL;
	window_packets = 2;
	error = ids_alloc_cpus();
	if (error)
		return error;
	error = nf_ct_netns_get(&init_net, NFPROTO_IPV4);
	if (error) {
		ids_free_cpus();
		return error;
	}
	first = new_connection(1000);
	second = new_connection(1001);
	CHECK(!IS_ERR(first) && !IS_ERR(second));
	CHECK(!set_rule("abcdef|ghijkl"));
	CHECK(packet(first, 0, 100, "abc", 3, 0, false) == 0);
	CHECK(packet(first, 0, 103, "", 0, 0, false) == 0);
	CHECK(packet(first, 1, 103, "def", 3, 0, false) == 0);
	CHECK(packet(second, 0, 103, "def", 3, 0, false) == 0);
	CHECK(packet(first, 0, 103, "defghi", 6, 0, true) == 1);
	CHECK(packet(first, 0, 103, "defghi", 6, 0, false) == 1);
	CHECK(packet(first, 0, 109, "jkl", 3, 0, false) == 1);
	CHECK(packet(first, 0, 112, "xyz", 3, 0, false) == 0);
	CHECK(!set_rule("abcdef"));
	CHECK(packet(first, 0, 100, "ab", 2, 0, false) == 0);
	CHECK(packet(first, 0, 102, "cd", 2, 0, false) == 0);
	CHECK(packet(first, 0, 104, "ef", 2, 0, false) == 0);
	CHECK(packet(first, 0, 200, "abc", 3, 0, false) == 0);
	CHECK(packet(first, 0, 204, "def", 3, 0, false) == 0);
	CHECK(packet(first, 0, 300, "def", 3, 0, false) == 0);
	CHECK(packet(first, 0, 297, "abc", 3, 0, false) == 0);
	CHECK(packet(first, 0, 0xfffffffeU, "ab", 2, 0, false) == 0);
	CHECK(packet(first, 0, 0, "cdef", 4, 0, false) == 1);
	CHECK(packet(first, 0, 0, "xxxx", 4, 0, false) == 0);
	CHECK(!set_rule("abc|abcdef"));
	CHECK(packet(first, 0, 100, "abc", 3, 0, false) == 1);
	CHECK(packet(first, 0, 103, "def", 3, 0, false) == 1);
	CHECK(!set_rule("abc"));
	CHECK(packet(first, 0, 100, "abc", 3, 0, false) == 1);
	CHECK(packet(first, 0, 103, "def", 3, 0, false) == 0);
	CHECK(!set_rule("(?<=abc)def"));
	CHECK(packet(first, 0, 100, "abc", 3, 0, false) == 0);
	CHECK(packet(first, 0, 103, "def", 3, 2, false) == 1);
	CHECK(packet(first, 0, 103, "def", 3, 2, false) == 1);
	CHECK(!set_rule("abc\\x00def"));
	CHECK(packet(first, 0, 100, "abc\0", 4, 0, true) == 0);
	CHECK(packet(first, 0, 104, "def", 3, 0, true) == 1);
	CHECK(!set_rule("(abc)(def)"));
	CHECK(packet(first, 0, 100, "abc", 3, 0, false) == 0);
	CHECK(packet(first, 0, 103, "def", 3, 0, false) == 1);
	CHECK(!set_rule("a*"));
	CHECK(packet(first, 0, 100, "bbb", 3, 0, false) == 0);
	CHECK(!set_rule("abcdef"));
	CHECK(packet(first, 0, 100, "abc", 3, 0, false) == 0);
	CHECK(packet(first, 0, 102, "def", 3, 1, false) == 0);
	CHECK(packet(first, 0, 200, "abc", 3, 0, false) == 0);
	CHECK(packet(first, 0, 203, "", 0, 4, false) == 0);
	CHECK(packet(first, 0, 203, "def", 3, 0, false) == 0);
	CHECK(packet(first, 0, 300, "abc", 3, 0, false) == 0);
	CHECK(packet(first, 0, 303, "", 0, 2, false) == 0);
	CHECK(packet(first, 0, 303, "def", 3, 0, false) == 0);
	CHECK(packet(NULL, 0, 100, "abc", 3, 0, false) == -EPERM);
	CHECK(packet(first, 0, 100, "abc", 3, 8, false) == -EPERM);
	memset(oversized, 'a', sizeof(oversized));
	CHECK(packet(first, 0, 100, oversized, sizeof(oversized), 0, false) == -EPERM);
	CHECK(!set_rule("abcdef"));
	max_flows = 1;
	CHECK(packet(first, 0, 100, "abc", 3, 0, false) == 0);
	CHECK(packet(second, 0, 103, "def", 3, 0, false) == -EPERM);
	rule = (void *)(unsigned long)test_info.state;
	for (i = 0; i < IDS_BUCKETS; i++) {
		spin_lock_bh(&rule->buckets[i].lock);
		hlist_for_each_entry(flow, &rule->buckets[i].flows, node)
			flow->seen = jiffies - idle_seconds * HZ;
		spin_unlock_bh(&rule->buckets[i].lock);
	}
	ids_collect(rule, false);
	CHECK(!atomic_read(&ids_flows));
	CHECK(packet(second, 0, 103, "def", 3, 0, false) == 0);
	CHECK(!set_rule("^(a+)+$"));
	memset(oversized, 'a', 100);
	oversized[99] = '!';
	CHECK(packet(first, 0, 100, oversized, 100, 0, false) == -EPERM);
	CHECK(!atomic_read(&ids_flows));
	CHECK(!set_rule("abc(?=def)"));
	CHECK(packet(first, 0, 100, "abc", 3, 0, false) == 0);
	/* Only matches consuming new bytes count; lookahead alone does not. */
	CHECK(packet(first, 0, 103, "def", 3, 0, false) == 0);
	max_flows = 8;
	CHECK(!set_rule("abcdef"));
	CHECK(!concurrent_test(first, first));
	CHECK(!set_rule("abcdef"));
	CHECK(!concurrent_test(first, second));
	CHECK(set_rule("(*ACCEPT)") == -EINVAL);
	CHECK(set_rule("(?C254)") == -EINVAL);
	CHECK(set_rule("abc)|(?:def") == -EINVAL);
	CHECK(set_rule("[") == -EINVAL);
	CHECK(set_rule("(*UTF)a") == -EINVAL);
	CHECK(!atomic_read(&ids_flows));
	for (n = 1; n <= IDS_MAX_WINDOW; n++) {
		clear_rule();
		CHECK(!atomic_read(&ids_flows));
		ids_free_cpus();
		window_packets = n;
		CHECK(!ids_alloc_cpus());
		snprintf(pattern, sizeof(pattern), "%.*s|%.*s", n, letters, n, letters + 1);
		CHECK(!set_rule(pattern));
		for (i = 0; i <= n; i++) {
			u32 seq = 0xfffffffcU + i;
			int expected = i + 1 >= n;
			CHECK(packet(first, 0, seq, letters + i, 1, 0, true) == expected);
			/* Retransmissions and ACKs must not consume window slots. */
			CHECK(packet(first, 0, seq, letters + i, 1, 0, true) == expected);
			CHECK(packet(first, 0, seq + 1, "", 0, 0, false) == 0);
		}
		CHECK(packet(first, 0, 0xfffffffcU + n + 1, "X", 1, 0, false) == 0);
		snprintf(pattern, sizeof(pattern), "%.*s", n + 1, letters);
		CHECK(!set_rule(pattern));
		for (i = 0; i <= n; i++)
			CHECK(packet(first, 0, 100 + i, letters + i, 1, 0, false) == 0);
		/* Fill the entire scratch buffer and repeatedly evict the oldest payload. */
		snprintf(pattern, sizeof(pattern), "^a{%u}$", n * payload_limit);
		CHECK(!set_rule(pattern));
		memset(oversized, 'a', sizeof(oversized));
		for (i = 0; i < n + 3; i++)
			CHECK(packet(first, 0, 100 + i * payload_limit, oversized,
				     payload_limit, 0, true) == (i + 1 >= n));
		if (n >= 3) {
			CHECK(!set_rule("abc"));
			CHECK(packet(first, 0, 100, "a", 1, 0, false) == 0);
			CHECK(packet(first, 0, 101, "b", 1, 0, false) == 0);
			CHECK(packet(first, 0, 103, "c", 1, 0, false) == 0);
			CHECK(packet(first, 0, 200, "a", 1, 0, false) == 0);
			CHECK(packet(first, 0, 201, "b", 1, 0, false) == 0);
			CHECK(packet(first, 0, 202, "c", 1, 2, false) == 1);
			CHECK(packet(first, 0, 202, "c", 1, 2, false) == 1);
		}
	}
	clear_rule();
	CHECK(!atomic_read(&ids_flows));
	pr_info("kpcre_ids_test: PASS (windows 1-8, sliding eviction, isolation, retransmits, binary/nonlinear skbs, limits, cleanup)\n");
	error = 0;
out:
	clear_rule();
	if (!IS_ERR_OR_NULL(first))
		nf_conntrack_put(&first->ct_general);
	if (!IS_ERR_OR_NULL(second))
		nf_conntrack_put(&second->ct_general);
	nf_ct_netns_put(&init_net, NFPROTO_IPV4);
	ids_free_cpus();
	return error;
}

static void __exit ids_test_exit(void) {}
module_init(ids_test_init);
module_exit(ids_test_exit);
