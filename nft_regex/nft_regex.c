// SPDX-License-Identifier: GPL-2.0-only
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/module.h>
#include <linux/percpu.h>
#include <linux/skbuff.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/hash.h>
#include <linux/workqueue.h>
#include <net/netfilter/nf_conntrack.h>
#include <net/ip.h>
#include <net/ipv6.h>
#include <net/netfilter/nf_tables.h>

#include "pcre2.h"
#include "nft_regex.h"

#define REGEX_MAX_WINDOW 8
#define REGEX_HASH_BITS 6
#define REGEX_BUCKETS (1U << REGEX_HASH_BITS)
#define REGEX_GC_INTERVAL (5 * HZ)

static unsigned int window_packets = 1;
module_param(window_packets, uint, 0444);
MODULE_PARM_DESC(window_packets, "Maximum adjacent TCP payloads (1-8; UDP stays per-packet)");
static unsigned int max_flows = 4096;
module_param(max_flows, uint, 0444);
MODULE_PARM_DESC(max_flows, "Maximum cached rule/connection pairs across native regex rules");
static unsigned int idle_seconds = 30;
module_param(idle_seconds, uint, 0444);
MODULE_PARM_DESC(idle_seconds, "Expire cached TCP payloads after this idle interval (1-3600)");

struct regex_payload {
	u8 *data;
	unsigned int len;
};

struct regex_direction {
	struct regex_payload history[REGEX_MAX_WINDOW - 1];
	unsigned int count;
	u32 seq;
	bool matched;
	bool closed;
};

struct regex_flow {
	struct hlist_node node;
	struct nf_conn *ct;
	unsigned long seen;
	struct regex_direction direction[2];
};

struct regex_bucket {
	spinlock_t lock;
	struct hlist_head flows;
};

struct regex_window {
	struct delayed_work gc;
	struct regex_bucket buckets[REGEX_BUCKETS];
};

struct nft_regex {
	pcre2_code *code;
	struct regex_window *window;
	char pattern[NFT_REGEX_PATTERN_MAX + 1];
};

struct regex_cpu {
	pcre2_match_data *data;
	pcre2_match_context *context;
	pcre2_jit_stack *stack;
	u8 *buffer;
	unsigned int boundary, budget;
	bool busy;
};

static struct regex_cpu __percpu *regex_cpus;

static atomic_t regex_flows = ATOMIC_INIT(0);

/* TCP cache ownership and retransmission policy follow xt_ids/xt_ids.c. */
static void regex_clear_direction(struct regex_direction *direction)
{
	unsigned int i;
	for (i = 0; i < direction->count; i++)
		kfree(direction->history[i].data);
	memset(direction, 0, sizeof(*direction));
}

static void regex_free_flow(struct regex_flow *flow)
{
	hlist_del(&flow->node);
	regex_clear_direction(&flow->direction[0]);
	regex_clear_direction(&flow->direction[1]);
	nf_conntrack_put(&flow->ct->ct_general);
	kfree(flow);
	atomic_dec(&regex_flows);
}

static void regex_collect(struct regex_window *rule, bool all)
{
	struct regex_flow *flow;
	struct hlist_node *next;
	unsigned int i;

	for (i = 0; i < REGEX_BUCKETS; i++) {
		struct regex_bucket *bucket = &rule->buckets[i];
		spin_lock_bh(&bucket->lock);
		hlist_for_each_entry_safe(flow, next, &bucket->flows, node)
			if (all || nf_ct_is_dying(flow->ct) ||
			    time_after_eq(jiffies, flow->seen + idle_seconds * HZ))
				regex_free_flow(flow);
		spin_unlock_bh(&bucket->lock);
	}
}

static void regex_gc(struct work_struct *work)
{
	struct regex_window *rule = container_of(to_delayed_work(work), struct regex_window, gc);
	regex_collect(rule, false);
	schedule_delayed_work(&rule->gc, REGEX_GC_INTERVAL);
}

static int regex_callout(pcre2_callout_block *block, void *data)
{
	struct regex_cpu *cpu = data;

	if (!cpu->budget--)
		return PCRE2_ERROR_CALLOUT;
	if (window_packets > 1 && block->callout_number == 254)
		return block->current_position <= cpu->boundary;
	return 0;
}

static int regex_search(const struct nft_regex *priv, struct regex_cpu *cpu,
			const u8 *subject, unsigned int length, unsigned int boundary)
{
	int result;

	cpu->boundary = boundary;
	cpu->budget = NFT_REGEX_WORK_MAX;
	result = pcre2_jit_match(priv->code, subject, length, 0, PCRE2_NOTEMPTY,
				cpu->data, cpu->context);
	if (result >= 0)
		return 1;
	return result == PCRE2_ERROR_NOMATCH ? 0 : result;
}

/* Return 1 for an inspectable payload, 0 for a nonmatch, or a negative error. */
static int regex_payload(const struct nft_pktinfo *pkt, unsigned int *offset,
			 unsigned int *length)
{
	const struct sk_buff *skb = pkt->skb;
	unsigned int network = skb_network_offset(skb), end, thoff = nft_thoff(pkt);
	struct tcphdr tcp;
	struct udphdr udp;
	struct iphdr ip;
	struct ipv6hdr ip6;
	unsigned short fragoff = 0;
	unsigned int found = 0, header_len;
	int flags = 0, proto;

	if (network > skb->len)
		return -EBADMSG;
	if (nft_pf(pkt) == NFPROTO_IPV4) {
		if (skb_copy_bits(skb, network, &ip, sizeof(ip)) ||
		    ip.version != 4 || ip.ihl < 5 ||
		    ntohs(ip.tot_len) < ip.ihl * 4 ||
		    ntohs(ip.tot_len) > skb->len - network)
			return -EBADMSG;
		if (ip.frag_off & htons(IP_MF | IP_OFFSET))
			return -EOPNOTSUPP;
		end = network + ntohs(ip.tot_len);
		if (thoff != network + ip.ihl * 4 || pkt->tprot != ip.protocol)
			return -EBADMSG;
	} else if (nft_pf(pkt) == NFPROTO_IPV6) {
		if (skb_copy_bits(skb, network, &ip6, sizeof(ip6)) ||
		    ip6.version != 6 || !ip6.payload_len ||
		    sizeof(ip6) + ntohs(ip6.payload_len) > skb->len - network)
			return -EBADMSG;
		end = network + sizeof(ip6) + ntohs(ip6.payload_len);
		proto = ipv6_find_hdr(skb, &found, -1, &fragoff, &flags);
		if (proto < 0 || (flags & IP6_FH_F_FRAG) || fragoff)
			return -EOPNOTSUPP;
		if (found != thoff || proto != pkt->tprot)
			return -EBADMSG;
	} else {
		return 0;
	}
	if (!(pkt->flags & NFT_PKTINFO_L4PROTO) || pkt->fragoff)
		return -EBADMSG;
	if (thoff > end)
		return -EBADMSG;
	if (pkt->tprot == IPPROTO_TCP) {
		if (end - thoff < sizeof(tcp) ||
		    skb_copy_bits(skb, thoff, &tcp, sizeof(tcp)) || tcp.doff < 5)
			return -EBADMSG;
		header_len = tcp.doff * 4;
		if (header_len > end - thoff)
			return -EBADMSG;
	} else if (pkt->tprot == IPPROTO_UDP) {
		if (end - thoff < sizeof(udp) ||
		    skb_copy_bits(skb, thoff, &udp, sizeof(udp)) ||
		    ntohs(udp.len) < sizeof(udp) || ntohs(udp.len) > end - thoff)
			return -EBADMSG;
		header_len = sizeof(udp);
		end = thoff + ntohs(udp.len);
	} else {
		return 0;
	}
	*offset = thoff + header_len;
	*length = end - *offset;
	if (*length > NFT_REGEX_PAYLOAD_MAX)
		return -E2BIG;
	return 1;
}

static int regex_tcp_search(const struct nft_regex *priv, struct regex_cpu *cpu,
			    const struct nft_pktinfo *pkt, u8 *payload, unsigned int length)
{
	struct tcphdr header, *tcp = &header;
	struct nf_conn *ct;
	enum ip_conntrack_info ctinfo;
	struct regex_bucket *bucket;
	struct regex_flow *flow = NULL, *candidate;
	struct regex_direction *direction;
	struct regex_payload *last;
	unsigned int i, offset, previous = 0;
	u8 *saved = NULL;
	u32 seq;
	int result = 0;

	if (skb_copy_bits(pkt->skb, nft_thoff(pkt), tcp, sizeof(*tcp)))
		return -EBADMSG;
	ct = nf_ct_get(pkt->skb, &ctinfo);
	if (!ct || nf_ct_is_template(ct) || nf_ct_protonum(ct) != IPPROTO_TCP)
		return -ENOTCONN;
	seq = ntohl(tcp->seq) + tcp->syn;
	bucket = &priv->window->buckets[hash_ptr(ct, REGEX_HASH_BITS)];
	spin_lock(&bucket->lock);
	hlist_for_each_entry(candidate, &bucket->flows, node)
		if (candidate->ct == ct) {
			flow = candidate;
			break;
		}
	if (flow && (tcp->rst || tcp->syn ||
	    time_after_eq(jiffies, flow->seen + idle_seconds * HZ))) {
		regex_free_flow(flow);
		flow = NULL;
	}
	if (tcp->rst)
		goto unlock;
	if (!length) {
		if (flow && tcp->fin)
			flow->direction[CTINFO2DIR(ctinfo)].closed = true;
		goto unlock;
	}
	if (!flow) {
		if (atomic_inc_return(&regex_flows) > max_flows) {
			atomic_dec(&regex_flows);
			result = -ENOSPC;
			goto unlock;
		}
		flow = kzalloc(sizeof(*flow), GFP_ATOMIC);
		if (!flow) {
			atomic_dec(&regex_flows);
			result = -ENOMEM;
			goto unlock;
		}
		flow->ct = ct;
		nf_conntrack_get(&ct->ct_general);
		hlist_add_head(&flow->node, &bucket->flows);
	}
	flow->seen = jiffies;
	direction = &flow->direction[CTINFO2DIR(ctinfo)];
	last = direction->count ? &direction->history[direction->count - 1] : NULL;
	/* Retransmitting a blocked boundary match must not evade its earlier verdict. */
	if (last && direction->seq == seq && last->len == length &&
	    !memcmp(last->data, payload, length)) {
		result = direction->matched;
		goto finish;
	}
	if (last && !direction->closed && seq == direction->seq + last->len) {
		if (window_packets > 1) {
			for (i = 0; i < direction->count; i++)
				previous += direction->history[i].len;
			offset = 0;
			for (i = 0; i < direction->count; i++) {
				memcpy(payload - previous + offset, direction->history[i].data,
				       direction->history[i].len);
				offset += direction->history[i].len;
			}
		}
	} else {
		/* shortcut: gaps/overlaps restart here; use full TCP reassembly if required. */
		regex_clear_direction(direction);
	}
	saved = kmemdup(payload, length, GFP_ATOMIC);
	if (!saved) {
		result = -ENOMEM;
		goto discard;
	}
	result = regex_search(priv, cpu, payload - previous, previous + length, previous);
	if (result < 0)
		goto discard;
	if (direction->count == window_packets - 1) {
		kfree(direction->history[0].data);
		direction->count--;
		memmove(direction->history, direction->history + 1,
			direction->count * sizeof(direction->history[0]));
	}
	direction->history[direction->count].data = saved;
	direction->history[direction->count++].len = length;
	direction->seq = seq;
	direction->matched = result;
	saved = NULL;
finish:
	if (tcp->fin)
		direction->closed = true;
	goto unlock;
discard:
	kfree(saved);
	regex_free_flow(flow);
unlock:
	spin_unlock(&bucket->lock);
	return result;
}

static void nft_regex_eval(const struct nft_expr *expr, struct nft_regs *regs,
			   const struct nft_pktinfo *pkt)
{
	const struct nft_regex *priv = nft_expr_priv(expr);
	struct regex_cpu *cpu;
	unsigned int offset, length;
	u8 *payload;
	int result;

	result = regex_payload(pkt, &offset, &length);
	if (result <= 0)
		goto verdict;
	if (!length && !(window_packets > 1 && pkt->tprot == IPPROTO_TCP)) {
		result = 0;
		goto verdict;
	}
	local_bh_disable();
	cpu = get_cpu_ptr(regex_cpus);
	if (unlikely(cpu->busy)) {
		result = -EBUSY;
		goto unlock;
	}
	cpu->busy = true;
	payload = cpu->buffer + (window_packets - 1) * NFT_REGEX_PAYLOAD_MAX;
	result = skb_copy_bits(pkt->skb, offset, payload, length);
	if (!result) {
		if (window_packets > 1 && pkt->tprot == IPPROTO_TCP)
			result = regex_tcp_search(priv, cpu, pkt, payload, length);
		else
			result = regex_search(priv, cpu, payload, length, 0);
	}
	cpu->busy = false;
unlock:
	put_cpu_ptr(regex_cpus);
	local_bh_enable();
verdict:
	if (result < 0) {
		regs->verdict.code = NF_DROP;
		pr_warn_ratelimited("nft_regex: inspection failed (%d); dropping packet\n",
				    result);
	} else if (!result) {
		regs->verdict.code = NFT_BREAK;
	}
}

static int nft_regex_init(const struct nft_ctx *ctx, const struct nft_expr *expr,
			  const struct nlattr * const tb[])
{
	struct nft_regex *priv = nft_expr_priv(expr);
	pcre2_compile_context *context;
	PCRE2_SIZE offset, jit_size;
	char wrapped[NFT_REGEX_PATTERN_MAX + 32];
	unsigned int i;
	int error;

	if (ctx->family != NFPROTO_IPV4 && ctx->family != NFPROTO_IPV6 &&
	    ctx->family != NFPROTO_INET)
		return -EAFNOSUPPORT;
	if (!tb[NFTA_REGEX_PATTERN] || nla_len(tb[NFTA_REGEX_PATTERN]) < 2 ||
	    nla_len(tb[NFTA_REGEX_PATTERN]) > sizeof(priv->pattern))
		return -EINVAL;
	memcpy(priv->pattern, nla_data(tb[NFTA_REGEX_PATTERN]),
	       nla_len(tb[NFTA_REGEX_PATTERN]));
	if (priv->pattern[nla_len(tb[NFTA_REGEX_PATTERN]) - 1] ||
	    strnlen(priv->pattern, sizeof(priv->pattern)) !=
	    nla_len(tb[NFTA_REGEX_PATTERN]) - 1)
		return -EINVAL;
	priv->window = NULL;
	if (window_packets > 1 &&
	    (strstr(priv->pattern, "(*ACCEPT") || strstr(priv->pattern, "(?C")))
		return -EINVAL;
	context = pcre2_compile_context_create(NULL);
	if (!context)
		return -ENOMEM;
	pcre2_set_parens_nest_limit(context, 32);
	/* Independent validation prevents escaping the boundary-callout wrapper. */
	priv->code = pcre2_compile((PCRE2_SPTR)priv->pattern, PCRE2_ZERO_TERMINATED,
		PCRE2_NEVER_UTF | PCRE2_AUTO_CALLOUT, &error, &offset, context);
	if (priv->code && window_packets > 1) {
		pcre2_code_free(priv->code);
		pcre2_set_parens_nest_limit(context, 33);
		snprintf(wrapped, sizeof(wrapped), "(?:%s)(?C254)", priv->pattern);
		priv->code = pcre2_compile((PCRE2_SPTR)wrapped, PCRE2_ZERO_TERMINATED,
			PCRE2_NEVER_UTF | PCRE2_AUTO_CALLOUT, &error, &offset, context);
	}
	pcre2_compile_context_free(context);
	if (!priv->code) {
		pr_warn_ratelimited("nft_regex: invalid pattern at byte %zu (%d)\n",
				    offset, error);
		return -EINVAL;
	}
	error = pcre2_jit_compile(priv->code, PCRE2_JIT_COMPLETE);
	if (error || pcre2_pattern_info(priv->code, PCRE2_INFO_JITSIZE, &jit_size) ||
	    !jit_size) {
		error = -EOPNOTSUPP;
		goto fail;
	}
	if (window_packets == 1)
		return 0;
	priv->window = kzalloc(sizeof(*priv->window), GFP_KERNEL);
	if (!priv->window) {
		error = -ENOMEM;
		goto fail;
	}
	error = nf_ct_netns_get(ctx->net, ctx->family);
	if (error) {
		kfree(priv->window);
		priv->window = NULL;
		goto fail;
	}
	for (i = 0; i < REGEX_BUCKETS; i++) {
		spin_lock_init(&priv->window->buckets[i].lock);
		INIT_HLIST_HEAD(&priv->window->buckets[i].flows);
	}
	INIT_DELAYED_WORK(&priv->window->gc, regex_gc);
	schedule_delayed_work(&priv->window->gc, REGEX_GC_INTERVAL);
	return 0;
fail:
	pcre2_code_free(priv->code);
	priv->code = NULL;
	return error;
}

static void nft_regex_destroy(const struct nft_ctx *ctx, const struct nft_expr *expr)
{
	const struct nft_regex *priv = nft_expr_priv(expr);

	if (priv->window) {
		cancel_delayed_work_sync(&priv->window->gc);
		regex_collect(priv->window, true);
		kfree(priv->window);
		nf_ct_netns_put(ctx->net, ctx->family);
	}
	pcre2_code_free(priv->code);
}

static int nft_regex_validate(const struct nft_ctx *ctx, const struct nft_expr *expr)
{
	const struct nft_regex *priv = nft_expr_priv(expr);

	if (!priv->window)
		return 0;
	return nft_chain_validate_hooks(ctx->chain, (1 << NF_INET_LOCAL_IN) |
				       (1 << NF_INET_FORWARD) | (1 << NF_INET_LOCAL_OUT));
}

static int nft_regex_dump(struct sk_buff *skb, const struct nft_expr *expr, bool reset)
{
	const struct nft_regex *priv = nft_expr_priv(expr);

	return nla_put_string(skb, NFTA_REGEX_PATTERN, priv->pattern) ? -1 : 0;
}

static void regex_free_cpus(void)
{
	int i;

	if (!regex_cpus)
		return;
	for_each_possible_cpu(i) {
		struct regex_cpu *cpu = per_cpu_ptr(regex_cpus, i);

		pcre2_jit_stack_free(cpu->stack);
		pcre2_match_context_free(cpu->context);
		pcre2_match_data_free(cpu->data);
		kvfree(cpu->buffer);
	}
	free_percpu(regex_cpus);
	regex_cpus = NULL;
}

static int regex_alloc_cpus(void)
{
	int i;

	/* The shared scratch ownership relies on non-RT bottom-half exclusion. */
	if (!window_packets || window_packets > REGEX_MAX_WINDOW || !max_flows ||
	    max_flows > 65536 || !idle_seconds || idle_seconds > 3600)
		return -EINVAL;
	if (IS_ENABLED(CONFIG_PREEMPT_RT))
		return -EOPNOTSUPP;
	regex_cpus = alloc_percpu(struct regex_cpu);
	if (!regex_cpus)
		return -ENOMEM;
	for_each_possible_cpu(i) {
		struct regex_cpu *cpu = per_cpu_ptr(regex_cpus, i);

		cpu->buffer = kvmalloc(window_packets * NFT_REGEX_PAYLOAD_MAX, GFP_KERNEL);
		cpu->data = pcre2_match_data_create(1, NULL);
		cpu->context = pcre2_match_context_create(NULL);
		cpu->stack = pcre2_jit_stack_create(65536, 65536, NULL);
		if (!cpu->buffer || !cpu->data || !cpu->context || !cpu->stack) {
			regex_free_cpus();
			return -ENOMEM;
		}
		pcre2_set_match_limit(cpu->context, NFT_REGEX_WORK_MAX);
		pcre2_set_callout(cpu->context, regex_callout, cpu);
		pcre2_jit_stack_assign(cpu->context, NULL, cpu->stack);
	}
	return 0;
}

#ifndef NFT_REGEX_TEST
static const struct nla_policy nft_regex_policy[NFTA_REGEX_MAX + 1] = {
	[NFTA_REGEX_PATTERN] = { .type = NLA_NUL_STRING, .len = NFT_REGEX_PATTERN_MAX },
};

static struct nft_expr_type nft_regex_type;
static const struct nft_expr_ops nft_regex_ops = {
	.type = &nft_regex_type,
	.size = NFT_EXPR_SIZE(sizeof(struct nft_regex)),
	.eval = nft_regex_eval,
	.init = nft_regex_init,
	.destroy = nft_regex_destroy,
	.validate = nft_regex_validate,
	.dump = nft_regex_dump,
};

static struct nft_expr_type nft_regex_type __read_mostly = {
	.name = "regex",
	.ops = &nft_regex_ops,
	.policy = nft_regex_policy,
	.maxattr = NFTA_REGEX_MAX,
	.owner = THIS_MODULE,
};

static int __init nft_regex_module_init(void)
{
	int error = regex_alloc_cpus();

	if (error)
		return error;
	error = nft_register_expr(&nft_regex_type);
	if (error)
		regex_free_cpus();
	return error;
}

static void __exit nft_regex_module_exit(void)
{
	nft_unregister_expr(&nft_regex_type);
	regex_free_cpus();
}

module_init(nft_regex_module_init);
module_exit(nft_regex_module_exit);
MODULE_ALIAS("nft-expr-regex");
#endif
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("nftables packet payload regex matching using kpcre PCRE2 JIT");
