// SPDX-License-Identifier: GPL-2.0
/* A bounded TCP payload window for each rule/connection/direction. */
#include <linux/module.h>
#include <linux/percpu.h>
#include <linux/skbuff.h>
#include <linux/tcp.h>
#include <linux/hash.h>
#include <linux/workqueue.h>
#include <linux/vmalloc.h>
#include <linux/netfilter/x_tables.h>
#include <net/netfilter/nf_conntrack.h>
#include "pcre2.h"
#include "xt_ids.h"

#define IDS_HASH_BITS 6
#define IDS_BUCKETS (1U << IDS_HASH_BITS)
#define IDS_CALLOUT_BUDGET 100000
#define IDS_GC_INTERVAL (5 * HZ)
#define IDS_MAX_WINDOW 8

static unsigned int window_packets = 2;
module_param(window_packets, uint, 0444);
MODULE_PARM_DESC(window_packets, "Maximum adjacent payloads to inspect together (1-8)");

static unsigned int payload_limit = 16384;
module_param(payload_limit, uint, 0444);
MODULE_PARM_DESC(payload_limit, "Maximum TCP payload bytes per packet (256-65535)");
static unsigned int max_flows = 4096;
module_param(max_flows, uint, 0444);
MODULE_PARM_DESC(max_flows, "Maximum cached rule/connection pairs across all rules");
static unsigned int idle_seconds = 30;
module_param(idle_seconds, uint, 0444);
MODULE_PARM_DESC(idle_seconds, "Expire cached payloads after this many idle seconds");

struct ids_payload {
	u8 *data;
	unsigned int len;
};

struct ids_direction {
	struct ids_payload history[IDS_MAX_WINDOW - 1];
	unsigned int count;
	u32 seq;
	bool matched;
	bool closed;
};

struct ids_flow {
	struct hlist_node node;
	struct nf_conn *ct;
	unsigned long seen;
	struct ids_direction direction[2];
};

struct ids_bucket {
	spinlock_t lock;
	struct hlist_head flows;
};

struct ids_rule {
	pcre2_code *code;
	struct delayed_work gc;
	struct ids_bucket buckets[IDS_BUCKETS];
};

struct ids_cpu {
	pcre2_match_data *data;
	pcre2_match_context *context;
	pcre2_jit_stack *stack;
	u8 *buffer;
	unsigned int boundary, budget;
	bool busy;
};

static struct ids_cpu __percpu *ids_cpus;
static atomic_t ids_flows = ATOMIC_INIT(0);

static void ids_clear_direction(struct ids_direction *direction)
{
	unsigned int i;
	for (i = 0; i < direction->count; i++)
		kfree(direction->history[i].data);
	memset(direction, 0, sizeof(*direction));
}

static void ids_free_flow(struct ids_flow *flow)
{
	hlist_del(&flow->node);
	ids_clear_direction(&flow->direction[0]);
	ids_clear_direction(&flow->direction[1]);
	nf_conntrack_put(&flow->ct->ct_general);
	kfree(flow);
	atomic_dec(&ids_flows);
}

static void ids_collect(struct ids_rule *rule, bool all)
{
	struct ids_flow *flow;
	struct hlist_node *next;
	unsigned int i;

	for (i = 0; i < IDS_BUCKETS; i++) {
		struct ids_bucket *bucket = &rule->buckets[i];
		spin_lock_bh(&bucket->lock);
		hlist_for_each_entry_safe(flow, next, &bucket->flows, node)
			if (all || nf_ct_is_dying(flow->ct) ||
			    time_after_eq(jiffies, flow->seen + idle_seconds * HZ))
				ids_free_flow(flow);
		spin_unlock_bh(&bucket->lock);
	}
}

static void ids_gc(struct work_struct *work)
{
	struct ids_rule *rule = container_of(to_delayed_work(work), struct ids_rule, gc);
	ids_collect(rule, false);
	schedule_delayed_work(&rule->gc, IDS_GC_INTERVAL);
}

static int ids_callout(pcre2_callout_block *block, void *data)
{
	struct ids_cpu *cpu = data;

	if (!cpu->budget--)
		return PCRE2_ERROR_CALLOUT;
	/* Reject an old-only candidate inside PCRE so later alternatives still run. */
	if (block->callout_number == 254)
		return block->current_position <= cpu->boundary;
	return 0;
}

static int ids_search(struct ids_rule *rule, struct ids_cpu *cpu,
		      const u8 *subject, unsigned int length, unsigned int boundary)
{
	int result;

	cpu->boundary = boundary;
	cpu->budget = IDS_CALLOUT_BUDGET;
	result = pcre2_jit_match(rule->code, subject, length, 0, PCRE2_NOTEMPTY,
				cpu->data, cpu->context);
	if (result >= 0)
		return 1;
	return result == PCRE2_ERROR_NOMATCH ? 0 : result;
}

static bool ids_match(const struct sk_buff *skb, struct xt_action_param *par)
{
	const struct xt_ids_info *info = par->matchinfo;
	struct ids_rule *rule = (void *)(unsigned long)info->state;
	struct tcphdr header, *tcp;
	struct nf_conn *ct;
	enum ip_conntrack_info ctinfo;
	struct ids_cpu *cpu;
	struct ids_bucket *bucket;
	struct ids_flow *flow = NULL, *candidate;
	struct ids_direction *direction;
	struct ids_payload *last;
	unsigned int offset, length, i, previous = 0;
	u32 seq;
	u8 *saved = NULL, *payload;
	int result = -EINVAL;

	if (par->fragoff || par->thoff > skb->len)
		goto error;
	tcp = skb_header_pointer(skb, par->thoff, sizeof(header), &header);
	if (!tcp || tcp->doff < 5 || tcp->doff * 4U > skb->len - par->thoff)
		goto error;
	ct = nf_ct_get(skb, &ctinfo);
	if (!ct || nf_ct_is_template(ct) || nf_ct_protonum(ct) != IPPROTO_TCP) {
		result = -ENOTCONN;
		goto error;
	}
	offset = par->thoff + tcp->doff * 4U;
	length = skb->len - offset;
	if (length > payload_limit) {
		result = -E2BIG;
		goto error;
	}
	seq = ntohl(tcp->seq) + tcp->syn;

	local_bh_disable();
	cpu = get_cpu_ptr(ids_cpus);
	if (unlikely(cpu->busy)) {
		put_cpu_ptr(ids_cpus);
		local_bh_enable();
		result = -EBUSY;
		goto error;
	}
	cpu->busy = true;
	payload = cpu->buffer + (window_packets - 1) * payload_limit;
	if (skb_copy_bits(skb, offset, payload, length)) {
		result = -EINVAL;
		goto release_cpu;
	}
	result = 0;
	bucket = &rule->buckets[hash_ptr(ct, IDS_HASH_BITS)];
	spin_lock(&bucket->lock);
	hlist_for_each_entry(candidate, &bucket->flows, node)
		if (candidate->ct == ct) {
			flow = candidate;
			break;
		}
	if (flow && (tcp->rst || tcp->syn ||
	    time_after_eq(jiffies, flow->seen + idle_seconds * HZ))) {
		ids_free_flow(flow);
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
		if (atomic_inc_return(&ids_flows) > max_flows) {
			atomic_dec(&ids_flows);
			result = -ENOSPC;
			goto unlock;
		}
		flow = kzalloc(sizeof(*flow), GFP_ATOMIC);
		if (!flow) {
			atomic_dec(&ids_flows);
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
		ids_clear_direction(direction);
	}
	saved = kmemdup(payload, length, GFP_ATOMIC);
	if (!saved) {
		result = -ENOMEM;
		goto discard;
	}
	result = ids_search(rule, cpu, payload - previous, previous + length, previous);
	if (result < 0)
		goto discard;
	/* N=1 retains one payload solely for retransmission verdicts. */
	if (direction->count == max(1U, window_packets - 1)) {
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
	ids_free_flow(flow);
unlock:
	spin_unlock(&bucket->lock);
release_cpu:
	cpu->busy = false;
	put_cpu_ptr(ids_cpus);
	local_bh_enable();
	if (result >= 0)
		return result;
error:
	par->hotdrop = true;
	pr_warn_ratelimited("xt_ids: inspection failed (%d); dropping packet\n", result);
	return false;
}

static int ids_check(const struct xt_mtchk_param *par)
{
	struct xt_ids_info *info = par->matchinfo;
	struct ids_rule *rule;
	char pattern[IDS_PATTERN_SIZE + 32];
	PCRE2_SIZE error_offset, jit_size;
	unsigned int i;
	int error;

	info->state = 0;
	if (!info->regex[0] || !memchr(info->regex, 0, sizeof(info->regex)))
		return -EINVAL;
	/* These constructs could bypass or impersonate the final boundary callout. */
	if (strstr(info->regex, "(*ACCEPT") || strstr(info->regex, "(?C"))
		return -EINVAL;
	rule = kzalloc(sizeof(*rule), GFP_KERNEL);
	if (!rule)
		return -ENOMEM;
	/* Validate independently so an unmatched ')' cannot escape the wrapper. */
	rule->code = pcre2_compile((PCRE2_SPTR)info->regex, PCRE2_ZERO_TERMINATED,
		PCRE2_NEVER_UTF, &error, &error_offset, NULL);
	if (!rule->code) {
		pr_warn("xt_ids: invalid regex at offset %zu (%d)\n", error_offset, error);
		error = -EINVAL;
		goto fail;
	}
	pcre2_code_free(rule->code);
	snprintf(pattern, sizeof(pattern), "(?:%s)(?C254)", info->regex);
	rule->code = pcre2_compile((PCRE2_SPTR)pattern, PCRE2_ZERO_TERMINATED,
		PCRE2_AUTO_CALLOUT | PCRE2_NEVER_UTF, &error, &error_offset, NULL);
	if (!rule->code) {
		pr_warn("xt_ids: invalid regex at wrapped offset %zu (%d)\n", error_offset, error);
		error = -EINVAL;
		goto fail;
	}
	error = pcre2_jit_compile(rule->code, PCRE2_JIT_COMPLETE);
	if (error || pcre2_pattern_info(rule->code, PCRE2_INFO_JITSIZE, &jit_size) || !jit_size) {
		pr_warn("xt_ids: JIT compilation is required (%d)\n", error);
		error = -EOPNOTSUPP;
		goto fail;
	}
	error = nf_ct_netns_get(par->net, par->family);
	if (error)
		goto fail;
	for (i = 0; i < IDS_BUCKETS; i++) {
		spin_lock_init(&rule->buckets[i].lock);
		INIT_HLIST_HEAD(&rule->buckets[i].flows);
	}
	INIT_DELAYED_WORK(&rule->gc, ids_gc);
	schedule_delayed_work(&rule->gc, IDS_GC_INTERVAL);
	info->state = (unsigned long)rule;
	return 0;
fail:
	pcre2_code_free(rule->code);
	kfree(rule);
	return error;
}

static void ids_destroy(const struct xt_mtdtor_param *par)
{
	const struct xt_ids_info *info = par->matchinfo;
	struct ids_rule *rule = (void *)(unsigned long)info->state;

	cancel_delayed_work_sync(&rule->gc);
	ids_collect(rule, true);
	pcre2_code_free(rule->code);
	kfree(rule);
	nf_ct_netns_put(par->net, par->family);
}

static void ids_free_cpus(void)
{
	int i;
	if (!ids_cpus)
		return;
	for_each_possible_cpu(i) {
		struct ids_cpu *cpu = per_cpu_ptr(ids_cpus, i);
		pcre2_jit_stack_free(cpu->stack);
		pcre2_match_context_free(cpu->context);
		pcre2_match_data_free(cpu->data);
		kvfree(cpu->buffer);
	}
	free_percpu(ids_cpus);
	ids_cpus = NULL;
}

static int ids_alloc_cpus(void)
{
	int i;
	if (!window_packets || window_packets > IDS_MAX_WINDOW ||
	    payload_limit < 256 || payload_limit > 65535 ||
	    !max_flows || max_flows > 65536 || !idle_seconds || idle_seconds > 3600)
		return -EINVAL;
	ids_cpus = alloc_percpu(struct ids_cpu);
	if (!ids_cpus)
		return -ENOMEM;
	for_each_possible_cpu(i) {
		struct ids_cpu *cpu = per_cpu_ptr(ids_cpus, i);
		cpu->buffer = kvmalloc(window_packets * payload_limit, GFP_KERNEL);
		cpu->data = pcre2_match_data_create(1, NULL);
		cpu->context = pcre2_match_context_create(NULL);
		cpu->stack = pcre2_jit_stack_create(16384, 65536, NULL);
		if (!cpu->buffer || !cpu->data || !cpu->context || !cpu->stack) {
			ids_free_cpus();
			return -ENOMEM;
		}
		pcre2_set_match_limit(cpu->context, 10000);
		pcre2_set_callout(cpu->context, ids_callout, cpu);
		pcre2_jit_stack_assign(cpu->context, NULL, cpu->stack);
	}
	return 0;
}

#ifndef IDS_TEST
static struct xt_match ids_mt_reg __read_mostly = {
	.name = "ids",
	.family = NFPROTO_UNSPEC,
	.table = "filter",
	.proto = IPPROTO_TCP,
	.hooks = (1 << NF_INET_LOCAL_IN) | (1 << NF_INET_FORWARD) | (1 << NF_INET_LOCAL_OUT),
	.match = ids_match,
	.checkentry = ids_check,
	.destroy = ids_destroy,
	.matchsize = sizeof(struct xt_ids_info),
	.usersize = offsetof(struct xt_ids_info, state),
	.me = THIS_MODULE,
};

static int __init ids_init(void)
{
	int error = ids_alloc_cpus();
	if (error)
		return error;
	error = xt_register_match(&ids_mt_reg);
	if (error)
		ids_free_cpus();
	return error;
}

static void __exit ids_exit(void)
{
	xt_unregister_match(&ids_mt_reg);
	ids_free_cpus();
}

module_init(ids_init);
module_exit(ids_exit);
MODULE_ALIAS("ipt_ids");
MODULE_ALIAS("ip6t_ids");
#endif
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("PCRE JIT matching across a bounded TCP payload window");
