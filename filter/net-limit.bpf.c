// SPDX-FileCopyrightText: 2025 UnionTech Software Technology Co., Ltd
//
// SPDX-License-Identifier: GPL-2.0

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

char __license[] SEC("license") = "GPL";

#define NET_LIMIT_SCOPE_CGROUP 2
#define NET_LIMIT_EGRESS 1
#define NET_LIMIT_INGRESS 2

#define NSEC_PER_SEC 1000000000ull
#define CG_ACT_OK 1
#define CG_ACT_SHOT 0
#define TC_ACT_OK 0

struct limit_rule {
	__u64 rate_bps;
	__u64 burst_bytes;
	__u32 direction;
	__u32 _pad;
};

struct bucket_key {
	__u32 scope;
	__u32 direction;
	__u64 id;  //当前cgroup的ID
};

struct rate_bucket {
	struct bpf_spin_lock lock;
	__u64 ts_ns;
	__u64 tokens;
};

struct limit_stats {
	__u64 pass_bytes;
	__u64 drop_bytes;
	__u64 pass_packets;
	__u64 drop_packets;
};

struct shape_rule {
	__u32 classid;
	__u32 direction;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 4096);
	__type(key, __u64);
	__type(value, struct limit_rule);
} cgroup_rules SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 8192);
	__type(key, struct bucket_key);
	__type(value, struct rate_bucket);
} buckets SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 8192);
	__type(key, struct bucket_key);
	__type(value, struct limit_stats);
} stats SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 8192);
	__type(key, struct bucket_key);
	__type(value, struct shape_rule);
} shape_rules SEC(".maps");

static __always_inline void add_stats(const struct bucket_key *key, __u32 len, bool drop)
{
	struct limit_stats init = {};
	struct limit_stats *s;

	bpf_map_update_elem(&stats, key, &init, BPF_NOEXIST);
	s = bpf_map_lookup_elem(&stats, key);
	if (!s)
		return;

	if (drop) {
		__sync_fetch_and_add(&s->drop_bytes, len);
		__sync_fetch_and_add(&s->drop_packets, 1);
	} else {
		__sync_fetch_and_add(&s->pass_bytes, len);
		__sync_fetch_and_add(&s->pass_packets, 1);
	}
}

static __always_inline int apply_rule(const struct bucket_key *key,const struct limit_rule *rule,__u32 len)
{
	struct rate_bucket init;
	struct rate_bucket *bucket;
	__u64 now = bpf_ktime_get_ns();
	__u64 burst = rule->burst_bytes;
	__u64 delta_ns;
	__u64 elapsed_sec;
	__u64 rem_ns;
	__u64 add;
	bool drop = false;

	if (rule->rate_bps == 0)
		return CG_ACT_OK;

	if (burst == 0)
		burst = rule->rate_bps;

	bucket = bpf_map_lookup_elem(&buckets, key);
	if (!bucket) {
		__builtin_memset(&init, 0, sizeof(init));
		init.ts_ns = now;
		init.tokens = burst;
		bpf_map_update_elem(&buckets, key, &init, BPF_ANY);
		bucket = bpf_map_lookup_elem(&buckets, key);
		if (!bucket) {
			add_stats(key, len, false);
			return CG_ACT_OK;
		}
	}

	bpf_spin_lock(&bucket->lock);
	delta_ns = now - bucket->ts_ns;
	elapsed_sec = delta_ns / NSEC_PER_SEC;
	rem_ns = delta_ns - elapsed_sec * NSEC_PER_SEC;
	if (elapsed_sec > 0 && rule->rate_bps > burst / elapsed_sec)
		add = burst;
	else
		add = elapsed_sec * rule->rate_bps;
	add += (rem_ns / 1000000ull) * (rule->rate_bps / 1000ull);
	if (add > burst)
		add = burst;
	if (add > 0) {
		bucket->tokens += add;
		if (bucket->tokens > burst)
			bucket->tokens = burst;
		bucket->ts_ns = now;
	}

	if (bucket->tokens < len) {
		drop = true;
	} else {
		bucket->tokens -= len;
	}
	bpf_spin_unlock(&bucket->lock);

	add_stats(key, len, drop);
	return drop ? CG_ACT_SHOT : CG_ACT_OK;
}

static __always_inline int handle_packet(struct __sk_buff *skb, __u32 direction)
{
	__u64 cgid;
	struct limit_rule *rule;
	struct bucket_key key = {};
	
	if (direction == NET_LIMIT_INGRESS) {
		cgid = bpf_skb_cgroup_id(skb);
		if (cgid == 0)
			cgid = bpf_get_current_cgroup_id();
	} else {
		cgid = bpf_get_current_cgroup_id();
	}

	rule = bpf_map_lookup_elem(&cgroup_rules, &cgid);
	if (rule && (rule->direction & direction)) {
		key.scope = NET_LIMIT_SCOPE_CGROUP;
		key.direction = direction;
		key.id = cgid;
		return apply_rule(&key, rule, skb->len);
	}

	return CG_ACT_OK;
}

SEC("cgroup_skb/ingress")
int net_limit_ingress(struct __sk_buff *skb)
{
	/* 精简 police 模式：只保留 ingress 丢包限速，egress 交给 tc shape。 */
	return handle_packet(skb, NET_LIMIT_INGRESS);
}

static __always_inline int shape_packet(struct __sk_buff *skb, __u32 direction)
{
	__u64 cgid;
	struct shape_rule *rule;
	struct bucket_key key = {};

	/* 精简 shape 模式：只保留 tc/egress 分类，真正限速由 HTB qdisc 完成。 */
	cgid = bpf_skb_cgroup_id(skb);
	if (cgid == 0)
		cgid = bpf_get_current_cgroup_id();

	key.scope = NET_LIMIT_SCOPE_CGROUP;
	key.direction = direction;
	key.id = cgid;
	rule = bpf_map_lookup_elem(&shape_rules, &key);
	if (!rule || !(rule->direction & direction))
		return TC_ACT_OK;

	/* skb->priority 使用 tc classid 编码，例如 1:10 = 0x00010010。 */
	skb->priority = rule->classid;
	return TC_ACT_OK;
}

SEC("tc/egress")
int net_shape_egress(struct __sk_buff *skb)
{
	return shape_packet(skb, NET_LIMIT_EGRESS);
}
