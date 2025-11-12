#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/udp.h>
#include <bpf_helpers.h>
#include "bpf_endian.h"

/* Map of backends: key = index (0..N-1), value = IPv4 + port */
struct backend_val {
	__u32 ip_be;   /* IPv4 address in big-endian (network order) */
	__u16 port_be; /* UDP port in big-endian (network order), typically 53 */
	__u16 pad;
};

/* BPF maps (BTF-defined, libbpf v1+ compatible) */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 64);
	__type(key, __u32);
	__type(value, struct backend_val);
} backends SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u32);
} backend_count SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u32);
} vip_map SEC(".maps");

/* Optional stats (packets matched) */
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 4);
	__type(key, __u32);
	__type(value, __u64);
} stats SEC(".maps");

static __always_inline int parse_udp(void *data, void *data_end,
				     struct udphdr **udph, __u16 *udp_len)
{
	struct udphdr *u = *udph;
	if ((void *)(u + 1) > data_end)
		return -1;
	*udp_len = bpf_ntohs(u->len);
	return 0;
}

static __always_inline int parse_ipv4(void *data, void *data_end,
				      struct iphdr **iph)
{
	struct iphdr *ip = *iph;
	if ((void *)(ip + 1) > data_end)
		return -1;
	if (ip->version != 4)
		return -1;
	if (ip->ihl < 5)
		return -1;
	if ((void *)ip + ip->ihl * 4 > data_end)
		return -1;
	return 0;
}

static __always_inline __u32 hash_2tuples(__u32 a, __u32 b)
{
	/* Fast multiplicative hash */
	__u32 x = a * 2654435761u ^ (b + 0x9e3779b9);
	x ^= x >> 13;
	x *= 0x85ebca6b;
	x ^= x >> 16;
	return x;
}

static __always_inline void update_ip_csum(struct iphdr *iph, __u32 old, __u32 new)
{
	/* Update IPv4 header checksum incrementally for daddr/saddr change.
	 * iph->check is in big-endian; helper expects folded sum eventually.
	 */
	__u64 sum = (~(__u16)iph->check) & 0xFFFF;
	sum += (~(__u16)(old >> 16)) & 0xFFFF;
	sum += (~(__u16)(old & 0xFFFF)) & 0xFFFF;
	sum += (__u16)(new >> 16);
	sum += (__u16)(new & 0xFFFF);
	sum = (sum & 0xFFFF) + (sum >> 16);
	sum = (sum & 0xFFFF) + (sum >> 16);
	iph->check = ~(__u16)sum;
}

SEC("xdp")
int xdp_dns_lb(struct xdp_md *ctx)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data     = (void *)(long)ctx->data;

	struct ethhdr *eth = data;
	if ((void *)(eth + 1) > data_end)
		return XDP_PASS;

	if (eth->h_proto != bpf_htons(ETH_P_IP))
		return XDP_PASS;

	struct iphdr *iph = (void *)(eth + 1);
	if (parse_ipv4(data, data_end, &iph) < 0)
		return XDP_PASS;

	if (iph->protocol != IPPROTO_UDP)
		return XDP_PASS;

	struct udphdr *udph = (void *)iph + iph->ihl * 4;
	__u16 udp_len;
	if (parse_udp(data, data_end, &udph, &udp_len) < 0)
		return XDP_PASS;

	/* Load VIP */
	__u32 zero = 0;
	__u32 *vip = bpf_map_lookup_elem(&vip_map, &zero);

	/* Stat slot 0: total UDP */
	__u64 *st;
	if ((st = bpf_map_lookup_elem(&stats, &zero)))
		*st += 1;

	/* If missing VIP config, don't touch packets */
	if (!vip)
		return XDP_PASS;

	/* Request path: dst == VIP and dport == 53 -> choose backend and DNAT */
	if (iph->daddr == *vip && udph->dest == bpf_htons(53)) {
		__u32 *cnt = bpf_map_lookup_elem(&backend_count, &zero);
		if (!cnt || *cnt == 0)
			return XDP_PASS;

		/* Hash on (src_ip, src_port) for stickiness */
		__u32 h = hash_2tuples(iph->saddr, (__u32)udph->source);
		__u32 idx = h % *cnt;

		struct backend_val *be = bpf_map_lookup_elem(&backends, &idx);
		if (!be || be->ip_be == 0)
			return XDP_PASS;

		/* Update stats[1]: requests rewritten */
		__u32 one = 1;
		if ((st = bpf_map_lookup_elem(&stats, &one)))
			*st += 1;

		/* Rewrite dst IP: VIP -> backend IP */
		__u32 old_daddr = iph->daddr;
		iph->daddr = be->ip_be;

		/* Keep DNS port 53 (backend port optionally from config) */
		udph->dest = (be->port_be ? be->port_be : bpf_htons(53));

		/* For IPv4 UDP, checksum 0 means 'no checksum' (valid). Avoid recompute cost. */
		udph->check = 0;

		/* Fix IP header checksum incrementally */
		update_ip_csum(iph, old_daddr, iph->daddr);

		/* In generic (SKB) mode, XDP_TX is not supported: pass up the stack to route out. */
		return XDP_PASS;
	}

	/* Response path: src in backends and sport == 53 -> SNAT to VIP */
	/* We do a small linear scan of backends (max 64). */
	__u32 *cnt2 = bpf_map_lookup_elem(&backend_count, &zero);
	if (cnt2 && *cnt2 > 0 && udph->source == bpf_htons(53)) {
		__u32 i;
		#pragma clang loop unroll(full)
		for (i = 0; i < 64; i++) {
			if (cnt2 && i >= *cnt2)
				break;
			struct backend_val *be2 = bpf_map_lookup_elem(&backends, &i);
			if (!be2)
				break;
			if (be2->ip_be == iph->saddr) {
				/* Update stats[2]: responses rewritten */
				__u32 two = 2;
				if ((st = bpf_map_lookup_elem(&stats, &two)))
					*st += 1;

				__u32 old_saddr = iph->saddr;
				iph->saddr = *vip;
				udph->check = 0;
				update_ip_csum(iph, old_saddr, iph->saddr);
				break;
			}
		}
	}

	return XDP_PASS;
}

char _license[] SEC("license") = "GPL";


