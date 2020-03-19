/* SPDX-License-Identifier: GPL-2.0 */
#include <stddef.h>
#include <stdbool.h>
#include <linux/bpf.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/icmpv6.h>
#include <linux/icmp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
/* Defines xdp_stats_map from packet04 */
#include "../common/xdp_stats_kern_user.h"
#include "../common/xdp_stats_kern.h"

/* Header cursor to keep track of current parsing position */
struct hdr_cursor {
	void *pos;
};

/* Packet parsing helpers.
 *
 * Each helper parses a packet header, including doing bounds checking, and
 * returns the type of its contents if successful, and -1 otherwise.
 *
 * For Ethernet and IP headers, the content type is the type of the payload
 * (h_proto for Ethernet, nexthdr for IPv6), for ICMP it is the ICMP type field.
 * All return values are in host byte order.
 */
/*
 *	struct vlan_hdr - vlan header
 *	@h_vlan_TCI: priority and VLAN ID
 *	@h_vlan_encapsulated_proto: packet type ID or len
 */
struct vlan_hdr {
	__be16	h_vlan_TCI;
	__be16	h_vlan_encapsulated_proto;
};

/*
 * Struct icmphdr_common represents the common part of the icmphdr and icmp6hdr
 * structures.
 */
struct icmphdr_common {
	__u8		type;
	__u8		code;
	__sum16	cksum;
};

/* Allow users of header file to redefine VLAN max depth */
#ifndef VLAN_MAX_DEPTH
#define VLAN_MAX_DEPTH 4
#endif

static __always_inline int proto_is_vlan(__u16 h_proto)
{
	return !!(h_proto == bpf_htons(ETH_P_8021Q) ||
		  h_proto == bpf_htons(ETH_P_8021AD));
}

/* Notice, parse_ethhdr() will skip VLAN tags, by advancing nh->pos and returns
 * next header EtherType, BUT the ethhdr pointer supplied still points to the
 * Ethernet header. Thus, caller can look at eth->h_proto to see if this was a
 * VLAN tagged packet.
 */
static __always_inline int parse_ethhdr(struct hdr_cursor *nh,
					void *data_end,
					struct ethhdr **ethhdr,
                    __u16 *proto)
{
	struct ethhdr *eth = nh->pos;
	int hdrsize = sizeof(*eth);
	struct vlan_hdr *vlh;
	int i;

	/* Byte-count bounds check; check if current pointer + size of header
	 * is after data_end.
	 */
	//if (nh->pos + 1 > data_end)
	if (nh->pos + hdrsize > data_end)
		return -1;

	*ethhdr = eth;
	nh->pos += hdrsize;

	if (nh->pos + hdrsize > data_end)
		return -1;

	vlh = nh->pos;
	*proto = eth->h_proto;
	/* Use loop unrolling to avoid the verifier restriction on loops;
	 * support up to VLAN_MAX_DEPTH layers of VLAN encapsulation.
	 */
    #pragma unroll
	for (i = 0; i < VLAN_MAX_DEPTH; i++) {
		if (!proto_is_vlan(*proto))
			break;

		if (vlh + 1 > data_end)
			break;

        bpf_printk("Unexpected vlan?\n");
		*proto = vlh->h_vlan_encapsulated_proto;
		vlh++;
	}

	nh->pos = vlh;
	return 0; /* network-byte-order */
}

/* Assignment 2: Implement and use this */
static __always_inline int parse_ip6hdr(struct hdr_cursor *nh,
					void *data_end,
					struct ipv6hdr **ip6hdr)
{
    struct ipv6hdr *ip6h = nh->pos;
    int hdrsize = sizeof(*ip6h);
    if (ip6h + 1 > (struct ipv6hdr *)data_end)
        return -1;
    nh->pos += hdrsize;
    ip6h->payload_len = __bpf_ntohs(ip6h->payload_len);
    *ip6hdr = ip6h;
    return 0;
}

/* Assignment 3: Implement and use this */
static __always_inline int parse_icmp6hdr(struct hdr_cursor *nh,
					  void *data_end,
					  struct icmp6hdr **i6hdr)
{
    struct icmp6hdr *icmp6h = nh->pos;
    int hdrsize = sizeof(*icmp6h);
    if (icmp6h + 1 > (struct icmp6hdr *)data_end)
        return -1;
    nh->pos += hdrsize;
    icmp6h->icmp6_cksum = __bpf_ntohs(icmp6h->icmp6_cksum);
    if (icmp6h->icmp6_type == 128)
    {
        icmp6h->icmp6_identifier = __bpf_ntohs(icmp6h->icmp6_identifier);
        icmp6h->icmp6_sequence   = __bpf_ntohs(icmp6h->icmp6_sequence);
        // Assignment 3 - drop even sequences
        if ((icmp6h->icmp6_sequence & 2) == 0)
            return -1;
    }
    *i6hdr = icmp6h;
    return 0;
}

static __always_inline int parse_icmphdr(struct hdr_cursor *nh,
					  void *data_end,
					  struct icmphdr **ihdr)
{
    struct icmphdr *icmph = nh->pos;
    int hdrsize = sizeof(*icmph);
    if (icmph + 1 > (struct icmphdr *)data_end)
        return -1;
    nh->pos += hdrsize;
    icmph->checksum = __bpf_ntohs(icmph->checksum);
    if (icmph->type == 128)
    {
        icmph->un.echo.id       = __bpf_ntohs(icmph->un.echo.id);
        icmph->un.echo.sequence = __bpf_ntohs(icmph->un.echo.sequence);
        // Assignment 3 - drop even sequences
        if ((icmph->un.echo.sequence & 2) == 0)
            return -1;
    }
    *ihdr = icmph;
    return 0;
}

static __always_inline int parse_iphdr(struct hdr_cursor *nh,
				       void *data_end,
				       struct iphdr **iphdr)
{
	struct iphdr *iph = nh->pos;
	int hdrsize;

	if (iph + 1 > data_end)
		return -1;

	hdrsize = iph->ihl * 4;

	/* Variable-length IPv4 header, need to use byte-based arithmetic */
	if (nh->pos + hdrsize > data_end)
		return -1;

	nh->pos += hdrsize;
	*iphdr = iph;

	return iph->protocol;
}

SEC("xdp_packet_parser")
int  xdp_parser_func(struct xdp_md *ctx)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	struct ethhdr *eth;
    struct ipv6hdr *ipv6;
    struct icmp6hdr *ipcmp6h;
    struct iphdr *iph;
    struct icmphdr  *icmph;

	/* Default action XDP_PASS, imply everything we couldn't parse, or that
	 * we don't want to deal with, we just pass up the stack and let the
	 * kernel deal with it.
	 */
	__u32 action = XDP_DROP; /* Default action */
        /* These keep track of the next header type and iterator pointer */
	struct hdr_cursor nh;
	__u16 nh_type;

	/* Start next header cursor position at data start */
	nh.pos = data;

	/* Packet parsing in steps: Get each header one at a time, aborting if
	 * parsing fails. Each helper function does sanity checking (is the
	 * header type in the packet correct?), and bounds checking.
	 */
	if (parse_ethhdr(&nh, data_end, &eth, &nh_type) == -1)
    {
        bpf_printk("parse_ethhdr failed\n");
        goto out;
    }

	if (nh_type == bpf_htons(ETH_P_IPV6))
    {
        /* Assignment additions go below here */
        if (parse_ip6hdr(&nh, data_end, &ipv6) == -1)
        {
            bpf_printk("parse_ip6hdr failed\n");
            goto out;
        }
        switch (ipv6->nexthdr)
        {
            case 58:
                if (parse_icmp6hdr(&nh, data_end, &ipcmp6h) == -1)
                {
                    bpf_printk("parse_icmp6hdr failed\n");
                    goto out;
                }
                break;
            default:
                bpf_printk("unexpected nexthdr: %d, payload_len: %d\n", ipv6->nexthdr, ipv6->payload_len);
                goto out;
        }
    }
    else if (nh_type == bpf_htons(ETH_P_IP))
    {
        if (parse_iphdr(&nh, data_end, &iph) == -1)
        {
            bpf_printk("parse_iphdr failed\n");
            goto out;
        }
        if (iph->protocol != 1)
        {
            bpf_printk("Unexpected protocol: %d\n", iph->protocol);
            goto out;
        }
        else if (parse_icmphdr(&nh, data_end, &icmph))
        {
            bpf_printk("parse_icmdhdr failed\n");
            goto out;
        }
    }
    else
    {
        bpf_printk("Unexpected packet type: 0x%x\n", bpf_htons(nh_type));
        goto out;
    }
	action = XDP_PASS;
out:
	return xdp_stats_record_action(ctx, action); /* read via xdp_stats */
}

char _license[] SEC("license") = "GPL";
