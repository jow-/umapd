// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright (C) 2021 Felix Fietkau <nbd@nbd.name>
 */
#define KBUILD_MODNAME "foo"
#include <uapi/linux/bpf.h>
#include <uapi/linux/if_ether.h>
#include <uapi/linux/if_packet.h>
#include <uapi/linux/filter.h>
#include <uapi/linux/pkt_cls.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "bpf_skb_utils.h"

#ifndef ETH_P_1905
#define ETH_P_1905	0x893a
#endif

struct umapsocket_addr_key {
	__be16 proto;
	u8 addr[ETH_ALEN];
};

struct umapsocket_addr_val {
	u16 index;
	u8 clone;
	u8 __pad;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, struct umapsocket_addr_key);
	__type(value, struct umapsocket_addr_val);
	__uint(max_entries, 128);
	__uint(map_flags, BPF_F_NO_PREALLOC);
} addr_map SEC(".maps");

SEC("tc")
int ingress(struct __sk_buff *skb)
{
	struct umapsocket_addr_key key;
	struct umapsocket_addr_val *val;
	struct skb_parser_info info;
	u32 ifindex = skb->ifindex;
	u32 orig_data, *data;
	bool multicast, clone;
	int redirect_ifindex;
	u16 addr_index = 0xffff;
	u8 *map_val;
	u16 *data2;

	redirect_ifindex = skb->tc_classid;
	skb->tc_classid = 0;

	skb_parse_init(&info, skb);
	if (!skb_parse_ethernet(&info))
		return TC_ACT_UNSPEC;

	skb_parse_vlan(&info);
	skb_parse_vlan(&info);

	if (info.proto != bpf_htons(ETH_P_LLDP) &&
		info.proto != bpf_htons(ETH_P_1905))
		return TC_ACT_UNSPEC;

	data = skb_ptr(skb, 0, sizeof(key));
	if (!data)
		return TC_ACT_UNSPEC;

	key.proto = info.proto;
	memcpy(&key.addr, data, sizeof(key.addr));

	val = bpf_map_lookup_elem(&addr_map, &key);
	if (!val)
		return TC_ACT_UNSPEC;

	addr_index = val->index;
	clone = val->clone;
	bpf_skb_store_bytes(skb, 0, &ifindex, 4, 0);
	bpf_skb_store_bytes(skb, 4, &addr_index, 2, 0);

	if (clone) {
		bpf_clone_redirect(skb, redirect_ifindex, BPF_F_INGRESS);
		bpf_skb_store_bytes(skb, 0, &key.addr, sizeof(key.addr), 0);
	} else {
		return bpf_redirect(redirect_ifindex, BPF_F_INGRESS);
	}

	return TC_ACT_UNSPEC;
}

char _license[] SEC("license") = "GPL";
