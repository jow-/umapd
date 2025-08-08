/*
 * Copyright (c) 2025 Felix Fietkau <nbd@nbd.name>
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED 'AS IS' AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

import {
	create as socket, error as sockerr,
	AF_PACKET, SOCK_RAW, SOCK_NONBLOCK,
	SOL_SOCKET, SO_REUSEADDR, SO_ATTACH_FILTER,
	SOL_PACKET, PACKET_ADD_MEMBERSHIP,
	PACKET_MR_MULTICAST, PACKET_MR_PROMISC
} from 'socket';

import {
	request as rtrequest,
	error as rterror,
	'const' as rtc
} from 'rtnl';

import { readfile, access } from 'fs';
import { pack, unpack } from 'struct';
import log from 'umap.log';
import usocket from 'umap.socket';
import * as bpf from 'bpf';
import * as uloop from 'uloop';
import defs from 'umap.defs';
import utils from 'umap.utils';

let err;
const bpf_prio = 0x90;

const bpf_stats_keys = [
	"unicast_packets_received",
	"unicast_bytes_received",
	"multicast_packets_received",
	"multicast_bytes_received",
	"broadcast_packets_received",
	"broadcast_bytes_received",
	"unicast_packets_sent",
	"unicast_bytes_sent",
	"multicast_packets_sent",
	"multicast_bytes_sent",
	"broadcast_packets_sent",
	"broadcast_bytes_sent",
];

function failure(msg) {
	err = msg;

	return null;
}

function bpf_map_stats_set(sockbr, ifindex, add) {
	let map = sockbr.bpf_map_stats;
	let key = pack('I', ifindex);
	if (!add)
		return map.delete(key);

	let val = '';
	for (let i = 0; i < 6; i++)
		val += pack('QQ', 0, 0);

	map.set(key, val, bpf.BPF_NOEXIST);
}

function bpf_map_entry_set(sockbr, mac, proto, clone, add) {
	let addr_list = sockbr.addr_list;
	let idx = index(addr_list, null);
	if (idx < 0)
		idx = length(addr_list);

	addr_list[idx] = mac;

	let key = pack('!H', proto) + utils.ether_aton(mac);
	if (!add)
		return sockbr.bpf_map.delete(key);

	let val = pack('HBB', idx, !!clone, 0);
	return sockbr.bpf_map.set(key, val);
}

function bpf_map_address_set(sockbr, mac, add)
{
	bpf_map_entry_set(sockbr, mac ?? defs.IEEE1905_MULTICAST_MAC, usocket.const.ETH_P_1905, false, add);
	bpf_map_entry_set(sockbr, mac ?? defs.LLDP_NEAREST_BRIDGE_MAC, usocket.const.ETH_P_LLDP, true, add);
}

function bpf_init(sockbr) {
	let mod = sockbr.bpf_mod = bpf.open_module('/lib/bpf/umap.o');
	if (!mod)
		return failure('Failed to load BPF module');

	let map = sockbr.bpf_map = mod.get_map('addr_map');
	if (!map)
		return failure('Failed to get BPF address map');

	map = sockbr.bpf_map_stats = mod.get_map('stats_map');
	if (!map)
		return failure('Failed to get BPF stats map');

	let prog = sockbr.bpf_prog_in = mod.get_program('ingress');
	if (!prog)
		return failure('Failed to get ingress BPF program');

	prog = sockbr.bpf_prog_out = mod.get_program('egress');
	if (!prog)
		return failure('Failed to get egress BPF program');

	bpf_map_address_set(sockbr, null, true);

	return true;
}

function bridge_recv(sockbr, payload) {
	let meta = unpack('IH', payload[0]);
	let ifindex = meta[0];

	payload[0] = sockbr.addr_list[''+meta[1]];
	if (!payload[0])
		return;

	let member = sockbr.ifindex_members[''+ifindex];
	if (!member)
		return;

	let proto = unpack('!H', payload[2])[0];
	let vlan = 0;
	if (proto == usocket.const.ETH_P_8021Q) {
		vlan = unpack('!H', substr(payload[3], 0, 2))[0];
		vlan &= 0xfff;
		payload[2] = substr(payload[3], 2, 2);
		payload[3] = substr(payload[3], 4);
		proto = unpack('!H', payload[2])[0];
	}

	payload[1] = utils.ether_ntoa(payload[1]);

	for (let sock in sockbr.sockets) {
		if (!sock.cb)
			continue;
		if (sock.ifname != member.ifname || sock.protocol != proto || sock.vlan_id != vlan)
			continue;

		if (sock.debug_rx) {
			let msg_data = [...payload];

			msg_data[0] = utils.ether_aton(msg_data[0]);
			msg_data[1] = utils.ether_aton(msg_data[1]);
			msg_data[2] = pack('!H', proto);

			sock.debug_rx.add(msg_data);
		}

		call(sock.cb, sock, null, payload);
	}
}

function uloop_handler(flags) {
	let sockbr = this.handle();
	let sock = sockbr.socket;

	while (true) {
		let msg = sock.recvmsg([6, 6, 2, 1504]);
		if (!msg)
			break;

		bridge_recv(sockbr, msg.data);
	}
}

const socket_proto = {
	const: usocket.const,

	send: function(src, dest, data) {
		let smac = hexdec(src ?? this.address, ':'),
			dmac = hexdec(dest, ':'),
			frame;

		if (this.vlan)
			frame = [dmac, smac, this.vlan, this.proto, data];
		else
			frame = [dmac, smac, this.proto, data];

		if (this.debug_tx)
			this.debug_tx.add(frame);

		return this.bridge.socket.sendmsg(frame, null, {
			family: AF_PACKET,
			address: dest,
			interface: this.ifname
		});
	},

	handler: function(cb) {
		this.cb = cb;
	},

	debug_config: usocket.debug_config,

	close: function() {
		let bridge = this.bridge;
		let idx = index(bridge.sockets, this);
		if (idx < 0)
			return;

		if (this.debug_tx)
			this.debug_tx.close();

		if (this.debug_rx)
			this.debug_rx.close();

		splice(bridge.sockets, idx, 1);
	}
};

const bridge_member_proto = {
	close: function() {
		let br = this.bridge;
		delete br.members[this.ifname];
		for (let sock in this.sockets)
			delete sock.member;

		bpf.tc_detach(br.ifname, 'ingress', bpf_prio);
	}
};

const bridge_proto = {
	stats: function (ifname) {
		let ifindex = +readfile(`/sys/class/net/${ifname}/ifindex`);
		let key = pack('I', ifindex);
		let val = this.bpf_map_stats.get(key);
		if (!val)
			return;

		val = unpack('QQQQQQQQQQQQ', val);
		if (!val)
			return;

		let stats = {};
		for (let i = 0; i < length(bpf_stats_keys); i++)
			stats[bpf_stats_keys[i]] = val[i];

		return stats;
	},

	member_update: function(ifname, address, add) {
		let member = this.members[ifname];
		if (!member)
			member = this.members[ifname] = {
				ifname,
				bridge: this
			};

		let ifindex = add ? +readfile(`/sys/class/net/${ifname}/ifindex`) : 0;
		if (member.ifindex && member.ifindex != ifindex) {
			bpf_map_stats_set(this, member.ifindex, false);
			delete this.ifindex_members[''+member.ifindex];
		}

		if (!add || (member.address && address != member.address))
			bpf_map_address_set(this, member.address, false);

		if (!add) {
			delete this.members[ifname];
			this.bpf_prog.tc_detach(ifname, 'ingress', bpf_prio);
			this.bpf_prog.tc_detach(ifname, 'egress', bpf_prio);
			return true;
		}

		if (!ifindex)
			return failure(`Could not get ifindex for interface ${ifname}`);

		member.ifindex = ifindex;
		member.address = address;
		this.ifindex_members[''+ifindex] = member;
		bpf_map_address_set(this, member.address, true);
		if (access(`/sys/class/net/${ifname}/phy80211`)) {
			if (!this.bpf_prog_out.tc_attach(ifname, 'egress', bpf_prio, this.ifindex))
				return failure(`Failed to attach BPF program to bridge member ${ifname}`);

			bpf_map_stats_set(this, ifindex, true);
		}

		if (!this.bpf_prog_in.tc_attach(ifname, 'ingress', bpf_prio, this.ifindex))
			return failure(`Failed to attach BPF program to bridge member ${ifname}`);

		return true;
	},

	create: function(ifname, protocol, vlan_id) {
		vlan_id ??= 0;
		let vlan = vlan_id ? pack('!HH', usocket.const.ETH_P_8021Q, vlan_id) : null;

		let sock = proto({
			ifname, protocol, vlan, vlan_id,
			proto: pack('!H', protocol),
			bridge: this,
		}, socket_proto);

		this.sockets ??= [];
		push(this.sockets, sock);

		return sock;
	},

	fileno: function () {
		return this.socket.fileno();
	},

	close: function() {
		for (let name, member in this.members)
			member.close();

		if (this.handle)
			this.handle.delete();

		if (this.socket)
			this.socket.close();

		rtrequest(rtc.RTM_DELLINK, rtc.NLM_F_REQUEST, {
			dev: this.ifname
		});
	}
};

function sockfail(sockbr, msg) {
	sockbr.close();
	return failure(msg);
}

export default {
	error: function () {
		let msg = err;

		err = null;

		return msg;
	},

	create: function(ifname, macaddr) {
		let sockbr = proto({
			ifname, macaddr,
			addr_list: [],
			sockets: [],
			members: {},
			ifindex_members: {},
		}, bridge_proto);

		if (!bpf_init(sockbr))
			return;

		bpf_map_address_set(sockbr, macaddr, true);
		rtrequest(rtc.RTM_DELLINK, rtc.NLM_F_REQUEST, {
			dev: ifname
		});
		rterror();

		rtrequest(rtc.RTM_NEWLINK, rtc.NLM_F_REQUEST | rtc.NLM_F_CREATE, {
			ifname,
			linkinfo: {
				type: 'ifb'
			}
		});
		let err = rterror();
		if (err)
			return sockfail(sockbr, `Failed to create bridge socket interface ${ifname}: ${err}`);

		rtrequest(rtc.RTM_SETLINK, rtc.NLM_F_REQUEST, {
			dev: ifname,
			change: 1,
			flags: 1
		});
		err = rterror();
		if (err)
			return sockfail(sockbr, `Failed to start bridge socket interface ${ifname}: ${err}`);

		sockbr.ifindex = +readfile(`/sys/class/net/${ifname}/ifindex`);
		if (!sockbr.ifindex)
			return sockfail(sockbr, `Failed to get ifindex for bridge socket interface ${ifname}`);

		let sock = sockbr.socket = socket(AF_PACKET, SOCK_RAW | SOCK_NONBLOCK, 0);
		if (!sock)
			return sockfail(sockbr, `Unable to create raw packet socket: ${sockerr()}`);

		sock.setopt(SOL_SOCKET, SO_REUSEADDR, true);

		let sa = {
			family: AF_PACKET,
			protocol: usocket.const.ETH_P_ALL,
			address: '',
			interface: ifname
		};

		if (!sock.bind(sa))
			return sockfail(sockbr, `Unable to bind packet socket: ${sockerr()}`);

		let mr = {
			type: PACKET_MR_PROMISC,
			interface: ifname
		};
		if (!sock.setopt(SOL_PACKET, PACKET_ADD_MEMBERSHIP, mr))
			return sockfail(sock, "Unable to enable promiscuous mode");

		sockbr.handle = uloop.handle(sockbr, uloop_handler, uloop.ULOOP_READ | uloop.ULOOP_EDGE_TRIGGER);
		if (!sockbr.handle)
			return sockfail(sockbr, `Unable to create uloop handle`);

		return sockbr;
	}
};
