/*
 * Copyright (c) 2022 Jo-Philipp Wich <jo@mein.io>.
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
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

import { request as rtrequest, 'const' as rtconst } from 'rtnl';
import { pack } from 'struct';
import * as udebug from 'udebug';

import utils from 'umap.utils';
import defs from 'umap.defs';

let err;

function failure(msg) {
	err = msg;

	return null;
}

function sockfail(sock, msg) {
	const serr = sock.error();

	sock.close();
	err = `${msg}: ${serr}`;

	return null;
}

export default {
	const: {
		ETH_P_8021Q: 0x8100,
		ETH_P_LLDP: 0x88cc,
		ETH_P_1905: 0x893a,
		ETH_P_ALL: 0x0003,
	},

	error: function () {
		let msg = err;

		err = null;

		return msg;
	},

	create: function (ifname, ethproto, vlan) {
		let upper = ifname;
		let address, bridge;

		while (true) {
			let link = rtrequest(rtconst.RTM_GETLINK, 0, { dev: upper });

			if (!link)
				return failure('No such interface');

			address ??= link.address;

			switch (link.linkinfo?.type) {
				case 'vlan':
					upper = link.link;
					continue;

				case 'bridge':
					bridge = upper;
					break;
			}

			break;
		}

		let sock = socket(AF_PACKET, SOCK_RAW | SOCK_NONBLOCK, 0);

		if (!sock)
			return failure(`Unable to create raw packet socket: ${sockerr()}`);

		if (!sock.setopt(SOL_SOCKET, SO_REUSEADDR, true))
			return sockfail(sock, `Unable to set SO_REUSEADDR option`);

		let sa = {
			family: AF_PACKET,
			protocol: ethproto,
			address: "",
			interface: ifname
		};

		/* If the interface requires VLAN awareness (which should only be the
		 * case for tagged bridge ports being part of a bridge VLAN) we need
		 * to do extra work to properly deal with frame reception:
		 *
		 *  - Enable reception of all protocols with ETH_P_ALL
		 *  - Install BPF filter to discard non-VLAN, wrong ethertype frames
		 *
		 * In all other cases (binding to a non-bridge port tagged interface,
		 * binding to untagged bridge ports) the kernel takes care of dealing
		 * with VLAN decapsulation.
		 */
		if (vlan) {
			const prog = {
				filter: [
					0x28, 0, 0, 0xfffff004, // Load pkttype
					0x15, 16, 0, 0x00000004, // Drop if outgoing
					0x30, 0, 0, 0xfffff030, // Load VLAN_TAG_PRESENT flag
					0x15, 4, 0, 0x00000001, // If present skip fallback check
					0x28, 0, 0, 0x0000000c, // Load ethertype at offset 12
					0x15, 2, 0, 0x00008100, // 802.1Q ?
					0x15, 1, 0, 0x000088a8, // QinQ ?
					0x15, 0, 10, 0x00009100, // QinQ ?
					0x30, 0, 0, 0xfffff030, // Reload VLAN_TAG_PRESENT flag
					0x15, 0, 2, 0x00000001, // If not present load tag from offset 14
					0x30, 0, 0, 0xfffff02c, // Load VLAN tag from skb info
					0x05, 0, 0, 0x00000001, // Skip next instruction
					0x28, 0, 0, 0x0000000e, // Load VLAN tag from offset 14
					0x54, 0, 0, 0x00000fff, // Mask priority bits
					0x15, 0, 3, vlan, // VLAN ID matches?
					0x28, 0, 0, 0xfffff000, // Load protocol from skb info
					0x15, 0, 1, ethproto, // Protocol matches?
					0x6, 0, 0, 0x00002000, // Return true
					0x6, 0, 0, 0x00000000, // Drop
				]
			};

			if (!sock.setopt(SOL_SOCKET, SO_ATTACH_FILTER, prog))
				return sockfail(sock, `Unable to set socket filter`);

			sa.protocol = this.const.ETH_P_ALL;
		}
		else {
			const prog = {
				filter: [
					0x28, 0, 0, 0xfffff004, // Load pkttype
					0x15, 3, 0, 0x00000004, // Drop if outgoing
					0x28, 0, 0, 0x0000000c, // Load ethertype at offset 12
					0x15, 0, 1, ethproto, // Protocol matches?
					0x6, 0, 0, 0x00002000, // Return true
					0x6, 0, 0, 0x00000000, // Drop
				]
			};

			if (!sock.setopt(SOL_SOCKET, SO_ATTACH_FILTER, prog))
				return sockfail(sock, `Unable to set socket filter`);

			sa.protocol = this.const.ETH_P_ALL;
		}

		if (!sock.bind(sa))
			return sockfail(sock, `Unable to bind packet socket`);

		if (ethproto == this.const.ETH_P_1905 || ethproto == this.const.ETH_P_LLDP) {
			let mr = {
				type: PACKET_MR_MULTICAST,
				interface: ifname,
				address: (ethproto == this.const.ETH_P_LLDP)
					? defs.LLDP_NEAREST_BRIDGE_MAC
					: defs.IEEE1905_MULTICAST_MAC
			};

			if (!sock.setopt(SOL_PACKET, PACKET_ADD_MEMBERSHIP, mr))
				return sockfail(sock, "Unable to add socket multicast membership");

			mr = {
				type: PACKET_MR_PROMISC,
				interface: ifname
			};

			if (!sock.setopt(SOL_PACKET, PACKET_ADD_MEMBERSHIP, mr))
				return sockfail(sock, "Unable to enable promiscuous mode");
		}

		return proto({
			address, ifname, bridge,
			socket: sock,
			protocol: pack('!H', ethproto),
			vlan_id: vlan,
			vlan: vlan ? pack('!HH', this.const.ETH_P_8021Q, vlan) : null,
			ports: {}
		}, this);
	},

	debug_config: function(config) {
		let size = config?.packet_size;
		if (!size)
			size = 131072;

		let entries = config?.packet_entries;
		if (!entries)
			entries = 512;

		let size_changed = this.debug_size != size || this.debug_entries != entries;
		for (let mode in [ "tx", "rx" ]) {
			let enabled = +config.enabled && +config["packet_" + mode];
			let field = "debug_" + mode;

			if (size_changed && this[field]) {
				this[field].close();
				delete this[field];
			}

			if (!!enabled == !!this[field])
				continue;

			if (enabled) {
				let name = config.prefix + " " + this.ifname;
				if (this.vlan_id)
					name += "." + vlan_id;
				name += " " + mode;
				if (this.ethproto == this.const.ETH_P_LLDP)
					name += " lldp";
				else if (this.ethproto == this.const.ETH_P_1905)
					name += " 1905";
				else if (this.ethproto > 0)
					name += sprintf("0x%04x", this.ethproto);

				let format = udebug.DLT_ETHERNET;
				this[field] = udebug.create_ring({
					name, size, entries, format
				});
			} else {
				this[field].close();
				delete this[field];
			}
		}
	},

	send: function (src, dest, data) {
		let smac = hexdec(src ?? this.address, ':'),
			dmac = hexdec(dest, ':'),
			frame;

		if (this.vlan)
			frame = [dmac, smac, this.vlan, this.protocol, data];
		else
			frame = [dmac, smac, this.protocol, data];

		if (this.debug_tx)
			this.debug_tx.add(frame);

		return this.socket.sendmsg(frame, null, {
			family: AF_PACKET,
			address: dest,
			interface: this.ifname
		});
	},

	recv: function () {
		let msg = this.socket.recvmsg([6, 6, 2, 1504]);

		if (!msg)
			return failure(sockerr());

		if (this.debug_rx)
			this.debug_rx.add(msg.data);

		return [
			utils.ether_ntoa(msg.data[0]),
			utils.ether_ntoa(msg.data[1]),
			(ord(msg.data[2], 0) << 8) | ord(msg.data[2], 1),
			msg.data[3]
		];
	},

	close: function () {
		if (this.debug_tx)
			this.debug_tx.close();

		if (this.debug_rx)
			this.debug_rx.close();

		return this.socket.close();
	},

	fileno: function () {
		return this.socket.fileno();
	}
};
