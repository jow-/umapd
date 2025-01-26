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
	SOL_SOCKET, SO_REUSEADDR,
	SOL_PACKET, PACKET_ADD_MEMBERSHIP,
	PACKET_MR_MULTICAST, PACKET_MR_PROMISC
} from 'socket';

import { request as rtrequest, 'const' as rtconst } from 'rtnl';
import { pack, unpack } from 'struct';

import utils from 'umap.utils';
import defs from 'umap.defs';
import log from 'umap.log';

let err;

function failure(msg) {
	err = msg;

	return null;
}

const ntohs = (pack('H', 0x0102) == '\x02\x01')
	? v => ((v & 0xff) << 8) | ((v & 0xff00) >> 8)
	: v => v;

export default {
	const: {
		ETH_P_8021Q: 0x8100,
		ETH_P_LLDP: 0x88cc,
		ETH_P_1905: 0x893a,
	},

	error: function () {
		let msg = err;

		err = null;

		return msg;
	},

	create: function (ifname, ethproto, vlan) {
		let sock, pr = +ethproto;
		let upper = ifname;
		let address, bridge;
		let sa, mr;

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

		// Create a raw socket with non-blocking behavior
		sock = socket(AF_PACKET, SOCK_RAW | SOCK_NONBLOCK, ntohs(pr));

		if (!sock)
			return failure("Unable to create raw packet socket");

		// Set SO_REUSEADDR option
		if (!sock.setopt(SOL_SOCKET, SO_REUSEADDR, true)) {
			sock.close();
			return failure("Unable to set SO_REUSEADDR socket option");
		}

		// Bind the socket to the specified interface
		sa = {
			family: AF_PACKET,
			protocol: pr,
			address: "00:00:00:00:00:00",
			interface: ifname
		};

		if (!sock.bind(sa)) {
			sock.close();
			return failure("Unable to bind packet socket");
		}

		// Enable multicast and promiscuous mode for specific protocols
		if (pr == this.const.ETH_P_1905 || pr == this.const.ETH_P_LLDP) {
			mr = {
				type: PACKET_MR_MULTICAST,
				interface: ifname,
				address: (pr == this.const.ETH_P_LLDP)
					? defs.LLDP_NEAREST_BRIDGE_MAC
					: defs.IEEE1905_MULTICAST_MAC
			};

			if (!sock.setopt(SOL_PACKET, PACKET_ADD_MEMBERSHIP, mr)) {
				sock.close();
				return failure("Unable to add socket multicast membership");
			}

			mr = {
				type: PACKET_MR_PROMISC,
				interface: ifname
			};

			if (!sock.setopt(SOL_PACKET, PACKET_ADD_MEMBERSHIP, mr)) {
				sock.close();
				return failure("Unable to enable promiscuous mode");
			}
		}

		return proto({
			address, ifname, bridge,
			socket: sock,
			protocol: pack('!H', ethproto),
			vlan: vlan ? pack('!HH', this.const.ETH_P_8021Q, vlan) : null,
			ports: {}
		}, this);
	},

	send: function (src, dest, data) {
		let smac = hexdec(src ?? this.address, ':'),
			dmac = hexdec(dest, ':'),
			frame;

		if (this.vlan)
			frame = [dmac, smac, this.vlan, this.protocol, data];
		else
			frame = [dmac, smac, this.protocol, data];

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

		let dstmac = utils.ether_ntoa(msg.data[0]);
		let srcmac = utils.ether_ntoa(msg.data[1]);
		let ifcmac = this.address;
		let ifcname = this.ifname;

		/* Determine RX interface */
		let rxdev = this.ifname;

		if (this.bridge) {
			let search = {
				family: rtconst.AF_BRIDGE,
				master: this.bridge,
				lladdr: srcmac
			};

			if (this.vlan)
				search.vlan = this.vlan;

			let neigh = rtrequest(rtconst.RTM_GETNEIGH, 0, search);

			if (neigh) {
				let rxdev = ifcname = neigh.dev;

				if (!this.ports[rxdev]) {
					let link = rtrequest(rtconst.RTM_GETLINK, 0, { dev: rxdev });

					if (link)
						ifcmac = this.ports[rxdev] = link.address;
					else
						log.warn(`Failed to query link information for bridge ${this.bridge} port ${rxdev}: ${rtnl.error()}`);
				}
				else {
					ifcmac = this.ports[rxdev];
				}
			}
			else {
				log.warn(`No FDB entry for source MAC ${srcmac} on bridge ${this.bridge}`);
			}
		}

		return [
			dstmac,
			srcmac,
			unpack('!H', msg.data[2]),
			msg.data[3],
			ifcmac, ifcname
		];
	},

	close: function () {
		return this.socket.close();
	},

	fileno: function () {
		return this.socket.fileno();
	}
};
