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

import { request as rtrequest, 'const' as rtconst } from 'rtnl';
import { socket, error as sockerr } from 'umap.socket.raw';
import { pack } from 'struct';

import utils from 'umap.utils';
import log from 'umap.log';

let err;

function failure(msg) {
	err = msg;

	return null;
}

export default {
	const: {
		ETH_P_8021Q: 0x8100,
		ETH_P_LLDP:  0x88cc,
		ETH_P_1905:  0x893a,
	},

	error: function() {
		let msg = err;

		err = null;

		return msg;
	},

	create: function(ifname, ethproto, vlan) {
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

		let sock = socket(ifname, ethproto);

		if (!sock)
			return failure(sockerr());

		return proto({
			address, ifname, bridge, vlan,
			socket: sock,
			protocol: ethproto,
			ports: {}
		}, this);
	},

	send: function(src, dest, data) {
		let smac = hexdec(src ?? this.address, ':'),
		    dmac = hexdec(dest, ':'),
		    frame;

		if (this.vlan)
			frame = pack('!6s6sHHH*', dmac, smac, this.const.ETH_P_8021Q, this.vlan, this.protocol, data);
		else
			frame = pack('!6s6sH*', dmac, smac, this.protocol, data);

		return this.socket.send(dest, frame);
	},

	recv: function() {
		let frame = this.socket.recv();

		if (!frame)
			return failure(sockerr());

		let dstmac = utils.ether_ntoa(frame, 0);
		let srcmac = utils.ether_ntoa(frame, 6);
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
			ord(frame, 12) * 256 + ord(frame, 13),
			substr(frame, 14),
			ifcmac, ifcname
		];
	},

	close: function() {
		return this.socket.close();
	},

	fileno: function() {
		return this.socket.fileno();
	}
};
