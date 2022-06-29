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

const struct = require('struct');
const rtnl = require('rtnl');

const rawsock = require('u1905.socket.raw');

let err;

function failure(msg) {
	err = msg;

	return null;
}

return {
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

	create: function(ifname, ethproto) {
		let link = rtnl.request(rtnl.const.RTM_GETLINK, 0, { dev: ifname });

		if (!link)
			return failure('No such interface');

		let sock = rawsock.socket(ifname, ethproto);

		if (!sock)
			return failure(rawsock.error());

		return proto({
			address: link.address,
			ifname: link.ifname,
			//vlan: (link.linkinfo?.type == 'vlan') ? link.linkinfo.id : null,
			socket: sock,
			protocol: ethproto
		}, this);
	},

	send: function(src, dest, data) {
		let smac = hexdec(src ?? this.address, ':'),
		    dmac = hexdec(dest, ':'),
		    frame;

		//if (this.vlan)
		//	frame = struct.pack('!6s6sHHH*', dmac, smac, this.const.ETH_P_8021Q, this.vlan, this.const.ETH_P_IEEE1905, data);
		//else
			frame = struct.pack('!6s6sH*', dmac, smac, this.protocol, data);

		return this.socket.send(dest, frame);
	},

	recv: function() {
		let frame = this.socket.recv();

		if (!frame)
			return failure(rawsock.error());

		return [
			sprintf('%02x:%02x:%02x:%02x:%02x:%02x', ...struct.unpack('!6B', frame, 0)),
			sprintf('%02x:%02x:%02x:%02x:%02x:%02x', ...struct.unpack('!6B', frame, 6)),
			ord(frame, 12) * 256 + ord(frame, 13),
			substr(frame, 14)
		];
	},

	close: function() {
		return this.socket.close();
	},

	fileno: function() {
		return this.socket.fileno();
	}
};
