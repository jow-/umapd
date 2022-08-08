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

const utils = require('u1905.utils');
const defs = require('u1905.defs');

return {
	create: function(chassis, port, ttl) {
		return proto({ chassis, port, ttl }, this);
	},

	parse: function(payload) {
		let chassis, port, ttl;
		let offset = 0;

		while (true) {
			let tl = struct.unpack('!BB', payload, offset);

			if (!tl || (tl[0] == 0 && tl[1] == 0))
				break;

			let t = tl[0] >> 1;
			let l = ((tl[0] & 1) << 8) | tl[1];

			if (offset + l + 2 > length(payload))
				return null;

			if (t == 0x1 && l == 7) {
				let v = struct.unpack('!B6s', payload, offset + 2);

				if (v?.[0] == 4)
					chassis = utils.ether_ntoa(v[1]);
			}
			else if (t == 0x2 && l == 7) {
				let v = struct.unpack('!B6s', payload, offset + 2);

				if (v?.[0] == 3)
					port = utils.ether_ntoa(v[1]);
			}
			else if (t == 0x3 && l == 2) {
				let v = struct.unpack('!H', payload, offset + 2);

				if (v)
					ttl = v[0];
			}

			offset += l + 2;
		}

		if (!chassis || !port || !ttl)
			return null;

		return proto({ chassis, port, ttl }, this);
	},

	send: function(socket) {
		return socket.send(socket.address, defs.LLDP_NEAREST_BRIDGE_MAC, struct.pack('!3B6s 3B6s 2BH H',
			(0x1 << 1), 7, 4,			// Chassis ID TLV, subtype 4 (LL address)
			hexdec(this.chassis, ':'),	// Chassis ID TLV MAC

			(0x2 << 1), 7, 3,			// Port ID TLV, subtype 3 (MAC)
			hexdec(this.port, ':'),		// Port ID TLV MAC

			(0x3 << 1), 2,				// TTL TLV
			this.ttl, 					// TTL TLV value

			0	 						// EOF TLV
		));
	}
};
