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

const fs = require('fs');
const rtnl = require('rtnl');
const struct = require('struct');
const nl80211 = require('nl80211');
const i1905tlv = require('u1905.tlv');
const utils = require('u1905.utils');
const log = require('u1905.log');
const defs = require('u1905.defs');

const ETHERNET_HEADER_LENGTH = 14;
const IEEE1905_HEADER_LENGTH = 8;
const CMDU_MAX_PAYLOAD_LENGTH = 1500 - ETHERNET_HEADER_LENGTH - IEEE1905_HEADER_LENGTH - 3 /* EOF TLV */;
const TLV_MAX_PAYLOAD_LENGTH = CMDU_MAX_PAYLOAD_LENGTH - 3 /* TLV type + TLV length */;

const CMDU_MESSAGE_VERSION = 0;

const CMDU_F_LASTFRAG = 0b10000000;
const CMDU_F_ISRELAY  = 0b01000000;

const CMDU_MAX_CONCURRENT_REASSEMBLY = 16;
const CMDU_MAX_PAYLOAD_SIZE = 102400;

let reassembly = utils.Queue(CMDU_MAX_CONCURRENT_REASSEMBLY);

function send_fragment(socket, src, dest, type, mid, fid, payload_fmt, payload_data, flags) {
	return socket.send(src, dest, struct.pack(`!BxHHBB${join('', payload_fmt)}`,
		CMDU_MESSAGE_VERSION,
		type,
		mid,
		fid,
		flags,
		...payload_data
	));
}

function parse_fragment(tlvs) {
	let payload = [];
	let offset = 0;

	while (true) {
		let tlv = i1905tlv.parse(tlvs, offset);

		if (!tlv)
			break;

		push(payload, tlv);

		offset += tlv.length + 3;
	}

	return payload;
}

return {
	mid_counter: 0,

	create: function(type, mid) {
		return proto({
			type,
			mid: mid ?? (++this.mid_counter % 65536),
			tlvs: []
		}, this);
	},

	parse: function(srcmac, payload) {
		// ensure minimum length
		if (length(payload) < IEEE1905_HEADER_LENGTH + 3) {
			log.debug('CMDU packet too short');
			return null;
		}

		let pktdata = struct.unpack('!BxHHBB*', payload),
		    version = pktdata[0],
		    type = pktdata[1],
		    mid = pktdata[2],
		    fid = pktdata[3],
		    flags = pktdata[4],
		    tlvs = pktdata[5];

		// verify version
		if (version != CMDU_MESSAGE_VERSION) {
			log.debug('Unexpected message version in CMDU');
			return null;
		}

		// shortcut: non-fragmented packet
		if (fid == 0 && (flags & CMDU_F_LASTFRAG)) {
			let payload = parse_fragment(tlvs);

			// require EOM TLV
			if (payload?.[-1]?.type != 0)
				return null;

			return proto({
				srcmac,
				flags,
				type,
				mid,
				tlvs: payload
			}, this);
		}

		// find message in reassembly buffer
		let msg = reassembly.find(e => (e.srcmac == srcmac && e.type == type && e.mid == mid));

		// no reassemble entry, create
		if (!msg) {
			// add entry
			msg = proto({
				srcmac,
				flags,
				type,
				mid,
				fragments: []
			}, this);

			reassembly.push(msg);
		}

		// reject duplicate fragment
		else if (msg.fragments[fid]) {
			return null;
		}

		// already seen last fragment, ensure that fid is below
		if ((msg.flags & CMDU_F_LASTFRAG) && fid >= length(msg.fragments))
			return null;

		// parse fragment TLVs
		let frag = parse_fragment(tlvs);

		// malformed
		if (!frag)
			return null;

		// require EOM TLV in last fragment
		if ((flags & CMDU_F_LASTFRAG) && frag?.[-1]?.type != 0)
			return null;

		msg.flags |= flags;
		msg.fragments[fid] = frag;

		// check for missing fragments
		if (msg.flags & CMDU_F_LASTFRAG) {
			let payload = [];

			for (fid = 0; fid < length(msg.fragments); fid++)
				if (msg.fragments[fid])
					push(payload, ...msg.fragments[fid]);
				else
					return msg;

			delete msg.fragments;

			msg.tlvs = payload;
			reassembly.remove(msg);
		}

		return msg;
	},

	is_complete: function() {
		return !this.fragments;
	},

	add_tlv: function(...args) {
		let tlv = i1905tlv.encode(...args);

		if (tlv)
			push(this.tlvs, tlv);
	},

	get_tlv: function(type) {
		for (let tlv in this.tlvs)
			if (tlv.type == type)
				return tlv;
	},

	decode: function(type) {
		let res;

		if (type) {
			for (let tlv in this.tlvs)
				if (tlv.type === type)
					return tlv.decode();

			return null;
		}

		for (let tlv in this.tlvs)
			push(res ??= [], [ tlv.type, tlv.decode() ]);

		return res;
	},

	send: function(socket, src, dest, flags) {
		let payload_data = [];
		let payload_fmt = [];
		let size = 0;
		let fid = 0;

		log.debug('TX: %s > %s : %s (%04x) [%d]',
			src, dest,
			defs.getCMDUTypeName(this.type) ?? 'Unknown Type', this.type,
			this.mid);

		if (this.tlvs[-1]?.type != 0)
			this.add_tlv(0);

		for (let tlv in this.tlvs) {
			let tlv_data = struct.pack('!BH*', tlv.type, tlv.length, tlv.payload);
			let tlv_length = length(tlv_data);

			assert(tlv_length <= CMDU_MAX_PAYLOAD_LENGTH, 'TLV too large');

			if (size + tlv_length > CMDU_MAX_PAYLOAD_LENGTH) {
				send_fragment(socket, src, dest, this.type, this.mid, fid++, payload_fmt, payload_data, (flags ?? 0));

				size = tlv_length;
				payload_fmt = [ '*' ];
				payload_data = [ tlv_data ];
				continue;
			}

			size += tlv_length;
			push(payload_fmt, '*');
			push(payload_data, tlv_data);
		}

		send_fragment(socket, src, dest, this.type, this.mid, fid, payload_fmt, payload_data, (flags ?? 0) | CMDU_F_LASTFRAG);
	}
};
