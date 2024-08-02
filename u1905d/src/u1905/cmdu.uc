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

import { pack, unpack, buffer } from 'struct';

import utils from 'u1905.utils';
import log from 'u1905.log';
import defs from 'u1905.defs';

import * as codec from 'u1905.tlv.codec';

const ETHERNET_HEADER_LENGTH = 14;
const IEEE1905_HEADER_LENGTH = 8;
const TLV_HEADER_LENGTH = 3;
const TLV_EXTENDED_HEADER_LENGTH = 5;
const IEEE1905_MAX_PAYLOAD_LENGTH = 1500 - ETHERNET_HEADER_LENGTH - IEEE1905_HEADER_LENGTH;
const CMDU_MAX_PAYLOAD_LENGTH = IEEE1905_MAX_PAYLOAD_LENGTH - TLV_HEADER_LENGTH /* EOF TLV */;
const TLV_MAX_PAYLOAD_LENGTH = CMDU_MAX_PAYLOAD_LENGTH - TLV_HEADER_LENGTH /* TLV type + TLV length */;

const CMDU_MESSAGE_VERSION = 0;

const CMDU_F_LASTFRAG = 0b10000000;
const CMDU_F_ISRELAY  = 0b01000000;

const CMDU_MAX_CONCURRENT_REASSEMBLY = 16;
const CMDU_MAX_PAYLOAD_SIZE = 102400;

let reassembly = utils.Queue(CMDU_MAX_CONCURRENT_REASSEMBLY);

function alloc_fragment(type, mid, fid, flags) {
	return buffer().put('!BxHHBB', CMDU_MESSAGE_VERSION, type, mid, fid, flags);
}

function decode_tlv(msg, type, start, end) {
	if (type !== defs.TLV_EXTENDED) {
		const decode = codec.decoder[type];

		if (decode == null) {
			log.warn(`CMDU ${msg.srcmac}#${msg.mid}: Unrecognized TLV type ${type} at offset ${start}`);
			return null;
		}

		const data = decode(msg.buf.pos(start), end);

		if (data == null) {
			log.warn(`CMDU ${msg.srcmac}#${msg.mid}: Invalid payload in TLV type ${type} at offset ${start}`);
			return null;
		}

		return { type, data };
	}
	else {
		const subtype = msg.buf.pos(start).get('!H');
		const decode = codec.extended_decoder[subtype];

		if (decode == null) {
			log.warn(`CMDU ${msg.srcmac}#${msg.mid}: Unrecognized extended TLV type ${type}, subtype ${subtype} at offset ${start}`);
			return null;
		}

		const data = decode(msg.buf, end);

		if (data == null) {
			log.warn(`CMDU ${msg.srcmac}#${msg.mid}: Invalid payload in extended TLV type ${type}, subtype ${subtype} at offset ${start}`);
			return null;
		}

		return { type, subtype, data };
	}
}

function parse_tlvs(buf) {
	const end = buf.length();
	const tlvs = [];

	for (let off = buf.pos(); off + TLV_HEADER_LENGTH <= end; buf.pos(off = tlvs[-1])) {
		const tlv_type = buf.get('B');
		const tlv_len = buf.get('!H');

		if (off + TLV_HEADER_LENGTH + tlv_len > end) {
			log.warn(`Unexpected EOF while parsing CMDU TLV ${tlv_type} - want ${tlv_len} bytes, have ${end - off + TLV_HEADER_LENGTH}`);
			return null;
		}

		push(tlvs, tlv_type, off + TLV_HEADER_LENGTH, off + TLV_HEADER_LENGTH + tlv_len);
	}

	return tlvs;
}

function cmdu_name(type) {
	for (let k, v in defs)
		if (v === type && index(k, 'MSG_') === 0)
			return substr(k, 4);
}

function tlv_name(type) {
	for (let k, v in defs)
		if (v === type && index(k, 'TLV_') === 0)
			return substr(k, 4);
}


export default {
	mid_counter: 0,

	create: function(type, mid) {
		return proto({
			type,
			mid: mid ?? (++this.mid_counter % 65536),
			buf: buffer(),
			tlvs: []
		}, this);
	},

	parse: function(srcmac, payload) {
		// ensure minimum length
		if (length(payload) < IEEE1905_HEADER_LENGTH + TLV_HEADER_LENGTH) {
			log.debug('CMDU packet too short');
			return null;
		}

		const buf = buffer(payload);
		const header = buf.read('!BxHHBB');

		const version = header[0];
		const type = header[1];
		const mid = header[2];
		const fid = header[3];
		const flags = header[4];

		// verify version
		if (version != CMDU_MESSAGE_VERSION) {
			log.debug('Unexpected message version in CMDU');
			return null;
		}

		// shortcut: non-fragmented packet
		if (fid == 0 && (flags & CMDU_F_LASTFRAG)) {
			let tlvs = parse_tlvs(buf.pos(IEEE1905_HEADER_LENGTH));

			if (tlvs == null) {
				log.warn(`CMDU ${srcmac}#${mid}: Invalid message payload`);
				return null;
			}

			if (tlvs[-3] !== defs.TLV_END_OF_MESSAGE) {
				log.warn(`CMDU ${srcmac}#${mid}: Missing End-Of-Message TLV`);
				return null;
			}

			return proto({
				srcmac,
				flags,
				type,
				mid,
				buf,
				tlvs
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
			log.warn(`CMDU ${srcmac}#${mid}: Duplicate fragment #${fid} received`);
			return null;
		}

		// already seen last fragment, ensure that fid is below
		if ((msg.flags & CMDU_F_LASTFRAG) && fid >= length(msg.fragments)) {
			log.warn(`CMDU ${srcmac}#${mid}: Bogus trailing fragment #${fid} received`);
			return null;
		}

		msg.flags |= flags;
		msg.fragments[fid] = buf;

		// reassemble fragments
		if (msg.flags & CMDU_F_LASTFRAG) {
			// return on yet missing fragments (fragments were received out of order)
			for (let i = 0; i < length(msg.fragments); i++) {
				if (msg.fragments[fid] == null) {
					log.debug(`CMDU ${srcmac}#${mid}: Fragments received out of order, fragment ${i+1} of ${length(msg.fragments)} missing`);
					return msg;
				}
			}

			// all fragments present, reassemble message
			msg.buf = shift(msg.fragments);

			while (msg.fragments[0] != null)
				msg.buf.end().put('*', shift(msg.fragments).slice(IEEE1905_HEADER_LENGTH));

			msg.buf.pos(IEEE1905_HEADER_LENGTH);

			let tlvs = parse_tlvs(msg.buf);

			if (tlvs == null) {
				log.warn(`CMDU ${srcmac}#${mid}: Invalid message payload`);
				return null;
			}

			if (tlvs[-3] !== defs.TLV_END_OF_MESSAGE) {
				log.warn(`CMDU ${srcmac}#${mid}: Missing End-Of-Message TLV`);
				return null;
			}

			msg.tlvs = tlvs;

			reassembly.remove(msg);

			delete msg.fragments;
		}

		return msg;
	},

	is_complete: function() {
		return !this.fragments;
	},

	ensure_eom: function() {
		if (this.tlvs[-3] !== defs.TLV_END_OF_MESSAGE) {
			const offset = this.tlvs[-1] ?? IEEE1905_HEADER_LENGTH;

			this.buf.pos(offset).put('!BH', defs.TLV_END_OF_MESSAGE, 0);
			push(this.tlvs, defs.TLV_END_OF_MESSAGE, offset, offset + TLV_HEADER_LENGTH);
		}
	},

	add_tlv: function(type, ...args) {
		let append_eom = false;
		let success = true;
		let offset;

		if (this.tlvs[-3] === defs.TLV_END_OF_MESSAGE) {
			append_eom = true;
			offset = this.tlvs[-2];
			splice(this.tlvs, -3);
		}
		else {
			offset = this.tlvs[-1] ?? IEEE1905_HEADER_LENGTH;
		}

		if (type !== defs.TLV_EXTENDED) {
			const encode = codec.encoder[type];

			if (encode != null && encode(this.buf.pos(offset + TLV_HEADER_LENGTH), ...args)) {
				// encoding successfull, write TLV header
				const tlv_len = this.buf.pos() - offset - TLV_HEADER_LENGTH;
				this.buf.pos(offset).put('!BH', type, tlv_len);
				push(this.tlvs, type, offset, offset + TLV_HEADER_LENGTH + tlv_len);
			}
			else {
				// encoding failure, reset buffer length
				this.buf.length(offset);
				success = false;
			}
		}
		else {
			const subtype = shift(args);
			const encode = codec.extended_encoder[subtype];

			if (encode != null && encode(this.buf.pos(offset + TLV_EXTENDED_HEADER_LENGTH), ...args)) {
				// encoding successfull, write extended TLV header
				const tlv_len = this.buf.pos() - offset - TLV_HEADER_LENGTH;
				this.buf.pos(offset).put('!BHH', defs.TLV_EXTENDED, tlv_len, subtype);
				push(this.tlvs, defs.TLV_EXTENDED, offset, offset + TLV_HEADER_LENGTH + tlv_len);
			}
			else {
				// encoding failure, reset buffer length
				this.buf.length(offset);
				success = false;
			}
		}

		if (append_eom)
			this.ensure_eom();

		return success;
	},

	add_tlv_raw: function(type, payload) {
		let append_eom = false;
		let offset;

		if (this.tlvs[-3] === defs.TLV_END_OF_MESSAGE) {
			append_eom = true;
			offset = this.tlvs[-2];
			splice(this.tlvs, -3);
		}
		else {
			offset = this.tlvs[-1] ?? IEEE1905_HEADER_LENGTH;
		}

		this.buf.pos(offset).put('!BH*', type, length(payload), payload);
		push(this.tlvs, type, offset, offset + TLV_HEADER_LENGTH + length(payload));

		if (append_eom)
			this.ensure_eom();
	},

	get_tlv: function(type) {
		for (let i = 0; this.tlvs[i] !== null; i += 3)
			if (this.tlvs[i] === type)
				return decode_tlv(this, this.tlvs[i], this.tlvs[i+1], this.tlvs[i+2])?.data;
	},

	get_tlv_raw: function(type) {
		for (let i = 0; this.tlvs[i] !== null; i += 3)
			if (this.tlvs[i] === type)
				return this.buf.slice(this.tlvs[i+1], this.tlvs[i+2]);
	},

	get_tlvs: function(...types) {
		const rv = [];

		for (let i = 0; this.tlvs[i] !== null; i += 3) {
			if (!length(types) || this.tlvs[i] in types) {
				const tlv = decode_tlv(this, this.tlvs[i], this.tlvs[i+1], this.tlvs[i+2]);
				if (tlv != null)
					push(rv, tlv);
			}
		}

		return rv;
	},

	get_tlvs_raw: function(...types) {
		const rv = [];

		for (let i = 0; this.tlvs[i] !== null; i += 3) {
			if (!length(types) || this.tlvs[i] in types) {
				push(rv, {
					type: this.tlvs[i],
					payload: this.buf.slice(this.tlvs[i+1], this.tlvs[i+2])
				});
			}
		}

		return rv;
	},

	has_tlv: function(...types) {
		let count = 0;

		for (let i = 0; this.tlvs[i] !== null; i += 3)
			if (this.tlvs[i] in types)
				count++;

		return count;
	},

	send: function(socket, src, dest, flags) {
		let payload_data = [];
		let payload_fmt = [];
		let size = 0;
		let fid = 0;

		log.debug('TX %-8s: %s > %s : %04x (%s) [%d]',
			socket.ifname,
			src, dest,
			this.type,
			cmdu_name(this.type) ?? 'Unknown Type',
			this.mid);

		this.ensure_eom();

		for (let i = 0; this.tlvs[i] !== null; i += 3) {
			if (this.tlvs[i] != 0) {
				log.debug('  TLV %02x (%s) - %d byte',
					this.tlvs[i],
					tlv_name(this.tlvs[i]) ?? 'Unknown TLV',
					this.tlvs[i+2] - this.tlvs[i+1]);
			}
		}

		let cmdu_size = this.tlvs[-1] ?? IEEE1905_HEADER_LENGTH;

		if (cmdu_size <= 1500 - ETHERNET_HEADER_LENGTH) {
			this.buf.start().put('!BxHHBB', CMDU_MESSAGE_VERSION, this.type, this.mid, 0, (flags ?? 0) | CMDU_F_LASTFRAG);

			socket.send(src, dest, this.buf.slice());
		}
		else if (true) {
			log.debug('  ! Requires fragmentation at TLV boundary');

			let payload_len = 0;

			for (let i = 0; this.tlvs[i] !== null; i += 3) {
				let tlv_len = this.tlvs[i+2] - this.tlvs[i+1];

				if (payload_len + tlv_len > IEEE1905_MAX_PAYLOAD_LENGTH) {
					let fragment = alloc_fragment(this.type, this.mid, fid++, flags ?? 0);

					fragment.put('*', this.buf.slice(this.tlvs[i+1] - payload_len, this.tlvs[i+1]));
					socket.send(src, dest, fragment.pull());

					payload_len = 0;
				}

				payload_len += tlv_len;
			}

			let fragment = alloc_fragment(this.type, this.mid, fid++, (flags ?? 0) | CMDU_F_LASTFRAG);

			fragment.put('*', this.buf.slice(-payload_len));
			socket.send(src, dest, fragment.pull());
		}
		else {
			log.debug('  ! Requires fragmentation at octet boundary');

			let offset = IEEE1905_HEADER_LENGTH;

			while (cmdu_size - offset > IEEE1905_MAX_PAYLOAD_LENGTH) {
				let fragment = alloc_fragment(this.type, this.mid, fid++, flags ?? 0);

				fragment.put('*', this.buf.slice(offset, offset + IEEE1905_MAX_PAYLOAD_LENGTH));
				socket.send(src, dest, fragment.pull());

				offset += IEEE1905_MAX_PAYLOAD_LENGTH;
			}

			let fragment = alloc_fragment(this.type, this.mid, fid++, (flags ?? 0) | CMDU_F_LASTFRAG);

			fragment.put('*', this.buf.slice(offset));
			socket.send(src, dest, fragment.pull());
		}
	}
};
