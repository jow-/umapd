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

import { readfile, open } from 'fs';
import { pack, unpack } from 'struct';

import { encoder, decoder, extended_encoder, extended_decoder } from 'umap.tlv.codec';

import utils from 'umap.utils';
import defs from 'umap.defs';
import log from 'umap.log';


export default {
	create: function (type, payload) {
		if (type < 0 || type > 0xff || length(payload) > 0xffff)
			return null;

		return proto({
			type,
			length: length(payload) ?? 0,
			payload
		}, this);
	},

	parse: function (buf) {
		let tlv_type = buf.get('B');
		let tlv_len = buf.get('!H');

		if (tlv_type === null || tlv_len === null || buf.pos() + tlv_len > buf.length())
			return null;

		return proto({
			type: tlv_type,
			length: tlv_len,
			payload: buf.get(tlv_len)
		}, this);
	},

	decode: function (type, payload) {
		type ??= this.type;
		payload ??= this.payload;

		if (type === defs.TLV_EXTENDED)
			return extended_decoder[unpack('!H', payload)]?.(payload);

		return decoder[type]?.(payload);
	},

	encode: function (type, ...args) {
		let buf = buffer();

		if (type === defs.TLV_EXTENDED) {
			let subtype = shift(args);

			buf.put('!H', subtype);
			buf = extended_encoder[subtype]?.(buf, ...args);
		}
		else {
			buf = encoder[type]?.(buf, ...args);
		}

		if (buf == null)
			return null;

		return proto({
			type,
			length: buf.length(),
			payload: buf.slice()
		}, this);
	}
};
