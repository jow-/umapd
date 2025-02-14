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

import { unpack } from 'struct';

import defs from 'umap.defs';

const Queue = {
	push: function (item) {
		if (item == null || item in this.q)
			return item;

		if (this.maxLength != null && length(this.q) >= this.maxLength)
			this.onRemove?.(shift(this.q));

		push(this.q, item);

		return item;
	},

	find: function (f) {
		for (let e in this.q)
			if (f?.(e))
				return e;
	},

	shift: function () {
		let item = shift(this.q);

		if (item) {
			this.onRemove?.(item);
			return item;
		}
	},

	pop: function () {
		let item = pop(this.q);

		if (item) {
			this.onRemove?.(item);
			return item;
		}
	},

	remove: function (item) {
		for (let i, e in this.q) {
			if (e === item) {
				splice(this.q, i, 1);
				this.onRemove?.(e);
				return item;
			}
		}
	},

	contains: function (item) {
		return (item in this.q);
	},
};

const AgingDict = {
	gc: function (except_key, now) {
		for (let k, v in this.d) {
			if (k != except_key && now - v[0] > this.maxAge) {
				this.onRemove?.(k, v[1]);
				delete this.d[k];
			}
		}
	},

	set: function (key, val) {
		let now = time();

		this.gc(key, now);

		if (exists(this.d, key))
			this.d[key][0] = now;
		else
			this.d[key] = [now, val];

		return val;
	},

	touch: function (key) {
		if (exists(this.d, key)) {
			this.d[key][0] = time();
			return this.d[key][1];
		}

		return null;
	},

	unset: function (key) {
		let val = null;

		this.gc(key, time());

		if (exists(this.d, key)) {
			val = this.d[key][1];
			this.onRemove?.(key, val);
			delete this.d[key];
		}

		return val;
	},

	get: function (key) {
		return this.d[key]?.[1];
	},

	has: function (key) {
		return exists(this.d, key);
	},

	values: function () {
		let rv = [];

		for (let k, v in this.d)
			push(rv, v[1]);

		return rv;
	}
};

export default {
	Queue: (maxLength, onRemove) => proto({
		maxLength,
		onRemove,
		q: []
	}, Queue),

	AgingDict: (maxAge, onRemove) => proto({
		maxAge,
		onRemove,
		d: {}
	}, AgingDict),

	ether_ntoa: function (v, off) {
		let mac = unpack('6B', v, off);
		return mac ? sprintf('%02x:%02x:%02x:%02x:%02x:%02x', ...mac) : null;
	},

	ether_aton: function (mac) {
		return hexdec(mac, ':');
	},

	ether_increment: function (mac, increment) {
		if (increment === 0)
			return mac;

		const bytes = unpack('6B', hexdec(mac, ':'));
		let carry = increment ?? 1;

		for (let i = 5; i >= 0; i--) {
			bytes[i] += carry;
			carry = bytes[i] / 256;
			bytes[i] %= 256;
		}

		bytes[0] |= 0x02;

		return sprintf('%02x:%02x:%02x:%02x:%02x:%02x', ...bytes);
	},

	lookup_enum: function (v, d) {
		for (let k in d)
			if (d[k] == v)
				return k;
	},

	uuid_ntoa: function (uuid) {
		let bytes = (type(uuid) == 'array') ? uuid : unpack('16B', uuid);
		return bytes ? sprintf('%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x', ...bytes) : 0;
	},

	uuid_aton: function (uuid) {
		return hexdec(uuid, '-');
	},

	cmdu_type_ntoa: function (cmdu_type) {
		for (let k, v in defs)
			if (v === cmdu_type && index(k, 'MSG_') === 0)
				return substr(k, 4);
	},

	tlv_type_ntoa: function (tlv_type) {
		for (let k, v in defs)
			if (v === tlv_type && index(k, 'TLV_') === 0)
				return substr(k, 4);
	},
};
