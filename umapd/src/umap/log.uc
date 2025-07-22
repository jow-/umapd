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

import * as udebug from "udebug";
let verbosity = 0;

export default {
	setVerbosity: (v) => (verbosity = v),

	debug_config: function (config) {
		let enabled = +config.enabled && +config.log;
		let size = +config.log_size;
		if (!size)
			size = 65536;
		let entries = +config.log_entries;
		if (!entries)
			entries = 1024;

		if (this.debug_ring && (this.debug_size != size || this.debug_entries != entries)) {
			this.debug_ring.close();
			delete this.debug_ring;
		}

		if (!!this.debug_ring == !!enabled)
			return;

		if (enabled) {
			let name = config.prefix + " log";
			this.debug_ring = udebug.create_ring({
				name, size, entries
			});
		} else {
			this.debug_ring.close();
			delete this.debug_ring;
		}
	},
	cond_warn: function (cond, prefix, fmt, ...args) {
		if (!cond && !this.debug_ring)
			return;

		let msg = sprintf(`${prefix} ${fmt}`, ...args);
		if (this.debug_ring)
			this.debug_ring.add(msg);
		if (cond)
			warn(msg + "\n");
	},
	debug3: function (fmt, ...args) { this.cond_warn(verbosity > 2, '[D] ', fmt, ...args) },
	debug2: function (fmt, ...args) { this.cond_warn(verbosity > 1, '[D] ', fmt, ...args) },
	debug: function (fmt, ...args) { this.cond_warn(verbosity > 0, '[D] ', fmt, ...args) },
	warn: function (fmt, ...args) { this.cond_warn(true, '[W] ', fmt, ...args) },
	error: function (fmt, ...args) { this.cond_warn(true, '[E] ', fmt, ...args) },
	info: function (fmt, ...args) { this.cond_warn(true, '[I] ', fmt, ...args) },
};
