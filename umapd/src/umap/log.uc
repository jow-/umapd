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

let verbosity = 0;

export default {
	setVerbosity: (v) => (verbosity = v),

	debug3: function (fmt, ...args) { (verbosity > 2 ? warn(sprintf(`[D] ${fmt}\n`, ...args)) : null) },
	debug2: function (fmt, ...args) { (verbosity > 1 ? warn(sprintf(`[D] ${fmt}\n`, ...args)) : null) },
	debug: function (fmt, ...args) { (verbosity > 0 ? warn(sprintf(`[D] ${fmt}\n`, ...args)) : null) },
	warn: function (fmt, ...args) { warn(sprintf(`[W] ${fmt}\n`, ...args)) },
	error: function (fmt, ...args) { warn(sprintf(`[E] ${fmt}\n`, ...args)) },
	info: function (fmt, ...args) { warn(sprintf(`[I] ${fmt}\n`, ...args)) }
};
