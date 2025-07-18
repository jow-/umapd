/*
 * Copyright (c) 2025 Jo-Philipp Wich <jo@mein.io>.
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

const handlers = {};

export default {
    register: function(eventtype, callback) {
        push(handlers[eventtype] ??= [], callback);
    },

    unregister: function(eventtype, callback) {
        for (let i = 0; i < length(handlers[eventtype]); i++) {
            if (handlers[eventtype][i] === callback) {
                splice(handlers[eventtype], i, 1);

                return true;
            }
        }

        return false;
    },

    dispatch: function(eventtype, payload) {
        if (!(eventtype in handlers))
            return false;

        for (let fn in handlers[eventtype])
            fn(payload);

        return true;
    },
};
