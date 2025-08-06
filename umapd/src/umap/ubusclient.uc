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

import { connect as ubus_connect, error as ubus_error, guard } from 'ubus';
import log from 'umap.log';

let ubusconn = null;
guard((e) => log.exception(e));

export default {
	connect: function () {
		ubusconn ??= ubus_connect();

		return (ubusconn != null);
	},

	error: function () {
		return ubus_error();
	},

	call: function (object, method, args) {
		if (this.connect())
			return ubusconn.call(object, method, args);
	},

	subscriber: function (notify_cb, remove_cb, subscriptions) {
		if (this.connect())
			return ubusconn.subscriber(notify_cb, remove_cb, subscriptions);
	},

	publish: function (namespace, procedures) {
		if (this.connect())
			return ubusconn.publish(namespace, procedures);
	},
};
