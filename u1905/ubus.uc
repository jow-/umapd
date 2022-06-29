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

const defs = require('u1905.defs');
const ubus = require('ubus');

let i1905al = null;
let ubusconn = null;

const I1905UbusProcedures = {
	get_intf_list: {
		args: {},
		call: function(req) {
			let interfaces = [];

			for (let i1905lif in i1905al.getLocalInterfaces()) {
				let type = i1905lif.getMediaType();

				push(interfaces, {
					address: i1905lif.address,
					type,
					type_name: defs.MEDIA_TYPES[type] ?? 'Unknown/Reserved',
					bridge: i1905lif.isBridged()
				});
			}

			return req.reply({ interfaces });
		}
	},

	get_metric: {
		args: {
			macaddress: "00:00:00:00:00:00"
		},
		call: function(req) {
			let mac = lc(req.args.macaddress ?? '00:00:00:00:00:00');

			if (!match(mac, /^[0-9a-f][0-9a-f]:[0-9a-f][0-9a-f]:[0-9a-f][0-9a-f]:[0-9a-f][0-9a-f]:[0-9a-f][0-9a-f]:[0-9a-f][0-9a-f]$/i))
				return req.reply(null, 2 /* UBUS_STATUS_INVALID_ARGUMENT */);

			let metrics = [];

			for (let i1905dev in i1905al.getDevices()) {
				if (mac != '00:00:00:00:00:00' && mac != i1905dev.al_address)
					continue;

				if (i1905dev == i1905al.getLocalDevice())
					continue;

				for (let i1905lif in i1905al.getLocalInterfaces()) {
					for (let i1905rif in i1905lif.getNeighbors()) {
						if (i1905rif.getDevice() != i1905dev)
							continue;

						let t = i1905lif.getMediaType();

						push(metrics, {
							neighbor_al_address: i1905dev.al_address,
							remote_address: i1905rif.address,
							local_address: i1905lif.address,
							is_bridge: i1905rif.isBridged(),
							media_type: t,
							media_type_name: defs.MEDIA_TYPES[t] ?? 'Unknown/Reserved',
							metrics: i1905lif.getLinkMetrics(i1905rif.address)
						});
					}
				}
			}

			if (mac != '00:00:00:00:00:00' && !length(metrics)) {
				return req.reply({
					metrics: null,
					reason: 0x07 /* UNMATCHED_NEIGHBOR_MAC_ADDRESS */,
					reason_name: 'UNMATCHED_NEIGHBOR_MAC_ADDRESS'
				});
			}
			else {
				return req.reply({
					metrics,
					reason: 0x00 /* SUCCESS */,
					reason_name: 'SUCCESS'
				});
			}
		}
	},

	get_topology: {
		args: {},
		call: function(req) {
			let res = {
				devices: [],
				links: []
			};

			for (let i1905dev in i1905al.getDevices()) {
				if (!i1905dev.isIEEE1905())
					continue;

				let links = i1905dev.getLinks();
				let ipaddrs = i1905dev.getIPAddrs();

				let info = i1905dev.dumpInformation();
				push(res.devices, {
					al_address: i1905dev.al_address,
					identification: i1905dev.getIdentification(),
					interfaces: [],
					...info
				});

				for (let address, iface in i1905dev.getInterfaceInformation()) {
					push(res.devices[-1].interfaces, {
						...iface,
						...(ipaddrs[address] ?? {}),
						links: links[address] ?? {}
					});
				}
			}

			return req.reply(res);
		}
	}
};

return {
	connect: function() {
		ubusconn ??= ubus.connect();

		return (ubusconn != null);
	},

	error: function() {
		return ubus.error();
	},

	publish: function(al) {
		i1905al = al;

		if (this.connect())
			return ubusconn.publish("ieee1905", I1905UbusProcedures);
	},

	call: function(object, method, args) {
		if (this.connect())
			return ubusconn.call(object, method, args);
	}
};
