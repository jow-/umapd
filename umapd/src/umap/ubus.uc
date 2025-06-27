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

import log from 'umap.log';
import defs from 'umap.defs';
import model from 'umap.model';
import utils from 'umap.utils';
import ubus from 'umap.ubusclient';

const I1905UbusProcedures = {
	get_intf_list: {
		args: {
			ubus_rpc_session: "00000000000000000000000000000000"
		},
		call: function (req) {
			let interfaces = [];

			for (let i1905lif in model.getLocalInterfaces()) {
				let type = i1905lif.getMediaType();

				push(interfaces, {
					address: i1905lif.address,
					type,
					type_name: defs.MEDIA_TYPE[type] ?? 'Unknown/Reserved',
					bridge: i1905lif.isBridged()
				});
			}

			return req.reply({ interfaces });
		}
	},

	get_metric: {
		args: {
			ubus_rpc_session: "00000000000000000000000000000000",
			macaddress: "00:00:00:00:00:00"
		},
		call: function (req) {
			let mac = lc(req.args.macaddress ?? '00:00:00:00:00:00');

			if (!match(mac, /^[0-9a-f][0-9a-f]:[0-9a-f][0-9a-f]:[0-9a-f][0-9a-f]:[0-9a-f][0-9a-f]:[0-9a-f][0-9a-f]:[0-9a-f][0-9a-f]$/i))
				return req.reply(null, 2 /* UBUS_STATUS_INVALID_ARGUMENT */);

			let metrics = [];

			for (let i1905dev in model.getDevices()) {
				if (mac != '00:00:00:00:00:00' && mac != i1905dev.al_address)
					continue;

				if (i1905dev == model.getLocalDevice())
					continue;

				for (let i1905lif in model.getLocalInterfaces()) {
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
							media_type_name: defs.MEDIA_TYPE[t] ?? 'Unknown/Reserved',
							metrics: i1905lif.getLinkMetrics(i1905rif.address)
						});
					}
				}
			}

			if (mac != '00:00:00:00:00:00' && !length(metrics)) {
				let reason = 0x07;
				let reason_name = defs.REASON_CODES[reason];

				return req.reply({ metrics: null, reason, reason_name });
			}
			else {
				let reason = 0x00;
				let reason_name = defs.REASON_CODES[reason];

				return req.reply({ metrics, reason, reason_name });
			}
		}
	},

	get_topology: {
		args: {
			ubus_rpc_session: "00000000000000000000000000000000"
		},
		call: function (req) {
			let res = {
				devices: [],
				links: []
			};

			for (let i1905dev in model.getDevices()) {
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
	},

	dump_database: {
		args: {
			ubus_rpc_session: "00000000000000000000000000000000"
		},
		call: function (req) {
			let devices = {};

			for (let i1905dev in model.getDevices()) {
				let rec = {};

				for (let tlvtype, tlvs in i1905dev.tlvs) {
					const k = utils.tlv_type_ntoa(+tlvtype);

					rec[k] = [];

					for (let i = 1; i < length(tlvs); i++)
						push(rec[k], hexenc(tlvs[i]));
				}

				devices[i1905dev.al_address] = rec;
			}

			return req.reply({ devices });
		}
	},
};

let namespace;

export default {
	connect: () => ubus.connect(),
	error: () => ubus.error(),
	call: (...args) => ubus.call(...args),

	register: function (method, argspec, func) {
		I1905UbusProcedures[method] = {
			args: {
				...(argspec ?? {}),
				ubus_rpc_session: '00000000000000000000000000000000'
			},
			call: func
		};
	},

	publish: function () {
		if (this.connect())
			return (namespace ??= ubus.publish("ieee1905", I1905UbusProcedures));
	},

	notify: function (...args) {
		if (namespace && namespace.subscribed())
			return namespace.notify(...args);
	}
};
