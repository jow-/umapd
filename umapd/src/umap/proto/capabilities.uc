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

import log from 'umap.log';
import model from 'umap.model';
import cmdu from 'umap.cmdu';
import defs from 'umap.defs';
import wireless from 'umap.wireless';

import { timer } from 'uloop';


const REPLY_HANDLER_TIMEOUT = 3000;
const callbacks = {};

function run_callback(msg) {
	if (!exists(callbacks, msg.mid))
		return false;

	callbacks[msg.mid][1].cancel();
	callbacks[msg.mid][0](msg);

	delete callbacks[msg.mid];

	return true;
}

function register_callback(msg, func) {
	if (type(func) == 'function') {
		callbacks[msg.mid] = [
			func,
			timer(REPLY_HANDLER_TIMEOUT, () => {
				callbacks[msg.mid][0](null);
				delete callbacks[msg.mid];
			})
		];
	}
}

const IProtoCapabilities = {
	init: function () { },

	query_ap_capability: function (address, reply_cb) {
		const i1905dev = model.lookupDevice(address);

		if (!i1905dev)
			return null;

		const query = cmdu.create(defs.MSG_AP_CAPABILITY_QUERY);

		register_callback(query, reply_cb);

		for (let i1905lif in model.getLocalInterfaces())
			query.send(i1905lif.i1905sock, model.address, i1905dev.al_address);

		return true;
	},

	query_backhaul_sta_capability: function (address, reply_cb) {
		const i1905dev = model.lookupDevice(address);

		if (!i1905dev)
			return null;

		const query = cmdu.create(defs.MSG_BACKHAUL_STA_CAPABILITY_QUERY);

		register_callback(query, reply_cb);

		for (let i1905lif in model.getLocalInterfaces())
			query.send(i1905lif.i1905sock, model.address, i1905dev.al_address);

		return true;
	},

	handle_cmdu: function (i1905lif, dstmac, srcmac, msg) {
		// disregard CMDUs not directed to our AL
		if (dstmac != model.address)
			return false;

		if (msg.type === defs.MSG_AP_CAPABILITY_QUERY) {
			const reply = cmdu.create(defs.MSG_AP_CAPABILITY_REPORT, msg.mid);

			reply.add_tlv(defs.TLV_AP_CAPABILITY, {
				onchannel_unassoc_sta_metrics: false,
				offchannel_unassoc_sta_metrics: false,
				agent_initiated_rcpi_steering: false
			});

			for (let radio in wireless.radios) {
				reply.add_tlv(defs.TLV_AP_RADIO_BASIC_CAPABILITIES,
					radio.getBasicCapabilities());

				let caps;

				if ((caps = radio.getHTCapabilities()) != null)
					reply.add_tlv(defs.TLV_AP_HT_CAPABILITIES, caps);

				if ((caps = radio.getVHTCapabilities()) != null)
					reply.add_tlv(defs.TLV_AP_VHT_CAPABILITIES, caps);

				if ((caps = radio.getHECapabilities()) != null)
					reply.add_tlv(defs.TLV_AP_HE_CAPABILITIES, caps);

				// TODO: [Profile 2, 3 TLVs]

				reply.add_tlv(defs.TLV_AP_RADIO_ADVANCED_CAPABILITIES, {
					radio_unique_identifier: radio.address,
					combined_front_back: true,
					combined_profile1_profile2: true,
					mscs: false,
					scs: false,
					qos_map: false,
					dscp_policy: false
				});
			}

			log.debug(`capabilities: sending AP capability report to ${srcmac}`);

			reply.send(i1905lif.i1905sock, model.address, srcmac);

			return true;
		}
		else if (msg.type === defs.MSG_AP_CAPABILITY_REPORT) {
			return run_callback(msg);
		}
		else if (msg.type === defs.MSG_BACKHAUL_STA_CAPABILITY_QUERY) {
			const reply = cmdu.create(defs.MSG_BACKHAUL_STA_CAPABILITY_REPORT, msg.mid);

			for (let radio in wireless.radios) {
				reply.add_tlv(defs.TLV_BACKHAUL_STA_RADIO_CAPABILITIES, {
					radio_unique_identifier: radio.address,
					mac_address: radio.getBackhaulStationAddress()
				});
			}

			log.debug(`capabilities: sending backhaul STA capability report to ${srcmac}`);

			reply.send(i1905lif.i1905sock, model.address, srcmac);

			return true;
		}
		else if (msg.type === defs.MSG_BACKHAUL_STA_CAPABILITY_REPORT) {
			if (!run_callback(msg) && model.isController) {
				let i1905dev = model.lookupDevice(srcmac);

				if (i1905dev)
					i1905dev.updateTLVs(msg.get_tlvs_raw(defs.TLV_BACKHAUL_STA_RADIO_CAPABILITIES));
			}

			return true;
		}

		return false;
	}
};

export default proto({}, IProtoCapabilities);
