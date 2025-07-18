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
import lldp from 'umap.lldp';
import defs from 'umap.defs';
import utils from 'umap.utils';

import proto_autoconf from 'umap.proto.autoconf';

import { timer, interval } from 'uloop';


const TOPOLOGY_DISCOVERY_DELAY = 500;

const TOPOLOGY_DISCOVERY_INTERVAL = 60000;
const TOPOLOGY_SENDNOTIFY_INTERVAL = 1000;
const TOPOLOGY_SELFUPDATE_INTERVAL = 5000;
const TOPOLOGY_NODEUPDATE_INTERVAL = 30000;
const TOPOLOGY_CLEANUP_INTERVAL = 5000;

let started = false;

function emit_topology_discovery() {
	this.set(TOPOLOGY_DISCOVERY_INTERVAL);

	for (let i1905lif in model.getLocalInterfaces()) {
		let lldpdu = lldp.create(model.address, i1905lif.address, 180);

		lldpdu.send(i1905lif.lldpsock);

		let msg = cmdu.create(defs.MSG_TOPOLOGY_DISCOVERY);

		msg.add_tlv(defs.TLV_IEEE1905_AL_MAC_ADDRESS, model.address);
		msg.add_tlv(defs.TLV_MAC_ADDRESS, i1905lif.address);

		msg.send(i1905lif.i1905sock, model.address, defs.IEEE1905_MULTICAST_MAC);
	}
}

function emit_topology_notification() {
	if (!model.topologyChanged)
		return;

	let reply = cmdu.create(defs.MSG_TOPOLOGY_NOTIFICATION);

	reply.add_tlv(defs.TLV_IEEE1905_AL_MAC_ADDRESS, model.address);

	for (let i1905lif in model.getLocalInterfaces())
		reply.send(i1905lif.i1905sock, model.address, defs.IEEE1905_MULTICAST_MAC, defs.CMDU_F_ISRELAY);

	model.topologyChanged = false;
}

function update_node_information() {
	const i1905lifs = model.getLocalInterfaces();

	for (let i1905dev in model.getDevices()) {
		let query;

		// query device information
		query = cmdu.create(defs.MSG_TOPOLOGY_QUERY);

		for (let i1905lif in i1905lifs)
			query.send(i1905lif.i1905sock, model.address, i1905dev.al_address);

		// query link metrics
		query = cmdu.create(defs.MSG_LINK_METRIC_QUERY);
		query.add_tlv(defs.TLV_LINK_METRIC_QUERY, { query_type: 0x00, /* all neighbors */ link_metrics_requested: 0x02 /* both Rx and Tx */ });

		for (let i1905lif in i1905lifs)
			query.send(i1905lif.i1905sock, model.address, i1905dev.al_address);

		if (model.isController) {
			// query higher layer info
			query = cmdu.create(defs.MSG_HIGHER_LAYER_QUERY);

			for (let i1905lif in i1905lifs)
				query.send(i1905lif.i1905sock, model.address, i1905dev.al_address);

			// query backhaul sta capability
			query = cmdu.create(defs.MSG_BACKHAUL_STA_CAPABILITY_QUERY);

			for (let i1905lif in i1905lifs)
				query.send(i1905lif.i1905sock, model.address, i1905dev.al_address);
		}
	}
}

function send_information_queries(i1905lif, al_mac) {
	let query;

	// query device information
	query = cmdu.create(defs.MSG_TOPOLOGY_QUERY);
	query.send(i1905lif.i1905sock, i1905lif.address, al_mac);

	// query link metrics
	query = cmdu.create(defs.MSG_LINK_METRIC_QUERY);
	query.add_tlv(defs.TLV_LINK_METRIC_QUERY, { query_type: 0x00, /* all neighbors */ link_metrics_requested: 0x02 /* both Rx and Tx */ });
	query.send(i1905lif.i1905sock, i1905lif.address, al_mac);

	// query higher layer info
	query = cmdu.create(defs.MSG_HIGHER_LAYER_QUERY);
	query.send(i1905lif.i1905sock, i1905lif.address, al_mac);

	// query backhaul sta capability
	query = cmdu.create(defs.MSG_BACKHAUL_STA_CAPABILITY_QUERY);
	query.send(i1905lif.i1905sock, model.address, al_mac);

	// query AP capabilities
	query = cmdu.create(defs.MSG_AP_CAPABILITY_QUERY);
	query.send(i1905lif.i1905sock, model.address, al_mac);
}

const IProtoTopology = {
	init: function () {
		model.updateSelf();
	},

	start: function () {
		if (started)
			return;

		timer(TOPOLOGY_DISCOVERY_DELAY,
			() => interval(TOPOLOGY_DISCOVERY_INTERVAL, emit_topology_discovery));

		interval(TOPOLOGY_SELFUPDATE_INTERVAL, () => model.updateSelf());
		interval(TOPOLOGY_CLEANUP_INTERVAL, () => model.collectGarbage());

		interval(TOPOLOGY_SENDNOTIFY_INTERVAL, emit_topology_notification);
		interval(TOPOLOGY_NODEUPDATE_INTERVAL, update_node_information);

		started = true;
	},

	handle_cmdu: function (i1905lif, dstmac, srcmac, msg) {
		const al_mac = msg.get_tlv(defs.TLV_IEEE1905_AL_MAC_ADDRESS);

		if (msg.type == defs.MSG_TOPOLOGY_DISCOVERY) {
			const if_mac = msg.get_tlv(defs.TLV_MAC_ADDRESS);

			if (!al_mac || !if_mac) {
				log.warn(`Ignoring incomplete topology discovery CMDU`);
				return true;
			}

			let dev = model.lookupDevice(al_mac);
			let query;

			if (!dev) {
				dev = model.addDevice(al_mac);

				// is a neighbour not known to us yet, assume it is new
				// and send a counter topology discovery message to speed
				// up the neighbour discovering us
				query = cmdu.create(defs.MSG_TOPOLOGY_DISCOVERY);
				query.add_tlv(defs.TLV_IEEE1905_AL_MAC_ADDRESS, model.address);
				query.add_tlv(defs.TLV_MAC_ADDRESS, i1905lif.address);
				query.send(i1905lif.i1905sock, i1905lif.address, al_mac);
			}

			let iface = dev.addInterface(if_mac);

			i1905lif.addNeighbor(iface);

			iface.updateCMDUTimestamp();

			if (model.isController)
				send_information_queries(i1905lif, al_mac);

			proto_autoconf.start_autoconfiguration();

			return true;
		}
		else if (msg.type == defs.MSG_TOPOLOGY_NOTIFICATION) {
			if (!model.isController)
				return true;

			if (!al_mac) {
				log.warn(`topology: ignoring notification without AL MAC`);
				return true;
			}

			const query = cmdu.create(defs.MSG_TOPOLOGY_QUERY);

			query.send(i1905lif.i1905sock, i1905lif.address, al_mac);

			return true;
		}
		else if (msg.type == defs.MSG_TOPOLOGY_QUERY) {
			// Ignore queries destined to other nodes
			if (dstmac != model.address)
				return true;

			let reply = cmdu.create(defs.MSG_TOPOLOGY_RESPONSE, msg.mid);

			for (let tlv in model.getLocalDevice().getTLVs(
				defs.TLV_IEEE1905_DEVICE_INFORMATION,
				defs.TLV_DEVICE_BRIDGING_CAPABILITY,
				defs.TLV_IEEE1905_NEIGHBOR_DEVICES,
				defs.TLV_NON1905_NEIGHBOR_DEVICES,
				defs.TLV_L2_NEIGHBOR_DEVICE
			)) {
				reply.add_tlv_raw(tlv.type, tlv.payload);
			}

			reply.send(i1905lif.i1905sock, dstmac, srcmac);

			return true;
		}
		else if (msg.type == defs.MSG_LINK_METRIC_QUERY) {
			// Ignore queries destined to other nodes
			if (dstmac != model.address)
				return true;

			let requested_metrics = msg.get_tlv(defs.TLV_LINK_METRIC_QUERY);

			if (!requested_metrics) {
				log.warn(`Ignoring incomplete link metric query CMDU`);
				return true;
			}

			let reply = cmdu.create(defs.MSG_LINK_METRIC_RESPONSE, msg.mid);

			for (let tlv in model.getLocalDevice().getTLVs(
				defs.TLV_IEEE1905_TRANSMITTER_LINK_METRIC,
				defs.TLV_IEEE1905_RECEIVER_LINK_METRIC
			)) {
				if (requested_metrics.al_mac_address == null || utils.ether_ntoa(tlv.payload, 6) == requested_metrics.al_mac_address)
					reply.add_tlv_raw(tlv.type, tlv.payload);
			}

			reply.send(i1905lif.i1905sock, dstmac, srcmac);

			return true;
		}
		else if (msg.type == defs.MSG_TOPOLOGY_RESPONSE) {
			if (!model.isController)
				return true;

			let devinfo = msg.get_tlv(defs.TLV_IEEE1905_DEVICE_INFORMATION);

			if (!devinfo) {
				log.warn(`Ignoring malformed topology response CMDU`);
				return true;
			}

			let i1905dev = model.addDevice(devinfo.al_mac_address);

			for (let peer_if in devinfo.local_interfaces)
				i1905dev.addInterface(peer_if.local_if_mac_address).updateCMDUTimestamp();

			for (let neigh_tlv in msg.get_tlvs(defs.TLV_IEEE1905_NEIGHBOR_DEVICES)) {
				for (let neighbor in neigh_tlv.ieee1905_neighbors) {
					if (!model.lookupDevice(neighbor.neighbor_al_mac_address)) {
						model.addDevice(neighbor.neighbor_al_mac_address);
						send_information_queries(i1905lif, neighbor.neighbor_al_mac_address);
					}
				}
			}

			i1905dev.updateTLVs(msg.get_tlvs_raw());

			return true;
		}
		else if (msg.type == defs.MSG_LINK_METRIC_RESPONSE) {
			let tlvs_by_al_address;

			for (let tlv in msg.get_tlvs_raw(defs.TLV_IEEE1905_TRANSMITTER_LINK_METRIC, defs.TLV_IEEE1905_RECEIVER_LINK_METRIC)) {
				const transmitter_al_mac_address = utils.ether_ntoa(tlv.payload);

				if (!transmitter_al_mac_address) {
					log.warn(`Ignoring malformed metrics reply CMDU`);
					return true;
				}

				push((tlvs_by_al_address ??= {})[transmitter_al_mac_address] ??= [], tlv);
			}

			for (let al_address, tlvs in tlvs_by_al_address) {
				let i1905dev = model.lookupDevice(al_address);

				if (i1905dev)
					i1905dev.updateTLVs(tlvs);
			}

			return true;
		}
		else if (msg.type == defs.MSG_HIGHER_LAYER_QUERY) {
			// Ignore queries destined to other nodes
			if (dstmac != model.address)
				return true;

			let reply = cmdu.create(defs.MSG_HIGHER_LAYER_RESPONSE, msg.mid);

			reply.add_tlv(defs.TLV_IEEE1905_AL_MAC_ADDRESS, model.address);

			for (let tlv in model.getLocalDevice().getTLVs(defs.TLV_IEEE1905_PROFILE_VERSION, defs.TLV_DEVICE_IDENTIFICATION, defs.TLV_CONTROL_URL, defs.TLV_IPV4, defs.TLV_IPV6))
				reply.add_tlv_raw(tlv.type, tlv.payload);

			reply.send(i1905lif.i1905sock, dstmac, srcmac);

			return true;
		}
		else if (msg.type == defs.MSG_HIGHER_LAYER_RESPONSE) {
			let i1905dev = model.lookupDevice(al_mac);

			if (i1905dev)
				i1905dev.updateTLVs(msg.get_tlvs_raw());

			return true;
		}
		else if (msg.type == defs.MSG_COMBINED_INFRASTRUCTURE_METRICS) {
			let i1905dev = model.lookupDevice(srcmac);

			if (!i1905dev) {
				log.debug('Ignoring infrastructure metrics from unknown device %s', srcmac);
				return true;
			}

			i1905dev.updateTLVs(msg.get_tlvs_raw());

			return true;
		}

		return false;
	}
};

export default proto({}, IProtoTopology);
