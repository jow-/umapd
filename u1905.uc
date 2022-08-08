#!/usr/bin/env ucode
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

'use strict';

const uloop = require('uloop');

const socket = require('u1905.socket');
const cmdu = require('u1905.cmdu');
const lldp = require('u1905.lldp');
const utils = require('u1905.utils');
const model = require('u1905.model');
const defs = require('u1905.defs');
const ubus = require('u1905.ubus');
const log = require('u1905.log');

function srcmac_to_almac(address) {
	let i1905dev = model.lookupDevice(address);
	return i1905dev?.al_address;
}

function handle_i1905_cmdu(i1905lif, dstmac, srcmac, msg) {
	let al_mac = msg.decode(defs.TLV_AL_MAC_ADDRESS);

	log.debug('RX %-8s: %s > %s : %s (%04x) [%d]',
		i1905lif.ifname,
		srcmac, dstmac,
		defs.getCMDUTypeName(msg.type) ?? 'Unknown Type', msg.type,
		msg.mid);

	for (let tlv in msg.tlvs)
		if (tlv.type != 0)
			log.debug('  TLV %02x (%s) - %d byte',
				tlv.type,
				defs.getTLVTypeName(tlv.type),
				tlv.length);

	// ignore packets looped back to us
	if (al_mac == model.address) {
		log.warn(`Ignoring CMDU originating from our AL MAC (network loop?)`);
		return;
	}

	if (msg.type == defs.MSG_TOPOLOGY_DISCOVERY) {
		let if_mac = msg.decode(defs.TLV_MAC_ADDRESS);

		if (!al_mac || !if_mac) {
			log.warn(`Ignoring incomplete topology discovery CMDU`);
			return;
		}

		let dev = model.lookupDevice(al_mac);
		let query;

		if (!dev) {
			dev = model.addDevice(al_mac);

		    // is a neighbour not known to us yet, assume it is new
		    // and send a counter topology discovery message to speed
		    // up the neighbour discovering us
			query = cmdu.create(defs.MSG_TOPOLOGY_DISCOVERY);
			query.add_tlv(defs.TLV_AL_MAC_ADDRESS, model.address);
			query.add_tlv(defs.TLV_MAC_ADDRESS, i1905lif.address);
			query.send(i1905lif.i1905txsock, i1905lif.address, al_mac);
		}

		let iface = dev.addInterface(if_mac);

		i1905lif.addNeighbor(iface);

		iface.updateCMDUTimestamp();

		// query device information
		query = cmdu.create(defs.MSG_TOPOLOGY_QUERY);
		query.send(i1905lif.i1905txsock, i1905lif.address, al_mac);

		// query link metrics
		query = cmdu.create(defs.MSG_LINK_METRIC_QUERY);
		query.add_tlv(defs.TLV_LINK_METRIC_QUERY, null /* model.address */, true, true);
		query.send(i1905lif.i1905txsock, i1905lif.address, al_mac);

		// query higher layer info
		query = cmdu.create(defs.MSG_HIGHER_LAYER_QUERY);
		query.send(i1905lif.i1905txsock, i1905lif.address, al_mac);
	}
	else if (msg.type == defs.MSG_TOPOLOGY_QUERY) {
		al_mac = srcmac_to_almac(srcmac);

		if (!al_mac) {
			log.warn('Ignoring topology query from unknown device %s', srcmac);
			return;
		}

		let reply = cmdu.create(defs.MSG_TOPOLOGY_RESPONSE, msg.mid);

		push(reply.tlvs, ...model.getLocalDevice().getTLVs(
			defs.TLV_DEVICE_INFORMATION,
			defs.TLV_DEVICE_BRIDGING_CAPABILITY,
			defs.TLV_IEEE1905_NEIGHBOR_DEVICES,
			defs.TLV_NON1905_NEIGHBOR_DEVICES,
			defs.TLV_L2_NEIGHBOR_DEVICE
		));

		reply.send(i1905lif.i1905txsock, dstmac, al_mac);
	}
	else if (msg.type == defs.MSG_LINK_METRIC_QUERY) {
		al_mac = srcmac_to_almac(srcmac);

		if (!al_mac) {
			log.warn('Ignoring metric query from unknown device %s', srcmac);
			return;
		}

		let requested_metrics = msg.decode(defs.TLV_LINK_METRIC_QUERY);

		if (!requested_metrics) {
			log.warn(`Ignoring incomplete link metric query CMDU`);
			return;
		}

		let reply = cmdu.create(defs.MSG_LINK_METRIC_RESPONSE, msg.mid);

		for (let tlv in model.getLocalDevice().getTLVs(
			defs.TLV_LINK_METRIC_TX,
			defs.TLV_LINK_METRIC_RX
		)) {
			if (requested_metrics.mac == null || utils.ether_ntoa(tlv.payload, 6) == requested_metrics.mac)
				push(reply.tlvs, tlv);
		}

		reply.send(i1905lif.i1905txsock, dstmac, al_mac);
	}
	else if (msg.type == defs.MSG_TOPOLOGY_RESPONSE) {
		let devinfo = msg.decode(defs.TLV_DEVICE_INFORMATION);

		if (!devinfo) {
			log.warn(`Ignoring malformed topology response CMDU`);
			return;
		}

		let i1905dev = model.addDevice(devinfo.al_address);

		i1905dev.updateTLVs(msg.tlvs);
	}
	else if (msg.type == defs.MSG_LINK_METRIC_RESPONSE) {
		for (let tlv in msg.tlvs) {
			if (tlv.type == defs.TLV_LINK_METRIC_RX) {
				let rx_metrics = tlv.decode();

				if (!rx_metrics) {
					log.warn(`Ignoring malformed metrics reply CMDU`);
					return;
				}

				let i1905dev = model.lookupDevice(rx_metrics.al_address);

				if (i1905dev)
					i1905dev.updateTLVs([ tlv ]);
			}
			else if (tlv.type == defs.TLV_LINK_METRIC_TX) {
				let tx_metrics = tlv.decode();

				if (!tx_metrics) {
					log.warn(`Ignoring malformed metrics reply CMDU`);
					return;
				}

				let i1905dev = model.lookupDevice(tx_metrics.al_address);

				if (i1905dev)
					i1905dev.updateTLVs([ tlv ]);
			}
		}
	}
	else if (msg.type == defs.MSG_HIGHER_LAYER_QUERY) {
		al_mac = srcmac_to_almac(srcmac);

		if (!al_mac) {
			log.warn('Ignoring higher layer query from unknown device %s', srcmac);
			return;
		}

		let reply = cmdu.create(defs.MSG_HIGHER_LAYER_RESPONSE, msg.mid);

		reply.add_tlv(defs.TLV_AL_MAC_ADDRESS, model.address);
		reply.add_tlv(defs.TLV_1905_PROFILE_VERSION, 0x01 /* IEEE 1905.1a */);
		reply.add_tlv(defs.TLV_DEVICE_IDENTIFICATION, null, null, null);

		// TODO: discover web interface presence
		reply.add_tlv(defs.TLV_CONTROL_URL, 'http://192.168.1.1');

		push(reply.tlvs, ...model.getLocalDevice().getTLVs(defs.TLV_IPV4, defs.TLV_IPV6));

		reply.send(i1905lif.i1905txsock, dstmac, al_mac);
	}
	else if (msg.type == defs.MSG_HIGHER_LAYER_RESPONSE) {
		let i1905dev = model.lookupDevice(al_mac);

		if (i1905dev)
			i1905dev.updateTLVs(msg.tlvs);
	}

	if (msg.flags & defs.CMDU_F_ISRELAY) {
		// unknown origin
		if (!al_mac) {
			log.warn(`Not relaying multicast message without AL MAC TLV`);
			return;
		}

		// already sent by us
		if (al_mac == model.address && msg.mid < cmdu.mid_counter) {
			log.warn(`Not relaying already sent multicast message`);
			return;
		}

		for (let i1905lif2 in model.getLocalInterfaces())
			if (i1905lif2.i1905rxsock != i1905lif.i1905rxsock)
				msg.send(i1905lif2.i1905txsock, i1905lif2.address, defs.IEEE1905_MULTICAST_MAC);
	}
}

function handle_i1905_input(flags) {
	let sock = this.handle();

	while (true) {
		let payload = sock.recv();

		if (!payload)
			break;

		let i1905lif = model.lookupLocalInterface(payload[5] ?? sock);
		let msg = cmdu.parse(payload[1], payload[3]);

		if (!msg)
			log.debug('RX %-8s: %s > %s : Invalid CMDU', payload[5], payload[1], payload[0]);
		else if (msg.is_complete())
			handle_i1905_cmdu(i1905lif, payload[0], payload[1], msg);
	}
}

function handle_lldp_input(flags) {
	let sock = this.handle();

	while (true) {
		let payload = sock.recv();

		if (!payload)
			break;

		let i1905lif = model.lookupLocalInterface(payload[5] ?? sock);
		let msg = lldp.parse(payload[3]);

		if (!msg) {
			log.warn(`Ignoring incomplete/malformed LLDPU`);
			continue;
		}

		if (msg.chassis == model.address) {
			log.warn(`Ignoring LLDPU originating from our AL MAC (network loop?)`);
			continue;
		}

		model.addDevice(msg.chassis).addInterface(msg.port).updateLLDPTimestamp();
	}
}

function update_self() {
	this.set(5000);

	model.updateSelf();
}

function emit_topology_discovery() {
	this.set(60000);

	for (let i1905lif in model.getLocalInterfaces()) {
		let lldpdu = lldp.create(model.address, i1905lif.address, 180);

		lldpdu.send(i1905lif.lldptxsock);

		let msg = cmdu.create(defs.MSG_TOPOLOGY_DISCOVERY);

		msg.add_tlv(defs.TLV_AL_MAC_ADDRESS, model.address);
		msg.add_tlv(defs.TLV_MAC_ADDRESS, i1905lif.address);

		msg.send(i1905lif.i1905txsock, model.address, defs.IEEE1905_MULTICAST_MAC);

	}
}

function emit_topology_notification() {
	this.set(1000);

	if (!model.topologyChanged)
		return;

	let reply = cmdu.create(defs.MSG_TOPOLOGY_NOTIFICATION);

	reply.add_tlv(defs.TLV_AL_MAC_ADDRESS, model.address);

	for (let i1905lif in model.getLocalInterfaces())
		reply.send(i1905lif.i1905txsock, model.address, defs.IEEE1905_MULTICAST_MAC, defs.CMDU_F_ISRELAY);

	model.topologyChanged = false;
}


uloop.init();

for (let ifname in ARGV) {
	let ifc = model.addLocalInterface(ifname);

	if (ifc) {
		uloop.handle(ifc.i1905rxsock, handle_i1905_input, uloop.ULOOP_READ|uloop.ULOOP_EDGE_TRIGGER);
		uloop.handle(ifc.lldprxsock, handle_lldp_input, uloop.ULOOP_READ|uloop.ULOOP_EDGE_TRIGGER);
	}
	else {
		log.error(`Unable to initialize interface ${ifname}: ${socket.error()}`);
		exit(1);
	}
}

model.initializeAddress();

if (!ubus.publish())
	log.warn(`Unable to publish ieee1905 object: ${ubus.error()}`);

uloop.timer(250, update_self);
uloop.timer(500, emit_topology_discovery);
uloop.timer(1000, emit_topology_notification);

uloop.run();

