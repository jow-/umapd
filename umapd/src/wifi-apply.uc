#!/usr/bin/env ucode

'use strict';

import { connect as ubus_connect, error as ubus_error } from 'ubus';
import { open, error as fserror } from 'fs';

const radio = getenv('RADIO');
const network = getenv('NETWORK');
const settings = json(ARGV[0]);

if (type(settings) != 'array' || type(radio) != 'string')
	die("Do not execute this program directly");

const STATEFILE_PATH = '/etc/umap-wireless-status.json';

const WPS_AUTH_OPEN = 0x0001;
const WPS_AUTH_WPAPSK = 0x0002;
const WPS_AUTH_WPA = 0x0008;
const WPS_AUTH_WPA2 = 0x0010;
const WPS_AUTH_WPA2PSK = 0x0020;
const WPS_AUTH_SAE = 0x0040;

const WPS_ENCR_NONE = 0x0001;
const WPS_ENCR_TKIP = 0x0004;
const WPS_ENCR_AES = 0x0008;

const lockfd = open('/var/lock/wifi-apply.lock', 'w');

if (!lockfd || !lockfd.lock('x'))
	die(`Unable to lock /var/lock/wifi-apply.lock: ${fserror()}`);

function equal(a, b) {
	const t1 = type(a), t2 = type(b);

	if (t1 != t2)
		return false;

	if (t1 == 'object') {
		if (length(a) != length(b))
			return false;

		for (let k, v in a)
			if (!(k in b) || !equal(v, b[k]))
				return false;

		for (let k in b)
			if (!(k in a))
				return false;
	}
	else if (t1 == 'array') {
		if (length(a) != length(b))
			return false;

		for (let i, v in a)
			if (!equal(v, b[i]))
				return false;
	}
	else if (a != b) {
		return false;
	}

	return true;
}

function bss_cmp(a, b) {
	for (let field in ['mode', 'ssid', 'bssid'])
		if (a[field] != b[field])
			return (a[field] < b[field]) ? -1 : 1;

	return 0;
}


const ubus = ubus_connect();

if (!ubus)
	die(`Unable to connect to ubus: ${ubus_error()}`);

let has_backhaul_sta = false;

const new_instances = { [radio]: {} };
const cur_instances = ubus.call('service', 'get_data', {
	name: 'umap-agent',
	type: 'wifi-iface'
})?.['umap-agent']?.['wifi-iface'] ?? {};

for (let state_radio, state_bsses in cur_instances) {
	if (state_radio != radio) {
		new_instances[state_radio] = state_bsses;
	}
	else {
		for (let key, bss in state_bsses)
			if (bss.config?.mode == 'sta' && bss.config?.multi_ap == 1)
				has_backhaul_sta = true;
	}
}

const counter = {};

for (let bss in sort(settings, bss_cmp)) {
	if (bss.multi_ap?.tear_down)
		break;

	if (bss.multi_ap?.is_backhaul_sta && !has_backhaul_sta)
		continue;

	const mode = bss.multi_ap?.is_backhaul_sta ? 'sta' : 'ap';
	const instance = new_instances[radio][`${mode}${counter[mode]++}`] = {
		device: radio,
		config: {
			mode: mode,
			ssid: bss.ssid,
			network: network ?? 'lan',
		}
	};

	if (!bss.multi_ap?.is_backhaul_sta)
		instance.config.bssid = bss.bssid;

	// Determine base encryption type
	let enc;

	if (bss.authentication_types & WPS_AUTH_SAE)
		enc = 'sae';
	else if ((bss.authentication_types & WPS_AUTH_WPA2PSK) && (bss.authentication_types & WPS_AUTH_WPAPSK))
		enc = 'psk2-mixed';
	else if (bss.authentication_types & WPS_AUTH_WPA2PSK)
		enc = 'psk2';
	else if (bss.authentication_types & WPS_AUTH_WPAPSK)
		enc = 'psk';
	else
		enc = 'none';

	// Append cipher types
	let ciphers = [];

	if (bss.encryption_types & WPS_ENCR_TKIP)
		push(ciphers, 'tkip');

	if (bss.encryption_types & WPS_ENCR_AES)
		push(ciphers, 'aes');

	if (length(ciphers))
		enc += '+' + join('+', ciphers);

	instance.config.encryption = enc;

	if (bss.encryption_types & (WPS_ENCR_TKIP | WPS_ENCR_AES))
		instance.config.key = bss.network_key;

	// Set multi ap operation mode
	let multi_ap_mode = 0;

	if (bss.multi_ap?.is_backhaul_bss || bss.multi_ap?.is_backhaul_sta)
		multi_ap_mode |= 1;

	if (bss.multi_ap?.is_fronthaul_bss) {
		multi_ap_mode |= 2;

		for (let other_bss in settings) {
			if (other_bss === bss)
				continue;

			if (!other_bss.multi_ap?.is_backhaul_bss)
				continue;

			if (bss.authentication_types & (WPS_AUTH_WPAPSK | WPS_AUTH_WPA2PSK))
				instance.config.wps_pushbutton = true;

			instance.config.multi_ap_backhaul_ssid = other_bss.ssid;

			if (other_bss.encryption_types & (WPS_ENCR_TKIP | WPS_ENCR_AES))
				instance.config.multi_ap_backhaul_key = other_bss.network_key;
		}
	}

	if (multi_ap_mode > 0)
		instance.config.multi_ap = multi_ap_mode;

	if (multi_ap_mode & 1)
		instance.config.wds = true;
}

if (!equal(cur_instances, new_instances)) {
	ubus.call('service', 'set', {
		name: 'umap-agent',
		data: { 'wifi-iface': new_instances }
	});

	ubus.call('network', 'reload');

	const statefile = open(STATEFILE_PATH, 'w');

	if (statefile) {
		statefile.write(new_instances);
		statefile.close();
	}
	else {
		warn(`Unable to open ${STATEFILE_PATH} for writing: ${fserror()}\n`);
	}
}

lockfd.lock('u');
lockfd.close();
