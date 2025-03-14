#!/usr/bin/env ucode

'use strict';

import { open, error as fserror } from 'fs';
import { cursor } from 'uci';

const ctx = cursor();
const radio = getenv('RADIO');
const network = getenv('NETWORK');
const settings = json(ARGV[0]);

if (type(settings) != 'array' || type(radio) != 'string')
	die("Do not execute this program directly");

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

let has_backhaul_sta = false;

ctx.foreach('wireless', 'wifi-iface', (s) => {
	if (s.device == radio) {
		if (s.mode == 'sta' && s.multi_ap == '1')
			has_backhaul_sta = true;

		ctx.delete('wireless', s['.name']);
	}
});

let disabled = false;

for (let bss in settings) {
	if (bss.multi_ap?.tear_down) {
		disabled = true;
		break;
	}

	if (bss.multi_ap?.is_backhaul_sta && !has_backhaul_sta)
		continue;

	let sid = ctx.add('wireless', 'wifi-iface');
	ctx.set('wireless', sid, 'device', radio);
	ctx.set('wireless', sid, 'mode', bss.multi_ap?.is_backhaul_sta ? 'sta' : 'ap');
	ctx.set('wireless', sid, 'ssid', bss.ssid);
	ctx.set('wireless', sid, 'bssid', bss.multi_ap?.is_backhaul_sta ? null : bss.bssid);
	ctx.set('wireless', sid, 'network', network ?? 'lan');

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

	ctx.set('wireless', sid, 'encryption', enc);

	if (bss.encryption_types & (WPS_ENCR_TKIP | WPS_ENCR_AES))
		ctx.set('wireless', sid, 'key', bss.network_key);

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
				ctx.set('wireless', sid, 'wps_pushbutton', 1);

			ctx.set('wireless', sid, 'multi_ap_backhaul_ssid', other_bss.ssid);

			if (other_bss.encryption_types & (WPS_ENCR_TKIP | WPS_ENCR_AES))
				ctx.set('wireless', sid, 'multi_ap_backhaul_key', other_bss.network_key);
		}
	}

	ctx.set('wireless', sid, 'multi_ap', multi_ap_mode);
	ctx.set('wireless', sid, 'wds', (multi_ap_mode & 1) ? 1 : null);
}

ctx.set('wireless', radio, 'disabled', disabled ? '1' : '0');
ctx.commit('wireless');

system(['/sbin/wifi', 'up', radio]);

lockfd.lock('u');
lockfd.close();
