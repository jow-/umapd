import { pack, unpack, buffer } from 'struct';
import { readfile } from 'fs';
import log from 'log';
import { sha256, hmac_sha256, aes_encrypt, aes_decrypt, dh_keypair, dh_sharedkey } from 'u1905.crypto';
import wireless from 'umap.wireless';

import model from 'u1905.model';
import utils from 'u1905.utils';

// Constants
const ATTR_VERSION = 0x104a;
const ATTR_MSG_TYPE = 0x1022;
const WPS_M1 = 0x04;
const WPS_M2 = 0x05;
const ATTR_SSID = 0x1045;
const ATTR_UUID_E = 0x1047;
const ATTR_UUID_R = 0x1048;
const ATTR_MAC_ADDR = 0x1020;
const ATTR_ENROLLEE_NONCE = 0x101a;
const ATTR_REGISTRAR_NONCE = 0x1039;
const ATTR_PUBLIC_KEY = 0x1032;
const ATTR_AUTH_TYPE_FLAGS = 0x1004;
const ATTR_AUTHENTICATOR = 0x1005;
const ATTR_ENCR_TYPE_FLAGS = 0x1010;
const ATTR_CONN_TYPE_FLAGS = 0x100d;
const WPS_CONN_ESS = 0x01;
const ATTR_CONFIG_METHODS = 0x1008;
const WPS_CONFIG_PUSHBUTTON = 0x0080;
const ATTR_WPS_STATE = 0x1044;
const WPS_STATE_NOT_CONFIGURED = 1;
const ATTR_ENCR_SETTINGS = 0x1018;
const ATTR_KEY_WRAP_AUTH = 0x101E;
const ATTR_MANUFACTURER = 0x1021;
const ATTR_MODEL_NAME = 0x1023;
const ATTR_MODEL_NUMBER = 0x1024;
const ATTR_NETWORK_KEY = 0x1027;
const ATTR_SERIAL_NUMBER = 0x1042;
const ATTR_PRIMARY_DEV_TYPE = 0x1054;
const WPS_DEV_NETWORK_INFRA = 1;
const WPS_DEV_NETWORK_INFRA_ROUTER = 1;
const ATTR_DEV_NAME = 0x1011;
const ATTR_RF_BANDS = 0x103c;
const ATTR_ASSOC_STATE = 0x1002;
const WPS_ASSOC_NOT_ASSOC = 0;
const WPS_ASSOC_CONN_SUCCESS = 1;
const ATTR_DEV_PASSWORD_ID = 0x1012;
const DEV_PW_PUSHBUTTON = 0x0004;
const ATTR_CONFIG_ERROR = 0x1009;
const WPS_CFG_NO_ERROR = 0;
const ATTR_OS_VERSION = 0x102d;
const ATTR_VENDOR_EXTENSION = 0x1049;
const WPS_VENDOR_ID_WFA_1 = 0x00;
const WPS_VENDOR_ID_WFA_2 = 0x37;
const WPS_VENDOR_ID_WFA_3 = 0x2A;
const WFA_ELEM_VERSION2 = 0x00;
const WFA_ELEM_MULTI_AP = 0x06;
const WPS_VERSION = 0x20;

// Global variables
let last_m1 = null;
let last_key = null;

function build_plain_settings(desiredConfiguration)
{
    let buf = buffer();

    buf.put("!HH*", ATTR_SSID, length(desiredConfiguration.ssid), desiredConfiguration.ssid);
    buf.put("!HHH", ATTR_AUTH_TYPE_FLAGS, 2, desiredConfiguration.authentication_types);
    buf.put("!HHH", ATTR_ENCR_TYPE_FLAGS, 2, desiredConfiguration.encryption_types);
    buf.put("!HH*", ATTR_NETWORK_KEY, length(desiredConfiguration.network_key), desiredConfiguration.network_key);
    buf.put("!HH6s", ATTR_MAC_ADDR, 6, utils.ether_aton(desiredConfiguration.bssid)); // XXX: how to allocate?

	desiredConfiguration.multi_ap ??= {};
	desiredConfiguration.multi_ap.is_backhaul_sta ??= false;
	desiredConfiguration.multi_ap.is_backhaul_bss ??= true;
	desiredConfiguration.multi_ap.is_fronthaul_bss ??= true;
	desiredConfiguration.multi_ap.tear_down ??= false;
	desiredConfiguration.multi_ap.profile1_backhaul_sta_assoc_dissallowed ??= false;
	desiredConfiguration.multi_ap.profile2_backhaul_sta_assoc_dissallowed ??= false;

    buf.put("!HHBBBBBB", ATTR_VENDOR_EXTENSION, 6,
            WPS_VENDOR_ID_WFA_1, WPS_VENDOR_ID_WFA_2, WPS_VENDOR_ID_WFA_3,
            WFA_ELEM_MULTI_AP, 1, 0
            	| (desiredConfiguration.multi_ap.is_backhaul_sta << 0)
            	| (desiredConfiguration.multi_ap.is_backhaul_bss << 1)
            	| (desiredConfiguration.multi_ap.is_fronthaul_bss << 2)
            	| (desiredConfiguration.multi_ap.tear_down << 3)
            	| (desiredConfiguration.multi_ap.profile1_backhaul_sta_assoc_dissallowed << 4)
            	| (desiredConfiguration.multi_ap.profile2_backhaul_sta_assoc_dissallowed << 5)
    );

    return buf.pull();
}

function derive_wps_keys(key, personalization_string, required_length)
{
	let result = "";

	for (let i = 1; length(result) < required_length; i++)
		result += hmac_sha256(key,
			pack("!I*I", i, personalization_string, required_length * 8));

	return substr(result, 0, required_length);
}

function derive_registrar_uuid()
{
	let hash = 0;

	for (let b in unpack("6B", hexdec(model.address, ":")))
		hash = (hash * 31) + b;

	const uuid = [];

	uuid[0] = hash % 256;
	uuid[1] = (uuid[0] * 21) % 256;
	uuid[2] = (uuid[1] * 21) % 256;
	uuid[3] = (uuid[2] * 21) % 256;
	uuid[4] = (uuid[3] * 21) % 256;
	uuid[5] = (uuid[4] * 21) % 256;
	uuid[6] = (((uuid[5] * 21) % 256) & 0x0f) | 0x40;
	uuid[7] = (uuid[6] * 21) % 256;
	uuid[8] = (((uuid[7] * 21) % 256) & 0x3f) | 0x80;
	uuid[9] = (uuid[8] * 21) % 256;
	uuid[10] = (uuid[9] * 21) % 256;
	uuid[11] = (uuid[10] * 21) % 256;
	uuid[12] = (uuid[11] * 21) % 256;
	uuid[13] = (uuid[12] * 21) % 256;
	uuid[14] = (uuid[13] * 21) % 256;
	uuid[15] = (uuid[14] * 21) % 256;

	return uuid;
}

export function wscBuildM1(radio)
{
	let local_device = model.getLocalDevice();
	let buf = buffer();

	buf.put("!HHB", ATTR_VERSION, 1, 0x10);
	buf.put("!HHB", ATTR_MSG_TYPE, 1, WPS_M1);
	buf.put("!HH16B", ATTR_UUID_E, 16, ...radio.deriveUUID());
	buf.put("!HH6s", ATTR_MAC_ADDR, 6, utils.ether_aton(radio.address));

	let enrollee_nonce = readfile("/dev/urandom", 16);
	buf.put("!HH16s", ATTR_ENROLLEE_NONCE, 16, enrollee_nonce);

	let keypair = dh_keypair();
	let priv_key = keypair[0];
	let pub_key = keypair[1];
	buf.put("!HH*", ATTR_PUBLIC_KEY, length(pub_key), pub_key);

	buf.put("!HHH", ATTR_AUTH_TYPE_FLAGS, 2, radio.inferWSCAuthenticationSuites());
	buf.put("!HHH", ATTR_ENCR_TYPE_FLAGS, 2, radio.inferWSCEncryptionTypes());

	const id = local_device.getIdentification();

	buf.put("!HHB", ATTR_CONN_TYPE_FLAGS, 1, WPS_CONN_ESS);
	buf.put("!HHH", ATTR_CONFIG_METHODS, 2, WPS_CONFIG_PUSHBUTTON);
	buf.put("!HHB", ATTR_WPS_STATE, 1, WPS_STATE_NOT_CONFIGURED);
	buf.put("!HH*", ATTR_MANUFACTURER, length(id?.manufacturer_name), id?.manufacturer_name ?? '');
	buf.put("!HH*", ATTR_MODEL_NAME, length(id?.manufacturer_model), id?.manufacturer_model ?? '');
	buf.put("!HH*", ATTR_MODEL_NUMBER, length('unspecified'), 'unspecified');
	buf.put("!HH*", ATTR_SERIAL_NUMBER, length('unspecified'), 'unspecified');

	let oui = "\x00\x50\xf2\x00";
	buf.put("!HHH4sH", ATTR_PRIMARY_DEV_TYPE, 8, WPS_DEV_NETWORK_INFRA, oui, WPS_DEV_NETWORK_INFRA_ROUTER);

	buf.put("!HH*", ATTR_DEV_NAME, length(id?.friendly_name), id?.friendly_name ?? '');

	buf.put("!HHB", ATTR_RF_BANDS, 1, radio.inferWSCRFBands());

	buf.put("!HHH", ATTR_ASSOC_STATE, 2, WPS_ASSOC_NOT_ASSOC);
	buf.put("!HHH", ATTR_DEV_PASSWORD_ID, 2, DEV_PW_PUSHBUTTON);
	buf.put("!HHH", ATTR_CONFIG_ERROR, 2, WPS_CFG_NO_ERROR);
	buf.put("!HHI", ATTR_OS_VERSION, 4, 0x80000001);
	buf.put("!HHBBBBBB", ATTR_VENDOR_EXTENSION, 6,
		WPS_VENDOR_ID_WFA_1, WPS_VENDOR_ID_WFA_2, WPS_VENDOR_ID_WFA_3,
		WFA_ELEM_VERSION2, 1, WPS_VERSION);

	last_m1 = buf.pull();
	last_key = { key: priv_key, mac: radio.address };

	return [ last_m1, last_key ];
};

export function wscProcessM1(m1)
{
	let msg = buffer(m1);
	let settings = {};

	while (true) {
		let attr_type = msg.get('!H');
        let attr_len  = msg.get('!H');

		if (attr_type == null)
            break;

		if (attr_type == ATTR_UUID_E && attr_len == 16)
			settings.uuid = utils.uuid_ntoa(msg.get(16));
		else if (attr_type == ATTR_MAC_ADDR && attr_len == 6)
			settings.bssid = utils.ether_ntoa(msg.get(6));
		else if (attr_type == ATTR_ENROLLEE_NONCE && attr_len == 16)
			settings.enrollee_nonce = msg.get(16);
		else if (attr_type == ATTR_PUBLIC_KEY && attr_len > 0)
			settings.public_key = msg.get(attr_len);
		else if (attr_type == ATTR_AUTH_TYPE_FLAGS && attr_len == 2)
            settings.supported_authentication_types = msg.get('!H');
		else if (attr_type == ATTR_ENCR_TYPE_FLAGS && attr_len == 2)
            settings.supported_encryption_types = msg.get('!H');
		else if (attr_type == ATTR_MANUFACTURER && attr_len > 0)
			settings.manufacturer = msg.get(attr_len);
		else if (attr_type == ATTR_MODEL_NAME && attr_len > 0)
			settings.model_name = msg.get(attr_len);
		else if (attr_type == ATTR_MODEL_NUMBER && attr_len > 0)
			settings.model_number = msg.get(attr_len);
        else if (attr_type == ATTR_SERIAL_NUMBER && attr_len > 0)
            settings.serial_number = msg.get(attr_len);
        else if (attr_type == ATTR_DEV_NAME && attr_len > 0)
            settings.device_name = msg.get(attr_len);
		else if (attr_type == ATTR_RF_BANDS && attr_len == 1)
			settings.supported_bands = msg.get('B');
		else
			msg.pos(msg.pos() + attr_len);
    }

    return settings;
};

export function wscBuildM2(m1, desiredConfiguration)
{
	let local_device = model.getLocalDevice();
	let msg = buffer(m1);

    let m1_mac_address, m1_nonce, m1_pubkey;

    while (true) {
        let attr_type = msg.get('!H');
        let attr_len = msg.get('!H');

		if (attr_type == null)
			break;

        if (attr_type == ATTR_MAC_ADDR && attr_len == 6)
            m1_mac_address = msg.get(6);
        else if (attr_type == ATTR_ENROLLEE_NONCE && attr_len == 16)
            m1_nonce = msg.get(16);
        else if (attr_type == ATTR_PUBLIC_KEY && attr_len > 0)
            m1_pubkey = msg.get(attr_len);
		else
			msg.pos(msg.pos() + attr_len);
    }

    if (!m1_mac_address || !m1_nonce || !m1_pubkey)
		return log.warn(`wsc: ignoring incomplete message received - ignoring M1`);

	let buf = buffer();

    buf.put("!HHB", ATTR_VERSION, 1, 0x10);
    buf.put("!HHB", ATTR_MSG_TYPE, 1, WPS_M2);
    buf.put("!HH16s", ATTR_ENROLLEE_NONCE, 16, m1_nonce);

    let registrar_nonce = readfile("/dev/urandom", 16);
    buf.put("!HH16s", ATTR_REGISTRAR_NONCE, 16, registrar_nonce);

    buf.put("!HH16B", ATTR_UUID_R, 16, ...derive_registrar_uuid());

    let keypair = dh_keypair();
    let local_privkey = keypair?.[0];
    let local_pubkey = keypair?.[1];
    buf.put("!HH*", ATTR_PUBLIC_KEY, length(local_pubkey), local_pubkey);

    //buf.put("!HHH", ATTR_AUTH_TYPE_FLAGS, 2, desiredConfiguration.authentication_types);
    //buf.put("!HHH", ATTR_ENCR_TYPE_FLAGS, 2, desiredConfiguration.encryption_types);

    buf.put("!HHB", ATTR_CONN_TYPE_FLAGS, 1, WPS_CONN_ESS);
    buf.put("!HHH", ATTR_CONFIG_METHODS, 2, WPS_CONFIG_PUSHBUTTON);

	const id = local_device.getIdentification();

    buf.put("!HH*", ATTR_MANUFACTURER, length(id?.manufacturer_name), id?.manufacturer_name ?? '');
    buf.put("!HH*", ATTR_MODEL_NAME, length(id?.manufacturer_model), id?.manufacturer_model ?? '');
    buf.put("!HH*", ATTR_MODEL_NUMBER, length('unspecified'), 'unspecified');
    buf.put("!HH*", ATTR_SERIAL_NUMBER, length('unspecified'), 'unspecified');

    let oui = "\x00\x50\xf2\x00";
    buf.put("!HHH4sH", ATTR_PRIMARY_DEV_TYPE, 8, WPS_DEV_NETWORK_INFRA, oui, WPS_DEV_NETWORK_INFRA_ROUTER);

    buf.put("!HH*", ATTR_DEV_NAME, length(id?.friendly_name), id?.friendly_name ?? '');

    buf.put("!HHB", ATTR_RF_BANDS, 1, desiredConfiguration.band);

    buf.put("!HHH", ATTR_ASSOC_STATE, 2, WPS_ASSOC_CONN_SUCCESS);
    buf.put("!HHH", ATTR_CONFIG_ERROR, 2, WPS_CFG_NO_ERROR);
    buf.put("!HHH", ATTR_DEV_PASSWORD_ID, 2, DEV_PW_PUSHBUTTON);
    buf.put("!HHI", ATTR_OS_VERSION, 4, 0x80000001);

    buf.put("!HHBBBBBB", ATTR_VENDOR_EXTENSION, 6,
            WPS_VENDOR_ID_WFA_1, WPS_VENDOR_ID_WFA_2, WPS_VENDOR_ID_WFA_3,
            WFA_ELEM_VERSION2, 1, WPS_VERSION);

    let shared_secret = dh_sharedkey(local_privkey, m1_pubkey);
    let dhkey = sha256(shared_secret);
    let kdk = hmac_sha256(dhkey, m1_nonce + m1_mac_address + registrar_nonce);
    let keys = derive_wps_keys(kdk, "Wi-Fi Easy and Secure Key Derivation", 80);
    let authkey = substr(keys, 0, 32);
    let keywrapkey = substr(keys, 32, 16);

    let plain_settings = build_plain_settings(desiredConfiguration);
	let key_wrap_auth = substr(hmac_sha256(authkey, plain_settings), 0, 8);
	let wrap_settings = buffer(plain_settings);
	wrap_settings.end().put('!HH8s', ATTR_KEY_WRAP_AUTH, 8, key_wrap_auth);

	let pad_bytes = 16 - (wrap_settings.length() % 16);
	wrap_settings.set(pad_bytes, wrap_settings.pos(), wrap_settings.pos() + pad_bytes);

    let iv = readfile("/dev/urandom", 16);
    let encrypted_settings = aes_encrypt(keywrapkey, iv, wrap_settings.pull());
    buf.put("!HH*", ATTR_ENCR_SETTINGS, length(iv) + length(encrypted_settings), iv + encrypted_settings);

	let authenticator = hmac_sha256(authkey, m1 + buf.slice());
	buf.put('!HH8s', ATTR_AUTHENTICATOR, 8, substr(authenticator, 0, 8));

    return buf.pull();
};

export function wscProcessM2(key, m1, m2)
{
	// Extract necessary data from M1 && M2
	let m1_nonce, m2_nonce, m2_pubkey, m2_encrypted_settings, m2_authenticator;
	let msg = buffer(m1);
	let settings = {};

    while (true) {
        let attr_type = msg.get('!H');
        let attr_len = msg.get('!H');

		if (attr_type == null)
			break;

        if (attr_type == ATTR_ENROLLEE_NONCE && attr_len == 16)
            m1_nonce = msg.get("!16s");
    }

    if (!m1_nonce)
        return log.warn("Incomplete M1 message received");

	msg = buffer(m2);

	while (true) {
		let attr_type = msg.get('!H');
        let attr_len  = msg.get('!H');

		if (attr_type == null)
            break;

		if (attr_type == ATTR_REGISTRAR_NONCE && attr_len == 16)
			m2_nonce = msg.get(attr_len);
		else if (attr_type == ATTR_PUBLIC_KEY && attr_len > 0)
            m2_pubkey = msg.get(attr_len);
		else if (attr_type == ATTR_AUTH_TYPE_FLAGS && attr_len == 2)
            settings.supported_authentication_types = msg.get('!H');
		else if (attr_type == ATTR_ENCR_TYPE_FLAGS && attr_len == 2)
            settings.supported_encryption_types = msg.get('!H');
		else if (attr_type == ATTR_ENCR_SETTINGS && attr_len >= 32)
			m2_encrypted_settings = msg.get(attr_len);
		else if (attr_type == ATTR_AUTHENTICATOR && attr_len == 8)
			m2_authenticator = msg.get(attr_len);
		else if (attr_type == ATTR_MANUFACTURER && attr_len > 0)
			settings.manufacturer = msg.get(attr_len);
		else if (attr_type == ATTR_MODEL_NAME && attr_len > 0)
			settings.model_name = msg.get(attr_len);
		else if (attr_type == ATTR_MODEL_NUMBER && attr_len > 0)
			settings.model_number = msg.get(attr_len);
        else if (attr_type == ATTR_SERIAL_NUMBER && attr_len > 0)
            settings.serial_number = msg.get(attr_len);
        else if (attr_type == ATTR_DEV_NAME && attr_len > 0)
            settings.device_name = msg.get(attr_len);
		else if (attr_type == ATTR_RF_BANDS && attr_len == 1)
			settings.bands = msg.get('B');
		else if (attr_type == WFA_ELEM_MULTI_AP && attr_len == 1) {
			const multi_ap_flags = msg.get('B');

			settings.multi_ap = {
				is_backhaul_sta: !!(multi_ap_flags & 0x1),
				is_backhaul_bss: !!(multi_ap_flags & 0x2),
				is_fronthaul_bss:  !!(multi_ap_flags & 0x4),
				tear_down: !!(multi_ap_flags & 0x8),
				profile1_backhaul_sta_assoc_dissallowed: !!(multi_ap_flags & 0x10),
				profile2_backhaul_sta_assoc_dissallowed: !!(multi_ap_flags & 0x20)
			};
		}
		else
			msg.pos(msg.pos() + attr_len);
    }

	if (!m2_nonce || !m2_pubkey || !m2_encrypted_settings || !m2_authenticator)
		return log.warn("Incomplete M2 message received");

	// Compute shared secret
	let shared_secret = dh_sharedkey(key.key, m2_pubkey);

	// Derive keys
	let dhkey = sha256(shared_secret);
	let kdk = hmac_sha256(dhkey, m1_nonce + utils.ether_aton(key.mac) + m2_nonce);
	let keys = derive_wps_keys(kdk, "Wi-Fi Easy and Secure Key Derivation", 80);
	let authkey = substr(keys, 0, 32);
	let keywrapkey = substr(keys, 32, 48);
	//let emsk = substr(keys, 48, 80);

	// Verify authenticator
	let computed_authenticator = substr(hmac_sha256(authkey, m1 + substr(m2, 0, -12)), 0, 8);
	if (computed_authenticator !== m2_authenticator) 
		return log.warn('WSC M2 message authentication failed');

	// Decrypt and process encrypted settings
	let iv = substr(m2_encrypted_settings, 0, 16);
	let ciphertext = substr(m2_encrypted_settings, 16);
	let decrypted_settings = aes_decrypt(keywrapkey, iv, ciphertext);

	msg = buffer(decrypted_settings);

	while (true) {
		let attr_type = msg.get('!H');
		let attr_len = msg.get('!H');

		if (attr_type == null)
			break;

		if (attr_type == ATTR_SSID && attr_len > 0)
			settings.ssid = msg.get(attr_len);
		else if (attr_type == ATTR_AUTH_TYPE_FLAGS && attr_len == 2)
            settings.authentication_types = msg.get('!H');
		else if (attr_type == ATTR_ENCR_TYPE_FLAGS && attr_len == 2)
			settings.encryption_types = msg.get('!H');
		else if (attr_type == ATTR_NETWORK_KEY && attr_len > 0)
			settings.network_key = msg.get(attr_len);
        else if (attr_type == ATTR_MAC_ADDR && attr_len == 6)
			settings.bssid = utils.ether_ntoa(msg.get(6));
		else
			msg.pos(msg.pos() + attr_len);
	}

    return settings;
};

export function wscGetType(m)
{
	for (let off = 0; off < length(m); ) {
		let tl = unpack("!HH", m, off); off += 4;

		if (tl[0] == ATTR_MSG_TYPE) {
			if (tl[1] != 1)
				return log.warn(`wsc: message has invalid ATTR_MSG_TYPE length ${tl[1]}`);

			switch (ord(m, off)) {
			case WPS_M1: return 1;
			case WPS_M2: return 2;
			default:     return null;
			}
		}

		off += tl[1];
	}

	return null;
};
