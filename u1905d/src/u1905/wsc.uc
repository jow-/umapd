import { pack, unpack, buffer } from 'struct';
import { readfile } from 'fs';
import { warn } from 'log';
import { sha256, hmac_sha256, aes_encrypt, aes_decrypt, dh_keypair, dh_sharedkey } from 'crypto';

// Constants
const ATTR_VERSION = 0x104a;
const ATTR_MSG_TYPE = 0x1022;
const WPS_M1 = 0x04;
const WPS_M2 = 0x05;
const ATTR_UUID_E = 0x1047;
const ATTR_UUID_R = 0x1048;
const ATTR_MAC_ADDR = 0x1020;
const ATTR_ENROLLEE_NONCE = 0x101a;
const ATTR_REGISTRAR_NONCE = 0x1039;
const ATTR_PUBLIC_KEY = 0x1032;
const ATTR_AUTH_TYPE_FLAGS = 0x1004;
const WPS_AUTH_OPEN = 0x0001;
const WPS_AUTH_WPAPSK = 0x0002;
const WPS_AUTH_WPA = 0x0008;
const WPS_AUTH_WPA2 = 0x0010;
const WPS_AUTH_WPA2PSK = 0x0020;
const ATTR_ENCR_TYPE_FLAGS = 0x1010;
const WPS_ENCR_NONE = 0x0001;
const WPS_ENCR_TKIP = 0x0004;
const WPS_ENCR_AES = 0x0008;
const ATTR_CONN_TYPE_FLAGS = 0x100d;
const WPS_CONN_ESS = 0x01;
const ATTR_CONFIG_METHODS = 0x1008;
const WPS_CONFIG_PUSHBUTTON = 0x0080;
const ATTR_WPS_STATE = 0x1044;
const WPS_STATE_NOT_CONFIGURED = 1;
const ATTR_MANUFACTURER = 0x1021;
const ATTR_MODEL_NAME = 0x1023;
const ATTR_MODEL_NUMBER = 0x1024;
const ATTR_SERIAL_NUMBER = 0x1042;
const ATTR_PRIMARY_DEV_TYPE = 0x1054;
const WPS_DEV_NETWORK_INFRA = 1;
const WPS_DEV_NETWORK_INFRA_ROUTER = 1;
const ATTR_DEV_NAME = 0x1011;
const ATTR_RF_BANDS = 0x103c;
const WPS_RF_24GHZ = 0x01;
const WPS_RF_50GHZ = 0x02;
const WPS_RF_60GHZ = 0x04;
const ATTR_ASSOC_STATE = 0x1002;
const WPS_ASSOC_NOT_ASSOC = 0;
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
const WPS_VERSION = 0x20;

// Global variables
let last_m1 = null;
let last_key = null;

function build_plain_settings(x)
{
    let buf = buffer();

    buf.put("!HH*", ATTR_SSID, length(x.interface_type_data.ieee80211.ssid), x.interface_type_data.ieee80211.ssid);
    buf.put("!HHH", ATTR_AUTH_TYPE, 2, x.interface_type_data.ieee80211.authentication_mode);
    buf.put("!HHH", ATTR_ENCR_TYPE, 2, x.interface_type_data.ieee80211.encryption_mode);
    buf.put("!HH*", ATTR_NETWORK_KEY, length(x.interface_type_data.ieee80211.network_key), x.interface_type_data.ieee80211.network_key);
    buf.put("!HH6s", ATTR_MAC_ADDR, 6, x.mac_address);

    return buf.pull();
}

function derive_wps_keys(key, personalization_string, length)
{
	let result = "";

	for (let i = 1; length(result) < length; i++)
		result += hmac_sha256(key,
			pack("!I*I", i, personalization_string, length * 8));

	return substr(result, 0, length);
}

export function wscBuildM1(interface_name)
{
	let x = PLATFORM_GET_1905_INTERFACE_INFO(interface_name);
	if (!x) {
		print("Could not retrieve info of interface", interface_name);
		return 0;
	}

	let buf = buffer();

	buf.put("!HHB", ATTR_VERSION, 1, 0x10);
	buf.put("!HHB", ATTR_MSG_TYPE, 1, WPS_M1);
	buf.put("!HH16s", ATTR_UUID_E, 16, x.uuid);
	buf.put("!HH6s", ATTR_MAC_ADDR, 6, x.mac_address);

	let enrollee_nonce = readfile("/dev/urandom", 16);
	buf.put("!HH16s", ATTR_ENROLLEE_NONCE, 16, enrollee_nonce);

	let keypair = dh_keypair();
	let priv_key = keypair[0];
	let pub_key = keypair[1];
	buf.put("!HH*", ATTR_PUBLIC_KEY, length(pub_key), pub_key);

	let auth_types = 0;
	if (x.interface_type_data.ieee80211.authentication_mode & IEEE80211_AUTH_MODE_OPEN)
		auth_types |= WPS_AUTH_OPEN;
	if (x.interface_type_data.ieee80211.authentication_mode & IEEE80211_AUTH_MODE_WPA)
		auth_types |= WPS_AUTH_WPA;
	if (x.interface_type_data.ieee80211.authentication_mode & IEEE80211_AUTH_MODE_WPAPSK)
		auth_types |= WPS_AUTH_WPAPSK;
	if (x.interface_type_data.ieee80211.authentication_mode & IEEE80211_AUTH_MODE_WPA2)
		auth_types |= WPS_AUTH_WPA2;
	if (x.interface_type_data.ieee80211.authentication_mode & IEEE80211_AUTH_MODE_WPA2PSK)
		auth_types |= WPS_AUTH_WPA2PSK;
	buf.put("!HHH", ATTR_AUTH_TYPE_FLAGS, 2, auth_types);

	let encryption_types = 0;
	if (x.interface_type_data.ieee80211.encryption_mode & IEEE80211_ENCRYPTION_MODE_NONE)
		encryption_types |= WPS_ENCR_NONE;
	if (x.interface_type_data.ieee80211.encryption_mode & IEEE80211_ENCRYPTION_MODE_TKIP)
		encryption_types |= WPS_ENCR_TKIP;
	if (x.interface_type_data.ieee80211.encryption_mode & IEEE80211_ENCRYPTION_MODE_AES)
		encryption_types |= WPS_ENCR_AES;
	buf.put("!HHH", ATTR_ENCR_TYPE_FLAGS, 2, encryption_types);

	buf.put("!HHB", ATTR_CONN_TYPE_FLAGS, 1, WPS_CONN_ESS);
	buf.put("!HHH", ATTR_CONFIG_METHODS, 2, WPS_CONFIG_PUSHBUTTON);
	buf.put("!HHB", ATTR_WPS_STATE, 1, WPS_STATE_NOT_CONFIGURED);
	buf.put("!HH*", ATTR_MANUFACTURER, length(x.manufacturer_name), x.manufacturer_name);
	buf.put("!HH*", ATTR_MODEL_NAME, length(x.model_name), x.model_name);
	buf.put("!HH*", ATTR_MODEL_NUMBER, length(x.model_number), x.model_number);
	buf.put("!HH*", ATTR_SERIAL_NUMBER, length(x.serial_number), x.serial_number);

	let oui = "\x00\x50\xf2\x00";
	buf.put("!HHHI4sH", ATTR_PRIMARY_DEV_TYPE, 8, WPS_DEV_NETWORK_INFRA, oui, WPS_DEV_NETWORK_INFRA_ROUTER);

	buf.put("!HH*", ATTR_DEV_NAME, length(x.device_name), x.device_name);

	let rf_bands = 0;
	if (x.interface_type == INTERFACE_TYPE_IEEE_802_11B_2_4_GHZ ||
	    x.interface_type == INTERFACE_TYPE_IEEE_802_11G_2_4_GHZ ||
	    x.interface_type == INTERFACE_TYPE_IEEE_802_11N_2_4_GHZ)
		rf_bands = WPS_RF_24GHZ;
	else if (x.interface_type == INTERFACE_TYPE_IEEE_802_11A_5_GHZ ||
	         x.interface_type == INTERFACE_TYPE_IEEE_802_11N_5_GHZ ||
	         x.interface_type == INTERFACE_TYPE_IEEE_802_11AC_5_GHZ)
		rf_bands = WPS_RF_50GHZ;
	else if (x.interface_type == INTERFACE_TYPE_IEEE_802_11AD_60_GHZ)
		rf_bands = WPS_RF_60GHZ;
	buf.put("!HHB", ATTR_RF_BANDS, 1, rf_bands);

	buf.put("!HHH", ATTR_ASSOC_STATE, 2, WPS_ASSOC_NOT_ASSOC);
	buf.put("!HHH", ATTR_DEV_PASSWORD_ID, 2, DEV_PW_PUSHBUTTON);
	buf.put("!HHH", ATTR_CONFIG_ERROR, 2, WPS_CFG_NO_ERROR);
	buf.put("!HHI", ATTR_OS_VERSION, 4, 0x80000001);
	buf.put("!HHBBBBBB", ATTR_VENDOR_EXTENSION, 6,
		WPS_VENDOR_ID_WFA_1, WPS_VENDOR_ID_WFA_2, WPS_VENDOR_ID_WFA_3,
		WFA_ELEM_VERSION2, 1, WPS_VERSION);

	last_m1 = buf.pull();
	last_key = { key: priv_key, mac: x.mac_address };

	return [ last_m1, last_key ];
}

export function wscBuildM2(m1)
{
    let registrar_interface_name = DMmacToInterfaceName(DMregistrarMacGet());
    if (!registrar_interface_name) {
        print("None of this nodes' interfaces matches the registrar MAC address. Ignoring M1 message.");
        return 0;
    }

	let msg = buffer(m1);

    let m1_mac_address, m1_nonce, m1_pubkey;

    while (true) {
        let attr_type = msg.get('!H');
        let attr_len = msg.get('!H');

		if (attr_type == null)
			break;

        if (attr_type == ATTR_MAC_ADDR && attr_len == 6)
            m1_mac_address = msg.get("!6s", m1);
        else if (attr_type == ATTR_ENROLLEE_NONCE && attr_len == 16)
            m1_nonce = msg.get("!16s");
        else if (attr_type == ATTR_PUBLIC_KEY)
            //m1_pubkey = msg.get(`!${attr_len}s`);
			m1_pubkey = msg.slice(msg.pos(), msg.pos() + attr_type);
    }

    if (!m1_mac_address || !m1_nonce || !m1_pubkey) {
        print("Incomplete M1 message received");
        return 0;
    }

    let x = PLATFORM_GET_1905_INTERFACE_INFO(registrar_interface_name);
    if (!x) {
        print("Could not retrieve info of interface", registrar_interface_name);
        return 0;
    }

    let buf = buffer();

    buf.put("!HHB", ATTR_VERSION, 1, 0x10);
    buf.put("!HHB", ATTR_MSG_TYPE, 1, WPS_M2);
    buf.put("!HH16s", ATTR_ENROLLEE_NONCE, 16, m1_nonce);

    let registrar_nonce = readfile("/dev/urandom", 16);
    buf.put("!HH16s", ATTR_REGISTRAR_NONCE, 16, registrar_nonce);

    buf.put("!HH16s", ATTR_UUID_R, 16, x.uuid);

    let keypair = dh_keypair();
    let local_privkey = keypair?.[0];
    let local_pubkey = keypair?.[1];
    buf.put("!HH*", ATTR_PUBLIC_KEY, length(local_pubkey), local_pubkey);

    let auth_types = 0;
    if (x.interface_type_data.ieee80211.authentication_mode & IEEE80211_AUTH_MODE_OPEN)
        auth_types |= WPS_AUTH_OPEN;
    if (x.interface_type_data.ieee80211.authentication_mode & IEEE80211_AUTH_MODE_WPA)
        auth_types |= WPS_AUTH_WPA;
    if (x.interface_type_data.ieee80211.authentication_mode & IEEE80211_AUTH_MODE_WPAPSK)
        auth_types |= WPS_AUTH_WPAPSK;
    if (x.interface_type_data.ieee80211.authentication_mode & IEEE80211_AUTH_MODE_WPA2)
        auth_types |= WPS_AUTH_WPA2;
    if (x.interface_type_data.ieee80211.authentication_mode & IEEE80211_AUTH_MODE_WPA2PSK)
        auth_types |= WPS_AUTH_WPA2PSK;
    buf.put("!HHH", ATTR_AUTH_TYPE_FLAGS, 2, auth_types);

    let encryption_types = 0;
    if (x.interface_type_data.ieee80211.encryption_mode & IEEE80211_ENCRYPTION_MODE_NONE)
        encryption_types |= WPS_ENCR_NONE;
    if (x.interface_type_data.ieee80211.encryption_mode & IEEE80211_ENCRYPTION_MODE_TKIP)
        encryption_types |= WPS_ENCR_TKIP;
    if (x.interface_type_data.ieee80211.encryption_mode & IEEE80211_ENCRYPTION_MODE_AES)
        encryption_types |= WPS_ENCR_AES;
    buf.put("!HHH", ATTR_ENCR_TYPE_FLAGS, 2, encryption_types);

    buf.put("!HHB", ATTR_CONN_TYPE_FLAGS, 1, WPS_CONN_ESS);
    buf.put("!HHH", ATTR_CONFIG_METHODS, 2, WPS_CONFIG_PUSHBUTTON);
    buf.put("!HH*", ATTR_MANUFACTURER, length(x.manufacturer_name), x.manufacturer_name);
    buf.put("!HH*", ATTR_MODEL_NAME, length(x.model_name), x.model_name);
    buf.put("!HH*", ATTR_MODEL_NUMBER, length(x.model_number), x.model_number);
    buf.put("!HH*", ATTR_SERIAL_NUMBER, length(x.serial_number), x.serial_number);

    let oui = "\x00\x50\xf2\x00";
    buf.put("!HHHI4sH", ATTR_PRIMARY_DEV_TYPE, 8, WPS_DEV_NETWORK_INFRA, oui, WPS_DEV_NETWORK_INFRA_ROUTER);

    buf.put("!HH*", ATTR_DEV_NAME, length(x.device_name), x.device_name);

    let rf_bands = 0;
    if (x.interface_type == INTERFACE_TYPE_IEEE_802_11B_2_4_GHZ ||
        x.interface_type == INTERFACE_TYPE_IEEE_802_11G_2_4_GHZ ||
        x.interface_type == INTERFACE_TYPE_IEEE_802_11N_2_4_GHZ)
        rf_bands = WPS_RF_24GHZ;
    else if (x.interface_type == INTERFACE_TYPE_IEEE_802_11A_5_GHZ ||
             x.interface_type == INTERFACE_TYPE_IEEE_802_11N_5_GHZ ||
             x.interface_type == INTERFACE_TYPE_IEEE_802_11AC_5_GHZ)
        rf_bands = WPS_RF_50GHZ;
    else if (x.interface_type == INTERFACE_TYPE_IEEE_802_11AD_60_GHZ)
        rf_bands = WPS_RF_60GHZ;
    buf.put("!HHB", ATTR_RF_BANDS, 1, rf_bands);

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
    let keys = wps_key_derivation_function(kdk, "Wi-Fi Easy and Secure Key Derivation", 80);
    let authkey = substr(keys, 0, 32);
    let keywrapkey = substr(keys, 32, 16);

    let plain_settings = build_plain_settings(x);
    let iv = readfile("/dev/urandom", 16);
    let encrypted_settings = aes_encrypt(keywrapkey, iv, plain_settings);
    buf.put("!HH*", ATTR_ENCR_SETTINGS, length(iv) + length(encrypted_settings), iv + encrypted_settings);

    let temp_buffer = buf.slice();
    let authenticator = substr(hmac_sha256(authkey, m1 + temp_buffer), 0, 8);
    buf.put("!HH8s", ATTR_AUTHENTICATOR, 8, authenticator);

    return buf.pull();
}

export function wscProcessM2(key, m1, m2)
{
	// Extract necessary data from M2
	let m2_nonce, m2_pubkey, m2_encrypted_settings, m2_authenticator;
	// ... (extraction code)

	// Compute shared secret
	let shared_secret = dh_sharedkey(key.key, m2_pubkey);

	// Derive keys
	let dhkey = sha256(shared_secret);
	let kdk = hmac_sha256(dhkey, m1_nonce + key.mac + m2_nonce);
	let keys = derive_wps_keys(kdk, "Wi-Fi Easy and Secure Key Derivation", 80);
	let authkey = substr(keys, 0, 32);
	let keywrapkey = substr(keys, 32, 48);
	let emsk = substr(keys, 48, 80);

	// Verify authenticator
	let computed_authenticator = substr(hmac_sha256(authkey, m1 + substr(m2, 0, -12)), 0, 8);
	if (computed_authenticator !== m2_authenticator) {
		warn('WSC M2 message authentication failed');
		return false;
	}

	// Decrypt and process encrypted settings
	let iv = substr(m2_encrypted_settings, 0, 16);
	let ciphertext = substr(m2_encrypted_settings, 16);
	let decrypted_settings = aes_decrypt(keywrapkey, iv, ciphertext);
	// ... (process decrypted settings)

	return true;
}

export function wscGetType(m)
{
	for (let off = 0; off < length(m); ) {
		let tl = unpack("!HH", m, off); off += 4;

		if (tl[0] == ATTR_MSG_TYPE) {
			if (tl[1] != 1) {
				warn('WSC message has invalid ATTR_MSG_TYPE length %d', tl[1]);

				return WSC_TYPE_UNKNOWN;
			}

			switch (ord(m, off)) {
			case WPS_M1: return WSC_TYPE_M1;
			case WPS_M2: return WSC_TYPE_M2;
			default:     return WSC_TYPE_UNKNOWN;
			}
		}

		off += tl[1];
	}

	return WSC_TYPE_UNKNOWN;
}
