#include <string.h>

#include <openssl/sha.h>
#include <openssl/hmac.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/ec.h>
#include <openssl/pem.h>
#include <openssl/core_names.h>
#include <openssl/param_build.h>
#include <openssl/err.h>

#include <ucode/module.h>


static uc_value_t *
uc_crypto_sha256(uc_vm_t *vm, size_t nargs)
{
	unsigned char hash[SHA256_DIGEST_LENGTH], *inputp;
	uc_value_t *input = uc_fn_arg(0), *result = NULL;
	EVP_MD_CTX *mdctx;
	int inputlen;

	if (ucv_type(input) != UC_STRING)
		return NULL;

	inputlen = ucv_string_length(input);
	inputp = (unsigned char *)ucv_string_get(input);

	if (!(mdctx = EVP_MD_CTX_new()) ||
	    !EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL) ||
	    !EVP_DigestUpdate(mdctx, inputp, inputlen) ||
	    !EVP_DigestFinal_ex(mdctx, hash, NULL))
		goto out;

	result = ucv_string_new_length((char *)hash, SHA256_DIGEST_LENGTH);

out:
	EVP_MD_CTX_free(mdctx);

	return result;
}

static uc_value_t *
uc_crypto_hmac_sha256(uc_vm_t *vm, size_t nargs)
{
	uc_value_t *key = uc_fn_arg(0), *data = uc_fn_arg(1);
	unsigned int len = SHA256_DIGEST_LENGTH;
	unsigned char *digest, *keyp, *datap;
	int keylen, datalen;

	if (ucv_type(key) != UC_STRING ||
	    ucv_type(data) != UC_STRING)
		return NULL;

	keylen = ucv_string_length(key);
	keyp = (unsigned char *)ucv_string_get(key);

	datalen = ucv_string_length(data);
	datap = (unsigned char *)ucv_string_get(data);

	digest = HMAC(EVP_sha256(), keyp, keylen, datap, datalen, NULL, NULL);

	return ucv_string_new_length((char *)digest, len);
}

static uc_value_t *
uc_crypto_aes_encrypt(uc_vm_t *vm, size_t nargs)
{
	uc_value_t *key = uc_fn_arg(0), *iv = uc_fn_arg(1), *text = uc_fn_arg(2);
	unsigned char encr[128], *keyp, *ivp, *textp;
	int encrlen, encrfinlen, textlen;
	EVP_CIPHER_CTX *ctx = NULL;
	EVP_CIPHER *cipher = NULL;
	uc_value_t *result = NULL;

	if (ucv_type(key) != UC_STRING ||
	    ucv_type(text) != UC_STRING ||
	    (iv != NULL && ucv_type(iv) != UC_STRING))
		return NULL;

	textlen = ucv_string_length(text);
	textp = (unsigned char *)ucv_string_get(text);

	keyp = (unsigned char *)ucv_string_get(key);
	ivp = (unsigned char *)ucv_string_get(iv);

	if (!(cipher = EVP_CIPHER_fetch(NULL, "AES-128-CBC", NULL)) ||
	    !(ctx = EVP_CIPHER_CTX_new()) ||
	    !EVP_EncryptInit_ex2(ctx, cipher, keyp, ivp, NULL) ||
		!EVP_CIPHER_CTX_set_padding(ctx, 0) ||
		!EVP_EncryptUpdate(ctx, encr, &encrlen, textp, textlen) ||
		!EVP_EncryptFinal_ex(ctx, encr + encrlen, &encrfinlen))
		goto out;

	result = ucv_string_new_length((char *)encr, encrlen + encrfinlen);

out:
	EVP_CIPHER_CTX_free(ctx);
	EVP_CIPHER_free(cipher);

	return result;
}

static uc_value_t *
uc_crypto_aes_decrypt(uc_vm_t *vm, size_t nargs)
{
	uc_value_t *key = uc_fn_arg(0), *iv = uc_fn_arg(1), *encr = uc_fn_arg(2);
	unsigned char text[128], *keyp, *ivp, *encrp;
	int textlen, textfinlen, encrlen;
	EVP_CIPHER_CTX *ctx = NULL;
	EVP_CIPHER *cipher = NULL;
	uc_value_t *result = NULL;

	if (ucv_type(key) != UC_STRING ||
	    ucv_type(encr) != UC_STRING ||
	    (iv != NULL && ucv_type(iv) != UC_STRING))
		return NULL;

	encrlen = ucv_string_length(encr);
	encrp = (unsigned char *)ucv_string_get(encr);

	keyp = (unsigned char *)ucv_string_get(key);
	ivp = (unsigned char *)ucv_string_get(iv);

	if (!(cipher = EVP_CIPHER_fetch(NULL, "AES-128-CBC", NULL)) ||
	    !(ctx = EVP_CIPHER_CTX_new()) ||
	    !EVP_DecryptInit_ex2(ctx, cipher, keyp, ivp, NULL) ||
		!EVP_CIPHER_CTX_set_padding(ctx, 0) ||
		!EVP_DecryptUpdate(ctx, text, &textlen, encrp, encrlen) ||
		!EVP_DecryptFinal_ex(ctx, text + textlen, &textfinlen))
		goto out;

	result = ucv_string_new_length((char *)text, textlen + textfinlen);

out:
	EVP_CIPHER_CTX_free(ctx);
	EVP_CIPHER_free(cipher);

	return result;
}

static unsigned char dh1536_p[] = {
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xC9, 0x0F, 0xDA, 0xA2,
	0x21, 0x68, 0xC2, 0x34, 0xC4, 0xC6, 0x62, 0x8B, 0x80, 0xDC, 0x1C, 0xD1,
	0x29, 0x02, 0x4E, 0x08, 0x8A, 0x67, 0xCC, 0x74, 0x02, 0x0B, 0xBE, 0xA6,
	0x3B, 0x13, 0x9B, 0x22, 0x51, 0x4A, 0x08, 0x79, 0x8E, 0x34, 0x04, 0xDD,
	0xEF, 0x95, 0x19, 0xB3, 0xCD, 0x3A, 0x43, 0x1B, 0x30, 0x2B, 0x0A, 0x6D,
	0xF2, 0x5F, 0x14, 0x37, 0x4F, 0xE1, 0x35, 0x6D, 0x6D, 0x51, 0xC2, 0x45,
	0xE4, 0x85, 0xB5, 0x76, 0x62, 0x5E, 0x7E, 0xC6, 0xF4, 0x4C, 0x42, 0xE9,
	0xA6, 0x37, 0xED, 0x6B, 0x0B, 0xFF, 0x5C, 0xB6, 0xF4, 0x06, 0xB7, 0xED,
	0xEE, 0x38, 0x6B, 0xFB, 0x5A, 0x89, 0x9F, 0xA5, 0xAE, 0x9F, 0x24, 0x11,
	0x7C, 0x4B, 0x1F, 0xE6, 0x49, 0x28, 0x66, 0x51, 0xEC, 0xE4, 0x5B, 0x3D,
	0xC2, 0x00, 0x7C, 0xB8, 0xA1, 0x63, 0xBF, 0x05, 0x98, 0xDA, 0x48, 0x36,
	0x1C, 0x55, 0xD3, 0x9A, 0x69, 0x16, 0x3F, 0xA8, 0xFD, 0x24, 0xCF, 0x5F,
	0x83, 0x65, 0x5D, 0x23, 0xDC, 0xA3, 0xAD, 0x96, 0x1C, 0x62, 0xF3, 0x56,
	0x20, 0x85, 0x52, 0xBB, 0x9E, 0xD5, 0x29, 0x07, 0x70, 0x96, 0x96, 0x6D,
	0x67, 0x0C, 0x35, 0x4E, 0x4A, 0xBC, 0x98, 0x04, 0xF1, 0x74, 0x6C, 0x08,
	0xCA, 0x23, 0x73, 0x27, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
};

static unsigned char dh1536_g[] = { 0x02 };

static EVP_PKEY *
pkey_create(const char *key, BIGNUM *val)
{
	BIGNUM *p = NULL, *g = NULL;
	OSSL_PARAM_BLD *bld = NULL;
	OSSL_PARAM *params = NULL;
	EVP_PKEY_CTX *ctx = NULL;
	EVP_PKEY *pkey = NULL;

	if (!(p = BN_bin2bn(dh1536_p, sizeof(dh1536_p), NULL)) ||
	    !(g = BN_bin2bn(dh1536_g, sizeof(dh1536_g), NULL)) ||
	    !(bld = OSSL_PARAM_BLD_new()) ||
	    !OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_FFC_P, p) ||
	    !OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_FFC_G, g) ||
	    !(key == NULL || OSSL_PARAM_BLD_push_BN(bld, key, val)) ||
	    !(params = OSSL_PARAM_BLD_to_param(bld)) ||
	    !(ctx = EVP_PKEY_CTX_new_from_name(NULL, "DH", NULL)) ||
	    EVP_PKEY_fromdata_init(ctx) < 1 ||
	    EVP_PKEY_fromdata(ctx, &pkey, EVP_PKEY_KEYPAIR, params) < 1)
		;

	OSSL_PARAM_BLD_free(bld);
	OSSL_PARAM_free(params);

	EVP_PKEY_CTX_free(ctx);

	BN_free(p);
	BN_free(g);

	return pkey;
}

static uc_value_t *
pkey_get_key(EVP_PKEY *pkey, const char *key_type)
{
	BIGNUM *bn = NULL;
	uc_string_t *us;

	if (EVP_PKEY_get_bn_param(pkey, key_type, &bn) != 1)
		return NULL;

	us = xalloc(sizeof(uc_string_t) + BN_num_bytes(bn) + 1);
	us->header.type = UC_STRING;
	us->header.refcount = 1;
	us->length = BN_num_bytes(bn);

	BN_bn2bin(bn, (unsigned char *)us->str);
	BN_free(bn);

	return &us->header;
}

static uc_value_t *
uc_crypto_dh_keypair(uc_vm_t *vm, size_t nargs)
{
	uc_value_t *result = NULL, *pubkey = NULL, *privkey = NULL;
	EVP_PKEY_CTX *ctx = NULL;
	EVP_PKEY *pkey = NULL;

	if (!(pkey = pkey_create(NULL, NULL)) ||
	    !(ctx = EVP_PKEY_CTX_new_from_pkey(NULL, pkey, NULL)) ||
	    EVP_PKEY_keygen_init(ctx) < 1 ||
	    EVP_PKEY_generate(ctx, &pkey) < 1 ||
	    !(privkey = pkey_get_key(pkey, OSSL_PKEY_PARAM_PRIV_KEY)) ||
	    !(pubkey = pkey_get_key(pkey, OSSL_PKEY_PARAM_PUB_KEY)))
		goto out;

	result = ucv_array_new_length(vm, 2);
	ucv_array_push(result, ucv_get(privkey));
	ucv_array_push(result, ucv_get(pubkey));

out:
	EVP_PKEY_CTX_free(ctx);
	EVP_PKEY_free(pkey);

	ucv_put(privkey);
	ucv_put(pubkey);

	return result;
}

static uc_value_t *
uc_crypto_dh_sharedkey(uc_vm_t *vm, size_t nargs)
{
	uc_value_t *privkey = uc_fn_arg(0), *peerkey = uc_fn_arg(1);
	EVP_PKEY *pkey_priv = NULL, *pkey_peer = NULL;
	BIGNUM *privbn = NULL, *peerbn = NULL;
	size_t privlen, peerlen, sharedlen;
	unsigned char *privp, *peerp;
	EVP_PKEY_CTX *ctx = NULL;
	uc_string_t *us = NULL;

	if (ucv_type(privkey) != UC_STRING ||
	    ucv_type(peerkey) != UC_STRING)
		return NULL;

	privlen = ucv_string_length(privkey);
	privp = (unsigned char *)ucv_string_get(privkey);

	peerlen = ucv_string_length(peerkey);
	peerp = (unsigned char *)ucv_string_get(peerkey);

	if (!(privbn = BN_bin2bn(privp, privlen, NULL)) ||
	    !(pkey_priv = pkey_create(OSSL_PKEY_PARAM_PRIV_KEY, privbn)) ||
	    !(peerbn = BN_bin2bn(peerp, peerlen, NULL)) ||
	    !(pkey_peer = pkey_create(OSSL_PKEY_PARAM_PUB_KEY, peerbn)) ||
	    !(ctx = EVP_PKEY_CTX_new_from_pkey(NULL, pkey_priv, NULL)) ||
	    EVP_PKEY_derive_init(ctx) < 1 ||
	    EVP_PKEY_derive_set_peer(ctx, pkey_peer) < 1 ||
	    EVP_PKEY_derive(ctx, NULL, &sharedlen) < 1)
		goto out;

	us = xalloc(sizeof(uc_string_t) + sharedlen + 1);
	us->header.type = UC_STRING;
	us->header.refcount = 1;
	us->length = sharedlen;

	if (EVP_PKEY_derive(ctx, (unsigned char *)us->str, &sharedlen) < 1) {
		free(us);
		us = NULL;
	}

out:
	EVP_PKEY_free(pkey_priv);
	EVP_PKEY_free(pkey_peer);
	EVP_PKEY_CTX_free(ctx);

	BN_free(peerbn);
	BN_free(privbn);

	return us ? &us->header : NULL;
}


static const uc_function_list_t crypto_functions[] = {
	{ "sha256",       uc_crypto_sha256       },
	{ "hmac_sha256",  uc_crypto_hmac_sha256  },
	{ "aes_encrypt",  uc_crypto_aes_encrypt  },
	{ "aes_decrypt",  uc_crypto_aes_decrypt  },
	{ "dh_keypair",   uc_crypto_dh_keypair   },
	{ "dh_sharedkey", uc_crypto_dh_sharedkey },
};

void uc_module_init(uc_vm_t *vm, uc_value_t *scope) {
	uc_function_list_register(scope, crypto_functions);
}
