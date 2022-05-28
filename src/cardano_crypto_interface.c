// C interface to cardano crypto
// Do not modify cardano crypto source

#include "cryptonite_blake2b.h"

// Include the encrypted_sign.c source code within this file in order to access static functions.
#include "encrypted_sign.c"
// Code included within encrypted_sign.c
//
//  Key size constants
//  Key struct definitions
//  memory_combine
// 
// Much of this functionality is exposed in the cardano_crypto_interface.h header file.

void wallet_encrypted_private_to_public
    (uint8_t const*  pass,
     uint32_t const  pass_len,
     ed25519_secret_key const encrypted_key,
     ed25519_public_key  pub_key /* out */)
{
    ed25519_secret_key decrypted_key;
    memory_combine(pass, pass_len, encrypted_key, decrypted_key, ENCRYPTED_KEY_SIZE);
	cardano_crypto_ed25519_publickey(decrypted_key, pub_key);
    clear(decrypted_key, sizeof(ed25519_secret_key));
}

void wallet_decrypt_private
    (uint8_t const*  pass,
     uint32_t const  pass_len,
     ed25519_secret_key const encrypted_key /* in */,
     ed25519_secret_key decrypted_key /* out */)
{
    memory_combine(pass, pass_len, encrypted_key, decrypted_key, ENCRYPTED_KEY_SIZE);
}

void blake2b_224_hash(const uint8_t *data, uint32_t len, uint8_t *out)
{
    uint32_t hashlen = 224;
    blake2b_ctx ctx;
    cryptonite_blake2b_init(&ctx, hashlen);
    cryptonite_blake2b_update(&ctx, data, len);
    cryptonite_blake2b_finalize(&ctx, hashlen, out);
}

static void add_left_public_v2
    (uint8_t *out,
     uint8_t *z,
     const uint8_t *in,
     derivation_scheme_mode mode)
{
	uint8_t zl8[32];
	ed25519_public_key pub_zl8;

	memset(zl8, 0, 32);
	switch (mode) {
	case DERIVATION_V1:
		multiply8_v1(zl8, z, 32);
		break;
	case DERIVATION_V2:
		multiply8_v2(zl8, z, 28);
		break;
	}

	/* Kl = 8*Zl*B + Al */
	cardano_crypto_ed25519_publickey(zl8, pub_zl8);
	cardano_crypto_ed25519_point_add(pub_zl8, in, out);
}

int wallet_encrypted_derive_public_v2
    (uint8_t const *pub_in,
     uint8_t const *cc_in,
     uint32_t index,
     uint8_t *pub_out,
     uint8_t *cc_out,
     derivation_scheme_mode mode)
{
	HMAC_sha512_ctx hmac_ctx;
	uint8_t idxBuf[4];
	uint8_t z[64];
	uint8_t hmac_out[64];

	/* cannot derive hardened key using public bits */
	if (index_is_hardened(index))
		return 1;

	serialize_index32(idxBuf, index, mode);

	/* calculate Z */
	HMAC_sha512_init(&hmac_ctx, cc_in, CHAIN_CODE_SIZE);
	HMAC_sha512_update(&hmac_ctx, TAG_DERIVE_Z_NORMAL, 1);
	HMAC_sha512_update(&hmac_ctx, pub_in, PUBLIC_KEY_SIZE);
	HMAC_sha512_update(&hmac_ctx, idxBuf, 4);
	HMAC_sha512_final(&hmac_ctx, z);

	/* get 8 * Zl */
	add_left_public_v2(pub_out, z, pub_in, mode);

	/* calculate the new chain code */
	HMAC_sha512_init(&hmac_ctx, cc_in, CHAIN_CODE_SIZE);
	HMAC_sha512_update(&hmac_ctx, TAG_DERIVE_CC_NORMAL, 1);
	HMAC_sha512_update(&hmac_ctx, pub_in, PUBLIC_KEY_SIZE);
	HMAC_sha512_update(&hmac_ctx, idxBuf, 4);
	HMAC_sha512_final(&hmac_ctx, hmac_out);

	memcpy(cc_out, hmac_out + (sizeof(hmac_out) - CHAIN_CODE_SIZE), CHAIN_CODE_SIZE);

	return 0;
}