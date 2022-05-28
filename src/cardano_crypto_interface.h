// Provide a header interface to the cardano crypto c api
// The goal of this interface is to provide the ability of calling code to use the functionality of cardano crypto without making changes to the cardano crypto repository.

#ifndef _CARDANO_CRYPTO_H_
#define _CARDANO_CRYPTO_H_

#include <stdint.h>

#ifdef  __cplusplus
extern "C" {
#endif

#include <ed25519.h>
#include <hmac.h>

#include "cryptonite_pbkdf2.h"

#define SECRET_KEY_SEED_SIZE 32
#define ENCRYPTED_KEY_SIZE 64
#define PUBLIC_KEY_SIZE    32
#define CHAIN_CODE_SIZE    32

typedef struct {
	uint8_t ekey[ENCRYPTED_KEY_SIZE];
	uint8_t pkey[PUBLIC_KEY_SIZE];
	uint8_t cc[CHAIN_CODE_SIZE];
} encrypted_key;

typedef struct {
	uint8_t pkey[PUBLIC_KEY_SIZE];
	uint8_t cc[CHAIN_CODE_SIZE];
} public_key;

typedef enum {
	DERIVATION_V1 = 1,
	DERIVATION_V2 = 2,
} derivation_scheme_mode;

static void unencrypt_start
    (uint8_t const*  pass,
     uint32_t const  pass_len,
     encrypted_key const *encrypted_key /* in */,
     ed25519_secret_key  decrypted_key /* out */);

static void unencrypt_stop(ed25519_secret_key decrypted_key);

void wallet_encrypted_derive_private
    (encrypted_key const *in,
     uint8_t const *pass, uint32_t const pass_len,
     uint32_t index,
     encrypted_key *out,
     derivation_scheme_mode mode);

int wallet_encrypted_derive_public
    (uint8_t *pub_in,
     uint8_t *cc_in,
     uint32_t index,
     uint8_t *pub_out,
     uint8_t *cc_out,
     derivation_scheme_mode mode);

int wallet_encrypted_derive_public_v2
    (uint8_t const *pub_in,
     uint8_t const *cc_in,
     uint32_t index,
     uint8_t *pub_out,
     uint8_t *cc_out,
     derivation_scheme_mode mode);

void wallet_encrypted_private_to_public
    (uint8_t const *pass,
     uint32_t const  pass_len,
     ed25519_secret_key const encrypted_key /* in */,
     ed25519_public_key pub_key /* out */);

void wallet_decrypt_private
    (uint8_t const *pass,
     uint32_t const  pass_len,
     ed25519_secret_key const encrypted_key /* in */,
     ed25519_secret_key decrypted_key /* out */);

void blake2b_224_hash(uint8_t const *data, uint32_t len, uint8_t *out);

#ifdef  __cplusplus
}
#endif

#endif  /* _CARDANO_CRYPTO_H_ */
