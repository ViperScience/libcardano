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

void blake2b_224_hash(const uint8_t *data, uint32_t len, uint8_t *out) {
    uint32_t hashlen = 224;
    blake2b_ctx ctx;
    cryptonite_blake2b_init(&ctx, hashlen);
    cryptonite_blake2b_update(&ctx, data, len);
    cryptonite_blake2b_finalize(&ctx, hashlen, out);
}