// Copyright (c) 2021 Viper Science LLC
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.

// Standard Library Headers
#include <numeric>
#include <stdexcept>
#include <vector>

// Third-Party Library Headers
#include <botan/pwdhash.h>
#include <botan/pbkdf2.h>
#include <botan/hash.h>
#include <botan/mac.h>
#include <cbor.h>

// Public Cardano++ Headers 
#include <cardano/crypto.hpp>
#include <cardano/encodings.hpp>

// Private Cardano++ Headers
#include "cardano_crypto_interface.h"
#include "utils.hpp"

#include <iostream>

using namespace cardano;

BIP32PublicKey::BIP32PublicKey(std::string pub, std::string cc) {
    if (pub.size() != PUBLIC_KEY_SIZE * 2)
        throw std::invalid_argument("Invalid hex public key size.");
    if (cc.size() != CHAIN_CODE_SIZE * 2)
        throw std::invalid_argument("Invalid hex chain code size.");
    auto bytes = BASE16::decode(pub + cc);
    std::copy_n(bytes.begin(), this->pub_.size(), this->pub_.begin());
    std::copy_n(bytes.begin() + this->pub_.size(), this->cc_.size(),
                this->cc_.begin());
} // BIP32PublicKey::ExtendedPublicKey

BIP32PublicKey BIP32PublicKey::fromBech32(std::string bech32_str) {
    BIP32PublicKey k;
    auto [hrp1, data] = BECH32::decode(bech32_str);
    std::copy_n(data.begin(), k.pub_.size(), k.pub_.begin());
    std::copy_n(data.begin() + k.pub_.size(), k.cc_.size(), k.cc_.begin());
    return k;
} // BIP32PublicKey::fromBech32

BIP32PublicKey BIP32PublicKey::deriveChild(uint32_t index, uint32_t derivation_mode) {
    uint8_t *pub_in = this->pub_.data();
    uint8_t *cc_in = this->cc_.data();

    BIP32PublicKey k;
    uint8_t *pub_out = k.pub_.data();
    uint8_t *cc_out = k.cc_.data();

    // Derive the child public key for the soft index.
    derivation_scheme_mode mode;
    switch (derivation_mode) {
    case 1:
        mode = DERIVATION_V1;
        break;
    case 2:
    default:
        mode = DERIVATION_V2;
        break;
    }
    int flag = wallet_encrypted_derive_public(pub_in, cc_in, index, pub_out, cc_out, mode);
    if (flag != 0)
        throw std::runtime_error(
            "Cannot derive hardened index from public key.");

    return k;
} // BIP32PublicKey::deriveChild

std::string BIP32PublicKey::toBech32(std::string hrp) {
    auto data = concat_bytes(this->pub_, this->cc_);
    return BECH32::encode(hrp, data);
} // BIP32PublicKey::toBech32

std::string BIP32PublicKey::toBase16() {
    auto bytes = concat_bytes(this->pub_, this->cc_);
    return BASE16::encode(bytes);
} // ExtendedPublicKey::toBase16

std::vector<uint8_t> BIP32PublicKey::toBytes(bool with_cc) {
    if (!with_cc) {
        std::vector<uint8_t> bytes(this->pub_.data(), this->pub_.data() + this->pub_.size());
        return bytes;
    }
    return concat_bytes(this->pub_, this->cc_);
} // BIP32PublicKey::toBytes

bool BIP32PrivateKey::clear() {
    std::fill(this->prv_.begin(), this->prv_.end(), 0);
    return std::accumulate(this->prv_.begin(), this->prv_.end(), 0) == 0;
} // BIP32PrivateKey::clear

BIP32PrivateKey::BIP32PrivateKey(std::string prv, std::string cc) {
    if (prv.size() != this->prv_.size() * 2)
        throw std::invalid_argument("Invalid hex private key size.");
    if (cc.size() != this->cc_.size() * 2)
        throw std::invalid_argument("Invalid hex chain code size.");
    auto bytes = BASE16::decode(prv + cc);
    std::copy_n(bytes.begin(), this->prv_.size(), this->prv_.begin());
    std::copy_n(bytes.begin() + this->prv_.size(), this->cc_.size(),
                this->cc_.begin());
} // BIP32PrivateKey::BIP32PrivateKey

BIP32PrivateKey::BIP32PrivateKey(std::span<const uint8_t> xpriv) {
    if (xpriv.size() != this->prv_.size() + this->cc_.size())
        throw std::invalid_argument("Invalid extended private key size.");
    std::copy_n(xpriv.begin(), this->prv_.size(), this->prv_.begin());
    std::copy_n(xpriv.begin() + this->prv_.size(), this->cc_.size(),
                this->cc_.begin());
} // BIP32PrivateKey::BIP32PrivateKey

BIP32PrivateKey BIP32PrivateKey::fromBech32(std::string_view bech32_str) {
    auto [hrp1, data] = cardano::BECH32::decode(bech32_str);
    std::array<uint8_t, ENCRYPTED_KEY_SIZE> skey;
    std::array<uint8_t, CHAIN_CODE_SIZE> cc;
    std::copy_n(data.begin(), ENCRYPTED_KEY_SIZE, skey.begin());
    std::copy_n(data.begin() + ENCRYPTED_KEY_SIZE, CHAIN_CODE_SIZE, cc.begin());
    return BIP32PrivateKey(skey, cc);
} // BIP32PrivateKey::fromBech32

auto tweak_bits_byron(std::span<uint8_t> data) -> void {
    // clear the lowest 3 bits
    // clear the highest bit
    // set the highest 2nd bit
    data[0]  &= 0b11111000;
    data[31] &= 0b01111111;
    data[31] |= 0b01000000;
} // tweak_bits_byron

auto tweak_bits_icarus(std::span<uint8_t> data) -> void {
    // on the ed25519 scalar leftmost 32 bytes:
    // * clear the lowest 3 bits
    // * clear the highest bit
    // * clear the 3rd highest bit
    // * set the highest 2nd bit
    data[0]  &= 0b11111000;
    data[31] &= 0b00011111;
    data[31] |= 0b01000000;
} // tweak_bits_icarus

auto hash_repeatedly(std::vector<uint8_t> key, size_t count)
-> std::vector<uint8_t> {
    if (count > 1000)
        std::runtime_error("Cannot generate root key (looping forever).");
    
    auto mac = Botan::MessageAuthenticationCode::create("HMAC(SHA-512)");
    if (!mac)
        std::runtime_error("Unable to create HMAC object.");

    auto message = "Root Seed Chain " + std::to_string(count);
    auto data = std::vector<uint8_t>(message.begin(), message.end());
    mac->set_key(key);
    mac->update(data);
    auto tag = mac->final();

    auto iL = std::vector<uint8_t>(tag.begin(), tag.begin() + 32);
    auto iR = std::vector<uint8_t>(tag.begin() + 32, tag.end());

    auto sha512 = Botan::HashFunction::create("SHA-512");
    sha512->update(iL.data(), iL.size());
    auto prv = sha512->final();
    tweak_bits_byron(prv);

    if (prv[31] & 0b00100000)
        return hash_repeatedly(key, count + 1);

    return concat_bytes(prv, iR);
} // hash_repeatedly

auto hash_seed(std::span<const uint8_t> seed) -> std::vector<uint8_t> {
    // CBOR encode the seed.
    uint8_t *buffer;
    size_t buffer_size;
    auto cbor_seed = cbor_build_bytestring(seed.data(), seed.size());
    auto cbor_len = cbor_serialize_alloc(cbor_seed, &buffer, &buffer_size);
    cbor_decref(&cbor_seed);

    // Blake2b-SHA256 encode the CBOR encoded seed (32 byte result).
    auto blake2b = Botan::HashFunction::create("Blake2b(256)");
    blake2b->update(buffer, cbor_len);
    auto hashed = blake2b->final();
    free(buffer);
    
    // CBOR encode the hashed seed (34 bytes after CBOR encoding).
    auto cbor_hash = cbor_build_bytestring(hashed.data(), hashed.size());
    cbor_len = cbor_serialize_alloc(cbor_hash, &buffer, &buffer_size);
    cbor_decref(&cbor_hash);

    // Store the result in a std::vector container.
    auto hashed_seed = std::vector<uint8_t>(buffer, buffer + cbor_len);
    free(buffer);

    return hashed_seed;
} // hash_seed

auto BIP32PrivateKey::fromMnemonicByron(cardano::Mnemonic mn)
-> BIP32PrivateKey {
    auto hashed_seed = hash_seed(mn.toSeed());
    auto xprv = hash_repeatedly(hashed_seed, 1);
    return BIP32PrivateKey(xprv);
} // BIP32PrivateKey::fromMnemonicByron

auto BIP32PrivateKey::fromMnemonic(cardano::Mnemonic mn,
                                   std::string_view passphrase)
-> BIP32PrivateKey {
    auto mac = Botan::MessageAuthenticationCode::create("HMAC(SHA-512)");
    auto pbkdf2 = std::unique_ptr<Botan::PBKDF2>(
        new Botan::PBKDF2(*mac.release(), 4096));
    auto seed = mn.toSeed();
    auto key = std::vector<uint8_t>(96);
    pbkdf2->derive_key(key.data(), key.size(), passphrase.data(),
                       passphrase.size(), seed.data(), seed.size());
    tweak_bits_icarus(key);
    return BIP32PrivateKey(key);
}; // BIP32PrivateKey::fromMnemonic

auto BIP32PrivateKey::fromMnemonic(cardano::Mnemonic mn) -> BIP32PrivateKey {
    return BIP32PrivateKey::fromMnemonic(mn, "");
}; // BIP32PrivateKey::fromMnemonic

std::string BIP32PrivateKey::toBech32(std::string hrp) {
    std::vector<uint8_t> data;
    data.reserve(ENCRYPTED_KEY_SIZE + CHAIN_CODE_SIZE);
    data.insert(data.begin(), this->prv_.begin(), this->prv_.end());
    data.insert(data.begin() + ENCRYPTED_KEY_SIZE, this->cc_.begin(),
                this->cc_.end());
    return BECH32::encode(hrp, data);
} // BIP32PrivateKey::toBech32

std::string BIP32PrivateKey::toBase16() {
    auto bytes = concat_bytes(this->prv_, this->cc_);
    return BASE16::encode(bytes);
} // ExtendedPublicKey::toBase16

BIP32PublicKey BIP32PrivateKey::toPublic() {
    std::array<uint8_t, PUBLIC_KEY_SIZE> pub_key;
    cardano_crypto_ed25519_publickey(this->prv_.data(), pub_key.data());
    return BIP32PublicKey(pub_key, this->cc_);
} // BIP32PrivateKey::toPublic

auto BIP32PrivateKey::deriveChild(uint32_t index, uint32_t derivation_mode)
-> BIP32PrivateKey {
    // Build the encrypted key struct for the derive function.
    encrypted_key ek;
    std::copy(this->prv_.begin(), this->prv_.end(), std::begin(ek.ekey));
    std::copy(this->cc_.begin(), this->cc_.end(), std::begin(ek.cc));
    cardano_crypto_ed25519_publickey(this->prv_.data(), ek.pkey);

    // Perform the child key derivation using the cardano crypto C library.
    derivation_scheme_mode mode;
    switch (derivation_mode)
    {
    case 1:
        mode = DERIVATION_V1;
        break;
    case 2:
    default:
        mode = DERIVATION_V2;
        break;
    }
    uint32_t pw_len = 0; // This will skip the decryption
    uint8_t *pw = NULL;
    encrypted_key ek_out;
    wallet_encrypted_derive_private(&ek, pw, pw_len, index, &ek_out, mode);

    std::array<uint8_t, ENCRYPTED_KEY_SIZE> skey;
    std::array<uint8_t, CHAIN_CODE_SIZE> cc;
    std::copy_n(std::begin(ek_out.ekey), ENCRYPTED_KEY_SIZE, skey.begin());
    std::copy_n(std::begin(ek_out.cc), CHAIN_CODE_SIZE, cc.begin());
    return BIP32PrivateKey(skey, cc);
} // BIP32PrivateKey::deriveChild

BIP32PrivateKeyEncrypted BIP32PrivateKey::encrypt(std::string password) {
    std::array<uint8_t, ENCRYPTED_KEY_SIZE> prv{};
    wallet_decrypt_private( // encrypts or decrypts
        (const uint8_t *)password.c_str(), password.size(), this->prv_.data(),
        prv.data());
    auto enc_key = BIP32PrivateKeyEncrypted(prv, this->cc_);
    this->clear();
    return enc_key;
} // BIP32PrivateKey::encrypt

BIP32PrivateKeyEncrypted::BIP32PrivateKeyEncrypted(std::string prv,
                                                   std::string cc) {
    if (prv.size() != this->xprv_.size() * 2)
        throw std::invalid_argument("Invalid hex public key size.");
    if (cc.size() != this->cc_.size() * 2)
        throw std::invalid_argument("Invalid hex chain code size.");
    auto bytes = BASE16::decode(prv + cc);
    std::copy_n(bytes.begin(), this->xprv_.size(), this->xprv_.begin());
    std::copy_n(bytes.begin() + this->xprv_.size(), this->cc_.size(),
                this->cc_.begin());
} // BIP32PrivateKeyEncrypted::ExtendedPublicKey

auto BIP32PrivateKeyEncrypted::deriveChild(
    uint32_t index, std::string password, uint32_t derivation_mode
) -> BIP32PrivateKeyEncrypted {
    auto decrypted = this->decrypt(password);
    auto child = decrypted.deriveChild(index, derivation_mode);
    return child.encrypt(password);
} // BIP32PrivateKeyEncrypted::deriveChild

auto BIP32PrivateKeyEncrypted::toPublic(std::string password)
-> BIP32PublicKey {
    std::array<uint8_t, PUBLIC_KEY_SIZE> pub{};
    wallet_encrypted_private_to_public((const uint8_t *)password.c_str(),
                                       password.size(), this->xprv_.data(),
                                       pub.data());
    return BIP32PublicKey(pub, this->cc_);
} // BIP32PrivateKeyEncrypted::toPublic

BIP32PrivateKey BIP32PrivateKeyEncrypted::decrypt(std::string password) {
    std::array<uint8_t, ENCRYPTED_KEY_SIZE> prv{};
    wallet_decrypt_private((const uint8_t *)password.c_str(), password.size(),
                           this->xprv_.data(), prv.data());
    return BIP32PrivateKey(prv, this->cc_);
} // BIP32PrivateKeyEncrypted::decrypt
