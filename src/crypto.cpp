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

// Public Cardano++ Headers 
#include <cardano/crypto.hpp>
#include <cardano/encodings.hpp>

// Private Cardano++ Headers
#include "cardano_crypto_interface.h"
#include "utils.hpp"

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

BIP32PublicKey BIP32PublicKey::deriveChild(uint32_t index) {
    uint8_t *pub_in = this->pub_.data();
    uint8_t *cc_in = this->cc_.data();

    BIP32PublicKey k;
    uint8_t *pub_out = k.pub_.data();
    uint8_t *cc_out = k.cc_.data();

    // Derive the child public key for the soft index.
    int flag = wallet_encrypted_derive_public(pub_in, cc_in, index, pub_out,
                                              cc_out, DERIVATION_V2);
    if (flag != 0)
        throw std::invalid_argument(
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

bool BIP32PrivateKey::clear() {
    std::fill(this->prv_.begin(), this->prv_.end(), 0);
    return std::accumulate(this->prv_.begin(), this->prv_.end(), 0) == 0;
} // BIP32PrivateKey::clear

BIP32PrivateKey::BIP32PrivateKey(std::string prv, std::string cc) {
    if (prv.size() != this->prv_.size() * 2)
        throw std::invalid_argument("Invalid hex public key size.");
    if (cc.size() != this->cc_.size() * 2)
        throw std::invalid_argument("Invalid hex chain code size.");
    auto bytes = BASE16::decode(prv + cc);
    std::copy_n(bytes.begin(), this->prv_.size(), this->prv_.begin());
    std::copy_n(bytes.begin() + this->prv_.size(), this->cc_.size(),
                this->cc_.begin());
} // BIP32PrivateKey::ExtendedPublicKey

BIP32PrivateKey BIP32PrivateKey::fromBech32(std::string bech32_str) {
    auto [hrp1, data] = cardano::BECH32::decode(bech32_str);
    std::array<uint8_t, ENCRYPTED_KEY_SIZE> skey;
    std::array<uint8_t, CHAIN_CODE_SIZE> cc;
    std::copy_n(data.begin(), ENCRYPTED_KEY_SIZE, skey.begin());
    std::copy_n(data.begin() + ENCRYPTED_KEY_SIZE, CHAIN_CODE_SIZE, cc.begin());
    return BIP32PrivateKey(skey, cc);
} // BIP32PrivateKey::fromBech32

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

BIP32PrivateKey BIP32PrivateKey::deriveChild(uint32_t index) {
    // Build the encrypted key struct for the derive function.
    encrypted_key ek;
    std::copy(this->prv_.begin(), this->prv_.end(), std::begin(ek.ekey));
    std::copy(this->cc_.begin(), this->cc_.end(), std::begin(ek.cc));
    cardano_crypto_ed25519_publickey(this->prv_.data(), ek.pkey);

    // Perform the child key derivation using the cardano crypto C library.
    uint32_t pw_len = 0; // This will skip the decryption
    uint8_t *pw = NULL;
    encrypted_key ek_out;
    wallet_encrypted_derive_private(&ek, pw, pw_len, index, &ek_out,
                                    DERIVATION_V2);

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

BIP32PrivateKeyEncrypted
BIP32PrivateKeyEncrypted::deriveChild(uint32_t index, std::string password) {
    auto decrypted = this->decrypt(password);
    auto child = decrypted.deriveChild(index);
    return child.encrypt(password);
} // BIP32PrivateKeyEncrypted::deriveChild

BIP32PublicKey BIP32PrivateKeyEncrypted::toPublic(std::string password) {
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
