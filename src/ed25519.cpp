// Copyright (c) 2022 Viper Science LLC
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
#include <memory>
#include <stdexcept>

// Third-Party Library Headers
#include <botan/auto_rng.h>
#include <botan/hash.h>
#include <botan/rng.h>
#include <sodium.h>

// Public Cardano Headers
#include <cardano/ed25519.hpp>

// Private Viper25519 code
#include "utils.hpp"

using namespace cardano;

ed25519::PublicKey::PublicKey(
    std::span<const uint8_t, ed25519::PUBLIC_KEY_SIZE> pub
)
{
    std::copy_n(pub.begin(), ed25519::KEY_SIZE, this->pub_.begin());
}  // PublicKey::PublicKey

auto ed25519::PublicKey::verifySignature(
    std::span<const uint8_t> msg,
    std::span<const uint8_t, SIGNATURE_SIZE> sig
) const -> bool
{
    return crypto_sign_verify_detached(
               sig.data(), msg.data(), msg.size(), this->pub_.data()
           ) == 0;
}  // PublicKey::verify

ed25519::PrivateKey::PrivateKey(std::span<const uint8_t, ed25519::KEY_SIZE> prv)
{
    std::move(prv.begin(), prv.end(), this->prv_.begin());
}  // PrivateKey::PrivateKey

auto ed25519::PrivateKey::generate() -> ed25519::PrivateKey
{
    auto pk = SecureByteArray<crypto_sign_PUBLICKEYBYTES>();
    auto sk = SecureByteArray<crypto_sign_SECRETKEYBYTES>();
    crypto_sign_keypair(pk.data(), sk.data());
    return ed25519::PrivateKey(std::span(sk).first<ed25519::KEY_SIZE>());
}  // PrivateKey::generate

auto ed25519::PrivateKey::publicKey() const -> ed25519::PublicKey
{
    auto pk = ByteArray<crypto_sign_PUBLICKEYBYTES>();
    auto sk = SecureByteArray<crypto_sign_SECRETKEYBYTES>();
    crypto_sign_ed25519_seed_keypair(pk.data(), sk.data(), this->prv_.data());
    return ed25519::PublicKey(pk);
}  // PrivateKey::publicKey

auto ed25519::PrivateKey::sign(std::span<const uint8_t> msg
) const -> ByteArray<SIGNATURE_SIZE>
{
    auto pk = ByteArray<crypto_sign_PUBLICKEYBYTES>();
    auto sk = SecureByteArray<crypto_sign_SECRETKEYBYTES>();
    crypto_sign_seed_keypair(pk.data(), sk.data(), this->prv_.data());

    auto sig = ByteArray<SIGNATURE_SIZE>();
    crypto_sign_detached(sig.data(), NULL, msg.data(), msg.size(), sk.data());
    return sig;
}  // PrivateKey::sign
