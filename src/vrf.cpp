// Copyright (c) 2024 Viper Science LLC
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

#include <cardano/vrf.hpp>

// Standard library headers
#include <stdexcept>

// Third-party headers
#include <sodium.h>

using namespace cardano;

auto VRFPublicKey::verifyProof(
    std::span<const uint8_t> msg,
    std::span<const uint8_t> proof
) const -> bool
{
    unsigned char output[64];
    auto pk_bytes = this->bytes();
    auto result = crypto_vrf_ietfdraft03_verify(
        output, pk_bytes.data(), proof.data(), msg.data(), msg.size()
    );
    return result == 0;
}  // VRFPublicKey::verifyProof

VRFSecretKey::VRFSecretKey(std::span<const uint8_t, VRF_SECRET_KEY_SIZE> prv)
{
    std::move(prv.begin(), prv.end(), this->prv_.begin());
}  // VRFSecretKey::VRFSecretKey

auto VRFSecretKey::generate() -> VRFSecretKey
{
    const auto seed = ed25519::PrivateKey::generate();
    const auto seed_bytes = seed.bytes();
    return VRFSecretKey::fromSeed(seed_bytes);
}  // VRFSecretKey::generate

auto VRFSecretKey::fromSeed(std::span<const uint8_t, VRF_SEED_SIZE> seed
) -> VRFSecretKey
{
    auto pk = ByteArray<crypto_sign_PUBLICKEYBYTES>();
    auto sk = SecureByteArray<crypto_sign_SECRETKEYBYTES>();
    crypto_sign_ed25519_seed_keypair(pk.data(), sk.data(), seed.data());
    return VRFSecretKey{sk};
}  // VRFSecretKey::fromSeed

auto VRFSecretKey::publicKey() const -> VRFPublicKey
{
    auto pk_bytes = std::array<uint8_t, VRF_PUBLIC_KEY_SIZE>();
    std::copy_n(
        this->prv_.begin() + VRF_SEED_SIZE,
        VRF_PUBLIC_KEY_SIZE,
        pk_bytes.begin()
    );
    return VRFPublicKey{pk_bytes};
}  // VRFSecretKey::publicKey

auto VRFSecretKey::isValid() const -> bool
{
    const auto bytes = std::span<const uint8_t>(this->prv_);
    auto sk = ed25519::PrivateKey(bytes.first<ed25519::KEY_SIZE>());
    auto pk = ed25519::PublicKey(bytes.last<ed25519::PUBLIC_KEY_SIZE>());
    return pk.bytes() == sk.publicKey().bytes();
}  // VRFSecretKey::isValid

auto VRFSecretKey::sign(std::span<const uint8_t> msg
) const -> std::array<uint8_t, ed25519::SIGNATURE_SIZE>
{
    auto sk =
        ed25519::PrivateKey(std::span(this->prv_).first<ed25519::KEY_SIZE>());
    return sk.sign(msg);
}  // VRFSecretKey::sign

auto VRFSecretKey::constructProof(std::span<const uint8_t> msg
) -> std::array<uint8_t, VRF_PROOF_SIZE>
{
    auto proof = std::array<uint8_t, VRF_PROOF_SIZE>{};
    auto result = crypto_vrf_ietfdraft03_prove(
        proof.data(), this->prv_.data(), msg.data(), msg.size()
    );
    if (result != 0)
    {
        throw std::runtime_error("crypto_vrf_prove failed.");
    }
    return proof;
}  // VRFSecretKey::constructProof

auto VRFSecretKey::verifyProof(
    std::span<const uint8_t> msg,
    std::span<const uint8_t, VRF_PROOF_SIZE> proof
) const -> bool
{
    auto pk = this->publicKey();
    return pk.verifyProof(msg, proof);
}  // VRFSecretKey::verifyProof

auto VRFSecretKey::proofToHash(std::span<const uint8_t, VRF_PROOF_SIZE> proof
) -> std::array<uint8_t, VRF_PROOF_HASH_SIZE>
{
    auto hash = std::array<uint8_t, VRF_PROOF_HASH_SIZE>{};
    auto result =
        crypto_vrf_ietfdraft03_proof_to_hash(hash.data(), proof.data());
    if (result != 0)
    {
        throw std::runtime_error("crypto_vrf_proof_to_hash failed.");
    }
    return hash;
}  // VRFSecretKey::proofToHash

auto VRFSecretKey::hash(std::span<const uint8_t> msg
) -> std::array<uint8_t, VRF_PROOF_HASH_SIZE>
{
    return VRFSecretKey::proofToHash(this->constructProof(msg));
}  // VRFSecretKey::hash
