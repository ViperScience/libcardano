// Copyright (c) 2023 Viper Science LLC
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

#include <cardano/stake_pool.hpp>

// Standard library headers

// Third-Party headers
#include <botan/hash.h>
#include <cppbor/cppbor.h>

// Libcardano headers
#include <cardano/encodings.hpp>

#include "utils.hpp"

using namespace cardano::stake_pool;

auto ColdVerificationKey::saveToFile(std::string_view fpath) const -> void
{
    const auto key_bytes = this->bytes();
    const auto key_cbor_hex = BASE16::encode(
        cppbor::Bstr({key_bytes.data(), key_bytes.size()}).encode()
    );
    cardano::writeEnvelopeTextFile(fpath, kTypeStr, kDescStr, key_cbor_hex);
}  // ColdVerificationKey::saveToFile

auto ColdVerificationKey::asBech32() const -> std::string
{
    static constexpr auto hrp = "pool_vk";
    return BECH32::encode(hrp, this->bytes());
}  // ColdVerificationKey::asBech32

auto ColdVerificationKey::poolId() -> std::array<uint8_t, STAKE_POOL_ID_SIZE>
{
    const auto key_bytes = this->bytes();
    const auto blake2b = Botan::HashFunction::create("Blake2b(224)");
    blake2b->update(key_bytes.data(), key_bytes.size());
    const auto hashed = blake2b->final();
    auto ret = std::array<uint8_t, STAKE_POOL_ID_SIZE>();
    std::copy_n(hashed.begin(), STAKE_POOL_ID_SIZE, ret.begin());
    return ret;
}  // ColdVerificationKey::poolId

auto ColdSigningKey::saveToFile(std::string_view fpath) const -> void
{
    const auto key_bytes = this->bytes();
    const auto key_cbor_hex = BASE16::encode(
        cppbor::Bstr({key_bytes.data(), key_bytes.size()}).encode()
    );
    cardano::writeEnvelopeTextFile(fpath, kTypeStr, kDescStr, key_cbor_hex);
}  // ColdSigningKey::saveToFile

auto ColdSigningKey::asBech32() const -> std::string
{
    static constexpr auto hrp = "pool_sk";
    return BECH32::encode(hrp, this->bytes());
}  // ColdSigningKey::asBech32

auto ColdSigningKey::poolId() -> std::array<uint8_t, STAKE_POOL_ID_SIZE>
{
    return this->verificationKey().poolId();
}  // ColdSigningKey::poolId

auto ColdSigningKey::extend() const -> ExtendedColdSigningKey
{
    return ExtendedColdSigningKey{ed25519::PrivateKey::extend().bytes()};
}  // ColdSigningKey::extend

auto ExtendedColdSigningKey::fromRootKey(const BIP32PrivateKey& root)
    -> ExtendedColdSigningKey
{
    auto pool_key = root.deriveChild(HardenIndex(1853))
                        .deriveChild(HardenIndex(1815))
                        .deriveChild(HardenIndex(0))
                        .deriveChild(HardenIndex(0));
    return ExtendedColdSigningKey{pool_key.toBytes()};
}  // ExtendedColdSigningKey::fromRootKey

auto ExtendedColdSigningKey::fromMnemonic(const cardano::Mnemonic& mn)
    -> ExtendedColdSigningKey
{
    auto root_key = BIP32PrivateKey::fromMnemonic(mn);
    auto pool_key = root_key.deriveChild(HardenIndex(1853))
                        .deriveChild(HardenIndex(1815))
                        .deriveChild(HardenIndex(0))
                        .deriveChild(HardenIndex(0));
    return ExtendedColdSigningKey{pool_key.toBytes()};
}  // ExtendedColdSigningKey::fromMnemonic

auto ExtendedColdSigningKey::saveToFile(std::string_view fpath) const -> void
{
    const auto key_bytes = this->bytes();
    const auto key_cbor_hex = BASE16::encode(
        cppbor::Bstr({key_bytes.data(), key_bytes.size()}).encode()
    );
    cardano::writeEnvelopeTextFile(fpath, kTypeStr, kDescStr, key_cbor_hex);
}  // ExtendedColdSigningKey::saveToFile

auto ExtendedColdSigningKey::asBech32() const -> std::string
{
    static constexpr auto hrp = "pool_xsk";
    return BECH32::encode(hrp, this->bytes());
}  // ExtendedColdSigningKey::asBech32

auto ExtendedColdSigningKey::poolId() -> std::array<uint8_t, STAKE_POOL_ID_SIZE>
{
    return this->verificationKey().poolId();
}  // ExtendedColdSigningKey::poolId
