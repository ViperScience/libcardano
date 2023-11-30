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
#include <string>

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
    const auto key_bytes = this->skey_.extend().bytes();
    return ExtendedColdSigningKey(key_bytes);
}  // ColdSigningKey::extend

auto ExtendedColdSigningKey::fromRootKey(const BIP32PrivateKey& root)
    -> ExtendedColdSigningKey
{
    const auto pool_key = root.deriveChild(HardenIndex(1853))
                              .deriveChild(HardenIndex(1815))
                              .deriveChild(HardenIndex(0))
                              .deriveChild(HardenIndex(0));
    const auto pool_key_bytes = pool_key.toBytes(false);
    return ExtendedColdSigningKey(pool_key_bytes);
}  // ExtendedColdSigningKey::fromRootKey

auto ExtendedColdSigningKey::fromMnemonic(const cardano::Mnemonic& mn)
    -> ExtendedColdSigningKey
{
    const auto root_key = BIP32PrivateKey::fromMnemonic(mn);
    const auto pool_key = root_key.deriveChild(HardenIndex(1853))
                              .deriveChild(HardenIndex(1815))
                              .deriveChild(HardenIndex(0))
                              .deriveChild(HardenIndex(0));
    const auto pool_key_bytes = pool_key.toBytes(false);
    return ExtendedColdSigningKey(pool_key_bytes);
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

auto OperationalCertificateIssueCounter::serialize(
    const ColdVerificationKey& vkey
) const -> std::vector<uint8_t>
{
    const auto key_bytes = vkey.bytes();
    const auto counter_cbor = cppbor::Array(
        this->count_, cppbor::Bstr({key_bytes.data(), key_bytes.size()})
    );
    return counter_cbor.encode();
}  // OperationalCertificateIssueCounter::toCBOR

auto OperationalCertificateIssueCounter::saveToFile(
    std::string_view fpath, const ColdVerificationKey& vkey
) const -> void
{
    static constexpr auto type_str = "NodeOperationalCertificateIssueCounter";
    static constexpr auto desc_str_head = "Next certificate issue number: ";
    const auto desc_str = desc_str_head + std::to_string(this->count_);
    const auto counter_cbor_hex = BASE16::encode(this->serialize(vkey));
    cardano::writeEnvelopeTextFile(fpath, type_str, desc_str, counter_cbor_hex);
}  // OperationalCertificateIssueCounter::saveToFile

////////////////////////////////////////////////////////////////////////////////

#include <debug_utils.hpp>

constexpr auto U64TO8_BE(const uint64_t v) -> std::array<uint8_t, 8>
{
    auto out = std::array<uint8_t, 8>{};
    out[7] = (uint8_t)v;
    out[6] = (uint8_t)(v >> 8);
    out[5] = (uint8_t)(v >> 16);
    out[4] = (uint8_t)(v >> 24);
    out[3] = (uint8_t)(v >> 32);
    out[2] = (uint8_t)(v >> 40);
    out[1] = (uint8_t)(v >> 48);
    out[0] = (uint8_t)(v >> 56);
    return out;
}  // U64TO8_BE

constexpr auto U64TO8_LE(const uint64_t v) -> std::array<uint8_t, 8>
{
    auto out = std::array<uint8_t, 8>{};
    out[0] = (uint8_t)v;
    out[1] = (uint8_t)(v >> 8);
    out[2] = (uint8_t)(v >> 16);
    out[3] = (uint8_t)(v >> 24);
    out[4] = (uint8_t)(v >> 32);
    out[5] = (uint8_t)(v >> 40);
    out[6] = (uint8_t)(v >> 48);
    out[7] = (uint8_t)(v >> 56);
    return out;
}  // U64TO8_LE

auto opCertMessageToSign(cardano::babbage::OperationalCert cert)
    -> std::vector<uint8_t>
{
    auto be = cardano::concat_bytes(
        cardano::concat_bytes(cert.hot_vkey, U64TO8_BE(cert.sequence_number)),
        U64TO8_BE(cert.kes_period)
    );
    cardano_debug::print_bytes(be);
    return be;
}

auto OperationalCertificateManager::generateUnsigned(
    const KesVerificationKey& hot_key,
    const OperationalCertificateIssueCounter& counter,
    size_t kes_period
) -> OperationalCertificateManager
{
    auto cert = cardano::babbage::OperationalCert();
    cert.hot_vkey = hot_key.bytes();
    cert.kes_period = kes_period;
    cert.sequence_number = counter.count();
    return OperationalCertificateManager(cert);
}  // OperationalCertificateManager::generateUnsigned

auto OperationalCertificateManager::generate(
    const KesVerificationKey& hot_key,
    const OperationalCertificateIssueCounter& counter,
    size_t kes_period,
    const ColdSigningKey& skey
) -> OperationalCertificateManager
{
    auto mgr = OperationalCertificateManager::generateUnsigned(
        hot_key, counter, kes_period
    );
    mgr.sign(skey);
    return mgr;
}  // OperationalCertificateManager::generateUnsigned

auto OperationalCertificateManager::generate(
    const KesVerificationKey& hot_key,
    const OperationalCertificateIssueCounter& counter,
    size_t kes_period,
    const ExtendedColdSigningKey& skey
) -> OperationalCertificateManager
{
    auto mgr = OperationalCertificateManager::generateUnsigned(
        hot_key, counter, kes_period
    );
    mgr.sign(skey);
    return mgr;
}  // OperationalCertificateManager::generate

auto OperationalCertificateManager::sign(const ColdSigningKey& skey) -> void
{
    this->cert_.sigma = skey.sign(opCertMessageToSign(this->cert_));
}  // OperationalCertificateManager::sign

auto OperationalCertificateManager::sign(const ExtendedColdSigningKey& skey)
    -> void
{
    this->cert_.sigma = skey.sign(opCertMessageToSign(this->cert_));
}  // OperationalCertificateManager::sign

auto OperationalCertificateManager::verify(const ColdVerificationKey& vkey
) const -> bool
{
    auto msg = opCertMessageToSign(this->cert_);
    return vkey.verifySignature(msg, this->cert_.sigma);
}  // OperationalCertificateManager::verify

auto OperationalCertificateManager::serialize() const -> std::vector<uint8_t>
{
    const auto sigm_bytes = this->cert_.sigma;
    const auto hkey_bytes = this->cert_.hot_vkey;
    const auto cbor_bytes = cppbor::Array(
        cppbor::Bstr({hkey_bytes.data(), hkey_bytes.size()}),
        cppbor::Uint(this->cert_.sequence_number),
        cppbor::Uint(this->cert_.kes_period),
        cppbor::Bstr({sigm_bytes.data(), sigm_bytes.size()})
    );
    return cbor_bytes.encode();
}  // OperationalCertificateManager::serialize

auto OperationalCertificateManager::serialize(const ColdVerificationKey& vkey
) const -> std::vector<uint8_t>
{
    const auto sigm_bytes = this->cert_.sigma;
    const auto hkey_bytes = this->cert_.hot_vkey;
    const auto vkey_bytes = vkey.bytes();
    const auto cbor_bytes = cppbor::Array(
        cppbor::Array(
            cppbor::Bstr({hkey_bytes.data(), hkey_bytes.size()}),
            cppbor::Uint(this->cert_.sequence_number),
            cppbor::Uint(this->cert_.kes_period),
            cppbor::Bstr({sigm_bytes.data(), sigm_bytes.size()})
        ),
        cppbor::Bstr({vkey_bytes.data(), vkey_bytes.size()})
    );
    return cbor_bytes.encode();
}  // OperationalCertificateManager::serialize

auto OperationalCertificateManager::saveToFile(
    std::string_view fpath, const ColdVerificationKey& vkey
) const -> void
{
    static constexpr auto type_str = "NodeOperationalCertificate";
    const auto counter_cbor_hex = BASE16::encode(this->serialize(vkey));
    cardano::writeEnvelopeTextFile(fpath, type_str, "", counter_cbor_hex);
}  // OperationalCertificateManager::saveToFile