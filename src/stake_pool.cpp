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

using namespace cardano;
using namespace cardano::stake_pool;

static constexpr auto MIN_POOL_COST_LOVELACE = 170000000;

auto ColdVerificationKey::saveToFile(std::string_view fpath) const -> void
{
    const auto key_bytes = this->bytes();
    const auto key_cbor_hex = BASE16::encode(
        cppbor::Bstr({key_bytes.data(), key_bytes.size()}).encode()
    );
    utils::writeEnvelopeTextFile(fpath, kTypeStr, kDescStr, key_cbor_hex);
}  // ColdVerificationKey::saveToFile

auto ColdVerificationKey::asBech32() const -> std::string
{
    static constexpr auto hrp = "pool_vk";
    return BECH32::encode(hrp, this->bytes());
}  // ColdVerificationKey::asBech32

auto ColdVerificationKey::poolId() const
    -> std::array<uint8_t, STAKE_POOL_ID_SIZE>
{
    const auto key_bytes = this->bytes();
    const auto blake2b = Botan::HashFunction::create("Blake2b(224)");
    blake2b->update(key_bytes.data(), key_bytes.size());
    const auto hashed = blake2b->final();
    return utils::makeByteArray<STAKE_POOL_ID_SIZE>(hashed);
}  // ColdVerificationKey::poolId

auto ColdSigningKey::saveToFile(std::string_view fpath) const -> void
{
    const auto key_bytes = this->bytes();
    const auto key_cbor_hex = BASE16::encode(
        cppbor::Bstr({key_bytes.data(), key_bytes.size()}).encode()
    );
    utils::writeEnvelopeTextFile(fpath, kTypeStr, kDescStr, key_cbor_hex);
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
    utils::writeEnvelopeTextFile(fpath, kTypeStr, kDescStr, key_cbor_hex);
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
    utils::writeEnvelopeTextFile(fpath, type_str, desc_str, counter_cbor_hex);
}  // OperationalCertificateIssueCounter::saveToFile

auto opCertMessageToSign(cardano::shelley::OperationalCert cert)
    -> std::vector<uint8_t>
{
    auto be = utils::concatBytes(
        utils::concatBytes(
            cert.hot_vkey, utils::U64TO8_BE(cert.sequence_number)
        ),
        utils::U64TO8_BE(cert.kes_period)
    );
    return be;
}

auto OperationalCertificateManager::generateUnsigned(
    const KesVerificationKey& hot_key,
    const OperationalCertificateIssueCounter& counter,
    size_t kes_period
) -> OperationalCertificateManager
{
    auto cert = cardano::shelley::OperationalCert();
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
    utils::writeEnvelopeTextFile(fpath, type_str, "", counter_cbor_hex);
}  // OperationalCertificateManager::saveToFile

RegistrationCertificateManager::RegistrationCertificateManager(
    const ColdVerificationKey& vkey,
    const VrfVerificationKey& vrf_vkey,
    uint64_t pledge_lovelace,
    uint64_t cost_lovelace,
    double margin,
    const RewardsAddress& reward_account
)
{
    if (margin < 0.0 || margin > 1.0)
    {
        throw std::invalid_argument("margin must be between 0 and 1");
    }

    if (cost_lovelace < MIN_POOL_COST_LOVELACE)
    {
        throw std::invalid_argument("cost must be above min pool cost.");
    }

    auto [n, d] = utils::rationalApprox(margin, 4096);

    this->cert_.pool_params.pool_operator = vkey.poolId();
    this->cert_.pool_params.vrf_keyhash = vrf_vkey.hash();
    this->cert_.pool_params.pledge = pledge_lovelace;
    this->cert_.pool_params.cost = cost_lovelace;
    this->cert_.pool_params.margin = {(uint64_t)n, (uint64_t)d};
    this->cert_.pool_params.reward_account = reward_account.toBytes(true);
}  // RegistrationCertificateManager::RegistrationCertificateManager

auto RegistrationCertificateManager::setMargin(double margin) -> void
{
    if (margin < 0.0 || margin > 1.0)
    {
        throw std::invalid_argument("margin must be between 0 and 1");
    }
    auto [n, d] = utils::rationalApprox(margin, 4096);
    this->cert_.pool_params.margin = {(uint64_t)n, (uint64_t)d};
}  // RegistrationCertificateManager::setMargin

auto RegistrationCertificateManager::addOwner(const RewardsAddress& stake_addr)
    -> void
{
    auto byte_vec = stake_addr.toBytes();
    auto arr = utils::makeByteArray<28>(byte_vec);
    this->cert_.pool_params.pool_owners.insert(arr);
}  // RegistrationCertificateManager::addOwner

auto RegistrationCertificateManager::addRelay(std::string_view relay) -> void
{
    this->cert_.pool_params.relays.push_back(
        std::make_unique<shelley::MultiHostName>(relay)
    );
}  // RegistrationCertificateManager::addRelay

auto RegistrationCertificateManager::addRelay(
    std::string_view dns_name, uint16_t port
) -> void
{
    this->cert_.pool_params.relays.push_back(
        std::make_unique<shelley::SingleHostName>(dns_name, port)
    );
}  // RegistrationCertificateManager::addRelay

auto RegistrationCertificateManager::addRelay(
    std::array<uint8_t, 4> ip, uint16_t port
) -> void
{
    this->cert_.pool_params.relays.push_back(
        std::make_unique<shelley::SingleHostAddr>(ip, port)
    );
}  // RegistrationCertificateManager::addRelay

auto RegistrationCertificateManager::addRelay(
    std::array<uint8_t, 16> ip, uint16_t port
) -> void
{
    this->cert_.pool_params.relays.push_back(
        std::make_unique<shelley::SingleHostAddr>(ip, port)
    );
}  // RegistrationCertificateManager::addRelay

auto RegistrationCertificateManager::setMetadata(
    std::string_view metadata_url, std::span<const uint8_t> hash
) -> void
{
    this->cert_.pool_params.pool_metadata.reset();
    this->cert_.pool_params.pool_metadata.emplace(
        metadata_url, utils::makeByteArray<32>(hash)
    );
}  // RegistrationCertificateManager::setMetadata

auto RegistrationCertificateManager::saveToFile(std::string_view fpath) const
    -> void
{
    static constexpr auto type_str = "NodeOperationalCertificate";
    static constexpr auto desc_str = "Stake Pool Registration Certificate";
    const auto cbor_hex = BASE16::encode(this->serialize());
    utils::writeEnvelopeTextFile(fpath, type_str, desc_str, cbor_hex);
}  // RegistrationCertificateManager::saveToFile

auto DeregistrationCertificateManager::saveToFile(std::string_view fpath) const
    -> void
{
    static constexpr auto type_str = "DeregistrationCertificateManager";
    static constexpr auto desc_str = "Stake Pool Retirement Certificate";
    const auto cbor_hex = BASE16::encode(this->serialize());
    utils::writeEnvelopeTextFile(fpath, type_str, desc_str, cbor_hex);
}  // DeregistrationCertificateManager::saveToFile

auto VrfVerificationKey::hash() const -> std::array<uint8_t, 32>
{
    // Blake2b-SHA256 encode the CBOR encoded seed (32 byte result).
    const auto blake2b = Botan::HashFunction::create("Blake2b(256)");
    blake2b->update(vkey_.bytes().data(), vkey_.bytes().size());
    const auto hashed = blake2b->final();
    return utils::makeByteArray<32>(hashed);
}  // VrfVerificationKey::hash