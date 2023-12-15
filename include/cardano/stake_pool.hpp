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

#ifndef _CARDANO_STAKE_POOL_HPP_
#define _CARDANO_STAKE_POOL_HPP_

// Standard library headers
#include <functional>

// Third-party library headers
#include <botan/hash.h>

#include <viper25519/ed25519.hpp>

// Public libcardano headers
#include <cardano/address.hpp>
#include <cardano/crypto.hpp>
#include <cardano/encodings.hpp>
#include <cardano/ledger.hpp>
#include <ranges>

/// @brief The root namespace for all Cardano functions and types.
namespace cardano
{

/// @brief The namespace containing all Cardano Stake Pool types.
namespace stake_pool
{

/// @brief Size of a stake pool key in bytes.
static constexpr uint32_t STAKE_POOL_KEY_SIZE = 32;

/// @brief Size of a stake pool ID in bytes.
static constexpr uint32_t STAKE_POOL_ID_SIZE = 28;

// Forward Declarations
class ColdVerificationKey;
class ColdSigningKey;
class ExtendedColdSigningKey;
class VrfVerificationKey;
class VrfSigningKey;
class KesVerificationKey;
class KesSigningKey;
class OperationalCertificateIssueCounter;
class OperationalCertificateManager;

/// @brief A stake pool verification key (Ed25519 public key).
class ColdVerificationKey
{
  private:
    ed25519::PublicKey vkey_;

  public:
    explicit ColdVerificationKey(std::span<const uint8_t> key_bytes)
        : vkey_{key_bytes}
    {
    }

    static constexpr auto kTypeStr = "StakePoolVerificationKey_ed25519";
    static constexpr auto kDescStr = "Stake Pool Operator Verification Key";

    /// @brief Return the key as a byte vector.
    [[nodiscard]] constexpr auto bytes() const
        -> const std::array<uint8_t, ed25519::ED25519_KEY_SIZE>&
    {
        return this->vkey_.bytes();
    }

    /// @brief Verify a signature using the verification key.
    /// @param msg A span of bytes (uint8_t) representing the original message.
    /// @param sig A span of 64 bytes (uint8_t) representing the signature.
    [[nodiscard]] auto verifySignature(
        std::span<const uint8_t> msg, std::span<const uint8_t> sig
    ) const -> bool
    {
        return this->vkey_.verifySignature(msg, sig);
    }

    /// @brief Generate the pool ID as an array of bytes.
    /// @return Pool ID as an array of bytes.
    [[nodiscard]] auto poolId() const
        -> std::array<uint8_t, STAKE_POOL_ID_SIZE>;

    /// @brief Serialize the key bytes as a Bech32 string.
    /// @param hrp The human readable part of the string.
    /// @return String representing the formatted key.
    [[nodiscard]] auto asBech32() const -> std::string;

    /// @brief Export the key to a file in the cardano node JSON format.
    /// @param fpath Path to the file to be (over)written.
    auto saveToFile(std::string_view fpath) const -> void;

};  // ColdVerificationKey

/// @brief A stake pool signing key (Ed25519 signing key).
///
/// This class wraps a standard Ed25519 signing key. It is included for
/// compatibility with legacy keys and is completely valid for use as a stake
/// pool key. However, users are encouraged to use the extended key version for
/// new keys, which implements CIP-1853 for pool key derivation.
///
class ColdSigningKey
{
  private:
    ed25519::PrivateKey skey_;

  public:
    explicit ColdSigningKey(std::span<const uint8_t> key_bytes)
        : skey_{key_bytes}
    {
    }

    static constexpr auto kTypeStr = "StakePoolSigningKey_ed25519";
    static constexpr auto kDescStr = "Stake Pool Operator Signing Key";

    /// Factory method to create a new Ed25519 private key from a
    /// cryptographically secure random number generator.
    [[nodiscard]] static auto generate() -> ColdSigningKey
    {
        return ColdSigningKey(ed25519::PrivateKey::generate().bytes());
    }

    /// @brief Generate a message signature from the signing key.
    /// @param msg A span of bytes (uint8_t) representing the message to sign.
    [[nodiscard]] auto sign(std::span<const uint8_t> msg) const
        -> std::array<uint8_t, ed25519::ED25519_SIGNATURE_SIZE>
    {
        return this->skey_.sign(msg);
    }

    /// @brief Return the key as a byte vector.
    [[nodiscard]] constexpr auto bytes() const -> const ed25519::KeyByteArray&
    {
        return this->skey_.bytes();
    }

    /// @brief Derive the corresponding verification (public) key.
    /// @return The verification key object.
    [[nodiscard]] auto verificationKey() const -> ColdVerificationKey
    {
        return ColdVerificationKey(this->skey_.publicKey().bytes());
    }

    /// @brief Generate the pool ID as an array of bytes.
    /// @return Pool ID as an array of bytes.
    [[nodiscard]] auto poolId() -> std::array<uint8_t, STAKE_POOL_ID_SIZE>;

    /// @brief Convert to an extended Ed25519 key version.
    /// @return An StakePoolExtendedSigningKey object.
    [[nodiscard]] auto extend() const -> ExtendedColdSigningKey;

    /// @brief Serialize the key bytes as a Bech32 string.
    /// @return String representing the formatted key.
    [[nodiscard]] auto asBech32() const -> std::string;

    /// @brief Export the key to a file in the cardano node JSON format.
    /// @param fpath Path to the file to be (over)written.
    auto saveToFile(std::string_view fpath) const -> void;
};

/// @brief A CIP-1853 stake pool signing key (extended Ed25519 signing key).
class ExtendedColdSigningKey
{
  private:
    ed25519::ExtendedPrivateKey skey_;

  public:
    explicit ExtendedColdSigningKey(std::span<const uint8_t> key_bytes)
        : skey_{key_bytes}
    {
    }

    /// Factory method to create a new Ed25519 private key from a
    /// cryptographically secure random number generator.
    [[nodiscard]] static auto generate() -> ExtendedColdSigningKey
    {
        return ExtendedColdSigningKey(
            ed25519::ExtendedPrivateKey::generate().bytes()
        );
    }

    /// @brief Derive the stake pool key from a root key.
    /// Derive the stake pool signing key from a root HD wallet key
    /// following the derivation outlined in CIP-1852 and CIP-1853.
    /// @param root The root signing key.
    [[nodiscard]] static auto fromRootKey(const BIP32PrivateKey& root)
        -> ExtendedColdSigningKey;

    /// @brief Derive the stake pool key from a seed phrase.
    /// Derive the stake pool signing key from a BIP-39 complient mnemonic seed
    /// phrase following the algorithms outlined in CIP-3, CIP-1852, and
    /// CIP-1853.
    /// @param mn A valid mnemonic seed phrase.
    /// @return A valid stake pool signing key object.
    [[nodiscard]] static auto fromMnemonic(const cardano::Mnemonic& mn)
        -> ExtendedColdSigningKey;

    // @brief Generate a message signature from the signing key.
    /// @param msg A span of bytes (uint8_t) representing the message to sign.
    [[nodiscard]] auto sign(std::span<const uint8_t> msg) const
        -> std::array<uint8_t, ed25519::ED25519_SIGNATURE_SIZE>
    {
        return this->skey_.sign(msg);
    }

    /// @brief Derive the corresponding verification (public) key.
    /// @return The verification key object.
    [[nodiscard]] auto verificationKey() const -> ColdVerificationKey
    {
        return ColdVerificationKey(this->skey_.publicKey().bytes());
    }

    /// @brief Generate the pool ID as an array of bytes.
    /// @return Pool ID as an array of bytes.
    [[nodiscard]] auto poolId() -> std::array<uint8_t, STAKE_POOL_ID_SIZE>;

    /// @brief Return the key as a byte vector.
    [[nodiscard]] constexpr auto bytes() const
        -> const ed25519::ExtKeyByteArray&
    {
        return this->skey_.bytes();
    }

    /// @brief Serialize the key bytes as a Bech32 string.
    /// @return String representing the formatted key.
    [[nodiscard]] auto asBech32() const -> std::string;

    /// @brief Export the key to a file in the cardano node JSON format.
    /// @param fpath Path to the file to be (over)written.
    auto saveToFile(std::string_view fpath) const -> void;

    static constexpr auto kTypeStr =
        "StakePoolExtendedSigningKey_ed25519_bip32";
    static constexpr auto kDescStr = "Stake Pool Operator Signing Key";

};  // ExtendedColdSigningKey

// Placeholder class for Cert dev
class VrfVerificationKey
{
  private:
    ed25519::PublicKey vkey_{BASE16::decode(
        "9f52b990a53f091cc43712728ebd9d69b277bf5bc673024736961376ce3f7053"
    )};

  public:
    [[nodiscard]] auto bytes() const
        -> const std::array<uint8_t, ed25519::ED25519_KEY_SIZE>&
    {
        return this->vkey_.bytes();
    }

    [[nodiscard]] auto hash() const -> std::array<uint8_t, 32>
    {
        // Blake2b-SHA256 encode the CBOR encoded seed (32 byte result).
        const auto blake2b = Botan::HashFunction::create("Blake2b(256)");
        blake2b->update(vkey_.bytes().data(), vkey_.bytes().size());
        const auto hashed = blake2b->final();
        auto ret = std::array<uint8_t, 32>{};
        std::copy(hashed.begin(), hashed.end(), ret.begin());
        return ret;
    }
};

class VrfSigningKey
{
};

// Placeholder class for Op Cert dev
class KesVerificationKey
{
  private:
    ed25519::PublicKey vkey_{BASE16::decode(
        "b4f7f2d8506deebd885e41e9d510a5eb7cd4101275d1860fc243c869470b26e5"
    )};

  public:
    [[nodiscard]] auto bytes() const
        -> const std::array<uint8_t, ed25519::ED25519_KEY_SIZE>&
    {
        return this->vkey_.bytes();
    }
};

class KesSigningKey
{
};

/// @brief A node operational certificate issue counter.
class OperationalCertificateIssueCounter
{
  private:
    size_t count_ = 0;

  public:
    explicit OperationalCertificateIssueCounter(size_t count = 0)
        : count_{count}
    {
    }

    /// @brief Serialize the counter to CBOR with the pool vkey.
    /// @param vkey Stake pool verification key.
    /// @return The CBOR byte string as a byte vector.
    [[nodiscard]] auto serialize(const ColdVerificationKey& vkey) const
        -> std::vector<uint8_t>;

    /// @brief Export the counter to a file in the text envelope format.
    /// @param vkey Stake pool verification key.
    /// @param fpath Path to the file to be (over)written.
    auto saveToFile(std::string_view fpath, const ColdVerificationKey& vkey)
        const -> void;

    /// @brief Increment the counter.
    /// @return The count post operation.
    auto increment() -> size_t
    {
        this->count_++;
        return this->count_;
    }

    /// @brief Decrement the counter.
    /// @return The count post operation.
    auto decrement() -> size_t
    {
        this->count_--;
        return this->count_;
    }

    /// @brief Set the counter.
    /// @return The count post operation.
    auto setCount(size_t count) -> size_t
    {
        this->count_ = count;
        return this->count_;
    }

    /// @brief Accessor for the counter.
    /// @return The current counter value.
    [[nodiscard]] auto count() const -> size_t { return this->count_; }

};  // OperationalCertificateIssueCounter

/// @brief Manage creation and serialization of node operational certificates.
class [[nodiscard]] OperationalCertificateManager
{
  private:
    cardano::shelley::OperationalCert cert_;

  public:
    OperationalCertificateManager() = delete;

    /// @brief Construct a manager object from an operational certificate.
    /// @param cert An operational certificate struct.
    explicit OperationalCertificateManager(
        cardano::shelley::OperationalCert cert
    )
        : cert_(std::move(cert))
    {
    }

    /// @brief Provide a constant reference to the certificate struct.
    /// @return A constant reference to the wrapped certificate struct.
    [[nodiscard]] auto certificate() const
        -> const cardano::shelley::OperationalCert&
    {
        return cert_;
    }

    /// @brief Generate a complete cert with signature.
    /// @param hot_key The stake pool hot public key (KES key).
    /// @param counter The issue counter object.
    /// @param kes_period The current KES period (int).
    /// @param skey The stake pool cold signing key.
    /// @return A new OperationalCertificateManager object.
    [[nodiscard]] static auto generate(
        const KesVerificationKey& hot_key,
        const OperationalCertificateIssueCounter& counter,
        size_t kes_period,
        const ColdSigningKey& skey
    ) -> OperationalCertificateManager;
    // verify vkey matches the skey

    /// @brief Generate a complete cert with signature.
    /// @param hot_key The stake pool hot public key (KES key).
    /// @param counter The issue counter object.
    /// @param kes_period The current KES period (int).
    /// @param skey The stake pool cold signing key (extended key).
    /// @return A new OperationalCertificateManager object.
    [[nodiscard]] static auto generate(
        const KesVerificationKey& hot_key,
        const OperationalCertificateIssueCounter& counter,
        size_t kes_period,
        const ExtendedColdSigningKey& skey
    ) -> OperationalCertificateManager;

    /// @brief Generate a new cert without a signature.
    /// @param hot_key The stake pool hot public key (KES key).
    /// @param counter The issue counter object.
    /// @param kes_period The current KES period (int).
    /// @return A new OperationalCertificateManager object.
    [[nodiscard]] static auto generateUnsigned(
        const KesVerificationKey& hot_key,
        const OperationalCertificateIssueCounter& counter,
        size_t kes_period
    ) -> OperationalCertificateManager;

    /// @brief Add a signature to the certificate.
    /// @param skey Stake pool cold signing key.
    auto sign(const ColdSigningKey& skey) -> void;

    /// @brief Add a signature to the certificate.
    /// @param skey Stake pool cold signing key (extended key).
    auto sign(const ExtendedColdSigningKey& skey) -> void;

    /// @brief Verify the certificate signature.
    /// @param vkey Stake pool verification key.
    /// @return True if the cert contains a valid cold key signature.
    [[nodiscard]] auto verify(const ColdVerificationKey& vkey) const -> bool;

    /// @brief Serialize the certificate to CBOR.
    /// @return The CBOR byte string as a byte vector.
    [[nodiscard]] auto serialize() const -> std::vector<uint8_t>;

    /// @brief Serialize the certificate to CBOR with the pool vkey.
    /// @param vkey Stake pool verification key.
    /// @return The CBOR byte string as a byte vector.
    [[nodiscard]] auto serialize(const ColdVerificationKey& vkey) const
        -> std::vector<uint8_t>;

    /// @brief Export the certifiate to a file in the text envelope format.
    /// @param fpath Path to the file to be (over)written.
    /// @param vkey The public key corresponding to the cert signing key.
    auto saveToFile(std::string_view fpath, const ColdVerificationKey& vkey)
        const -> void;
};

/// @brief Manage creation and serialization of node registration certificates.
class RegistrationCertificateManager
{
  private:
    cardano::shelley::PoolRegistration cert_;

  public:
    RegistrationCertificateManager() = delete;

    /// @brief Construct a manager object from a registration certificate.
    /// @param cert The retirement certificate struct.
    explicit RegistrationCertificateManager(
        cardano::shelley::PoolRegistration cert
    )
        : cert_(std::move(cert))
    {
    }

    /// @brief Construct a new registration certificate.
    /// @param vkey The verification key of the pool.
    /// @param vrf_vkey The VRF verification key of the pool.
    /// @param pledge_lovelace The pledge amount in Lovelace.
    /// @param cost_lovelace The cost (fixed fee) per epoch in Lovelace.
    /// @param margin The margin (decimal unit interval) cost per epoch.
    /// @param reward_account The pool reward account address.
    RegistrationCertificateManager(
        const ColdVerificationKey& vkey,
        const VrfVerificationKey& vrf_vkey,
        uint64_t pledge_lovelace,
        uint64_t cost_lovelace,
        double margin,
        const RewardsAddress& reward_account
    );

    /// @brief Set the stake pool operator ID.
    /// @param vkey The verification key of the pool.
    auto setOperator(const ColdVerificationKey& vkey) -> void
    {
        this->cert_.pool_params.pool_operator = vkey.poolId();
    }

    /// @brief Set the stake pool operator ID.
    /// @param poolId The stake pool ID calculated from the Vkey hash.
    auto setOperator(const std::array<uint8_t, STAKE_POOL_ID_SIZE>& poolId)
        -> void
    {
        this->cert_.pool_params.pool_operator = poolId;
    }

    /// @brief Set the pool VRF key.
    /// @param vrf_vkey The stake pool VRF verification key.
    auto setVrfKey(const VrfVerificationKey& vrf_vkey) -> void
    {
        this->cert_.pool_params.vrf_keyhash = vrf_vkey.hash();
    }

    /// @brief Set the stake pool pledge.
    /// @param pledge_lovelace The pledge amount in Lovelace.
    auto setPledge(uint64_t pledge_lovelace) -> void
    {
        this->cert_.pool_params.pledge = pledge_lovelace;
    }

    /// @brief Set the stake pool cost.
    /// @param cost_lovelace The cost (fixed fee) per epoch in Lovelace.
    auto setCost(uint64_t cost_lovelace) -> void
    {
        this->cert_.pool_params.cost = cost_lovelace;
    }

    /// @brief Set the stake pool margin.
    /// @param margin The margin (decimal unit interval) cost per epoch.
    auto setMargin(double margin) -> void;

    /// @brief Set the stake pool reward account.
    /// @param reward_account The pool reward account address.
    auto setRewardAccount(const RewardsAddress& reward_account) -> void
    {
        this->cert_.pool_params.reward_account = reward_account.toBytes(true);
    }

    /// @brief Add a stake pool owner to the certificate.
    /// @param stake_addr The stake pool owner stake address.
    auto addOwner(const RewardsAddress& stake_addr) -> void;

    /// @brief Add a multi-host-name relay to the certificate.
    /// @param dns_name The DNS name of the relay.
    auto addRelay(std::string_view dns_name) -> void;

    /// @brief Add a single-host-name relay to the certificate.
    /// @param dns_name The DNS name of the relay.
    /// @param port The port of the relay.
    auto addRelay(std::string_view dns_name, uint16_t port) -> void;

    /// @brief Add a single-host-address relay to the certificate.
    /// @param ip The IPV4 address of the relay.
    /// @param port The relay port.
    auto addRelay(std::array<uint8_t, 4> ip, uint16_t port) -> void;

    /// @brief Add a single-host-address relay to the certificate.
    /// @param ip The IPV6 address of the relay.
    /// @param port The relay port.
    auto addRelay(std::array<uint8_t, 16> ip, uint16_t port) -> void;

    /// @brief Add a metadata URL to the certificate.
    /// @param metadata_url The metadata file URL.
    /// @param hash The metadata file hash.
    auto setMetadata(
        std::string_view metadata_url, std::span<const uint8_t> hash
    ) -> void;

    /// @brief Provide a constant reference to the certificate struct.
    /// @return A constant reference to the internal certificate struct.
    [[nodiscard]] auto certificate() const
        -> const cardano::shelley::PoolRegistration&
    {
        return cert_;
    }

    /// @brief Serialize the certificate to CBOR.
    /// @return The CBOR byte string as a byte vector.
    [[nodiscard]] auto serialize() const -> std::vector<uint8_t>
    {
        return cert_.serialize();
    }
};

/// @brief An interface for managing stake pool retirement certificates.
class DeregistrationCertificateManager
{
  private:
    cardano::shelley::PoolRetirement cert_;

  public:
    DeregistrationCertificateManager() = delete;

    /// @brief Construct a manager object from a retirement certificate.
    /// @param cert The retirement certificate struct.
    explicit DeregistrationCertificateManager(
        cardano::shelley::PoolRetirement cert
    )
        : cert_(std::move(cert))
    {
    }

    /// @brief Construst a retirement certificate.
    /// @param vkey The verification key of the retiring pool.
    /// @param epoch The epoch in which the pool will retire.
    DeregistrationCertificateManager(
        const ColdVerificationKey& vkey, uint64_t epoch
    )
    {
        this->cert_.pool_keyhash = vkey.poolId();
        this->cert_.epoch = epoch;
    }

    /// @brief Set the epoch in which the pool will retire.
    /// @param epoch The epoch in which the pool will retire.
    auto setEpoch(uint64_t epoch) -> void { this->cert_.epoch = epoch; }

    /// @brief Provide a constant reference to the certificate struct.
    /// @return A constant reference to the internal certificate struct.
    [[nodiscard]] auto certificate() const
        -> const cardano::shelley::PoolRetirement&
    {
        return cert_;
    }

    /// @brief Serialize the certificate to CBOR.
    /// @return The CBOR byte string as a byte vector.
    [[nodiscard]] auto serialize() const -> std::vector<uint8_t>
    {
        return cert_.serialize();
    }
};

}  // namespace stake_pool
}  // namespace cardano

#endif  // _CARDANO_STAKE_POOL_HPP_