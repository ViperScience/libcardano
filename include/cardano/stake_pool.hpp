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
#include <memory>

// Third-party library headers
#include <viper25519/ed25519.hpp>

// Public libcardano headers
#include <cardano/crypto.hpp>

namespace cardano
{
namespace stake_pool
{

static constexpr uint32_t STAKE_POOL_KEY_SIZE = 32;
static constexpr uint32_t STAKE_POOL_ID_SIZE = 28;

// Forward Declarations
class ColdVerificationKey;
class ColdSigningKey;
class ColdCounter;
class ExtendedColdSigningKey;
class VrfVerificationKey;
class VrfSigningKey;
class KesVerificationKey;
class KesSigningKey;
class OperationalCertificate;

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

    /// @brief Export the key to a file in the cardano node JSON format.
    /// @param fpath Path to the file to be (over)written.
    auto saveToFile(std::string_view fpath) const -> void;

    /// @brief Return the key as a byte vector.
    [[nodiscard]] constexpr auto bytes() const
        -> const std::array<uint8_t, ed25519::ED25519_KEY_SIZE>&
    {
        return this->vkey_.bytes();
    }

    /// @brief Serialize the key bytes as a Bech32 string.
    /// @param hrp The human readable part of the string.
    /// @return String representing the formatted key.
    [[nodiscard]] auto asBech32() const -> std::string;

    /// @brief Generate the pool ID as an array of bytes.
    /// @return Pool ID as an array of bytes.
    [[nodiscard]] auto poolId() -> std::array<uint8_t, STAKE_POOL_ID_SIZE>;
};  // ColdVerificationKey

/// @brief A stake pool signing key (Ed25519 signing key).
/// This class wraps a standard Ed25519 signing key. It is included for
/// compatibility with legacy keys and is completely valid for use as a stake
/// pool key. However, users are encouraged to use the extended key version for
/// new keys, which implements CIP-1853 for pool key derivation.
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

    /// @brief Export the key to a file in the cardano node JSON format.
    /// @param fpath Path to the file to be (over)written.
    auto saveToFile(std::string_view fpath) const -> void;

    /// @brief Return the key as a byte vector.
    [[nodiscard]] constexpr auto bytes() const -> const ed25519::KeyByteArray&
    {
        return this->skey_.bytes();
    }

    /// @brief Serialize the key bytes as a Bech32 string.
    /// @return String representing the formatted key.
    [[nodiscard]] auto asBech32() const -> std::string;

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
};

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

    /// @brief Export the key to a file in the cardano node JSON format.
    /// @param fpath Path to the file to be (over)written.
    auto saveToFile(std::string_view fpath) const -> void;

    /// @brief Return the key as a byte vector.
    [[nodiscard]] constexpr auto bytes() const
        -> const ed25519::ExtKeyByteArray&
    {
        return this->skey_.bytes();
    }

    /// @brief Serialize the key bytes as a Bech32 string.
    /// @return String representing the formatted key.
    [[nodiscard]] auto asBech32() const -> std::string;

    /// @brief Derive the corresponding verification (public) key.
    /// @return The verification key object.
    [[nodiscard]] auto verificationKey() const -> ColdVerificationKey
    {
        return ColdVerificationKey(this->skey_.publicKey().bytes());
    }

    /// @brief Generate the pool ID as an array of bytes.
    /// @return Pool ID as an array of bytes.
    [[nodiscard]] auto poolId() -> std::array<uint8_t, STAKE_POOL_ID_SIZE>;

    static constexpr auto kTypeStr =
        "StakePoolExtendedSigningKey_ed25519_bip32";
    static constexpr auto kDescStr = "Stake Pool Operator Signing Key";

};  // StakePoolExtendedSigningKey

class OperationalCertificateIssueCounter
{
  private:
    std::shared_ptr<ColdVerificationKey> vkey_;
    size_t count_;

  public:
    // auto toCBOR();

    // saveToFile () < use text envelope

    // get/set count and key
};

class OperationalCertificate
{
};

}  // namespace stake_pool
}  // namespace cardano

#endif  // _CARDANO_STAKE_POOL_HPP_