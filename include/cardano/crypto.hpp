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

#ifndef _CARDANO_CRYPTO_HPP_
#define _CARDANO_CRYPTO_HPP_

// Standard library headers
#include <array>
#include <cstdint>
#include <string>
#include <vector>

// Third-party library headers
#include <viper25519/ed25519.hpp>

// Public libcardano headers
#include <cardano/mnemonic.hpp>

namespace cardano
{

static constexpr uint32_t SECRET_KEY_SEED_SIZE = 32;
static constexpr uint32_t ENCRYPTED_KEY_SIZE = 64;
static constexpr uint32_t PUBLIC_KEY_SIZE = 32;
static constexpr uint32_t CHAIN_CODE_SIZE = 32;

static constexpr uint32_t HardenIndex(uint32_t index)
{
    if (index < 0x80000000) return index + 0x80000000;
    return index;
}

/// @brief  Key derivation mode.
enum class DerivationMode
{
    V1,
    V2
};

// Forward Declarations
class BIP32PublicKey;
class BIP32PrivateKey;
class BIP32PrivateKeyEncrypted;

/// Represent a BIP32 public key.
class BIP32PublicKey
{
  private:
    /// Public key (unencrypted).
    ed25519::PublicKey pub_;

    /// Chain code byte array (unencrypted).
    std::array<uint8_t, CHAIN_CODE_SIZE> cc_{};

    /// Make the default constructor private so that it can only be used
    /// internally.
    // BIP32PublicKey() = default;

  public:
    constexpr BIP32PublicKey(
        std::array<uint8_t, PUBLIC_KEY_SIZE> pub,
        std::array<uint8_t, CHAIN_CODE_SIZE> cc
    )
        : pub_{pub}, cc_{cc}
    {
    }

    /// Factory method, create public key from a bech32 string.
    /// @param xpub Bech32 encoded extended public key.
    static auto fromBech32(std::string xpub) -> BIP32PublicKey;

    /// Factory method, create public key from a base16 string.
    /// @param xpub Extended public key (includes chain code) hex string.
    static auto fromBase16(std::string_view xpub) -> BIP32PublicKey;

    /// Factory method, create public key from a base16 string.
    /// @param pub Public key hex string.
    /// @param cc Chain code hex string.
    static auto fromBase16(const std::string& pub, const std::string& cc)
        -> BIP32PublicKey;

    /// Return the public key as a byte vector.
    /// @param with_cc Flag to include the chain code with the key.
    [[nodiscard]] auto toBytes(bool with_cc = true) const
        -> std::vector<uint8_t>;

    /// Encode the public key as a bech32 string.
    /// @param hrp The bech32 human readable header.
    [[nodiscard]] auto toBech32(std::string_view hrp) const -> std::string;

    /// Encode the public key as a hex string.
    [[nodiscard]] auto toBase16() const -> std::string;

    /// Encode the public key as CBOR hex string.
    /// @param with_cc Flag to include the chain code with the key.
    [[nodiscard]] auto toCBOR(bool with_cc = true) const -> std::string;

    /// Derive a child (non-hardened) key from the public key.
    /// @param index Non-hardened BIP32 derivation index.
    /// @param derivation_mode V1 - Byron, V2 - Shelley
    [[nodiscard]] auto deriveChild(
        const uint32_t index,
        const DerivationMode derivation_mode = DerivationMode::V2
    ) const -> BIP32PublicKey;

};  // BIP32PublicKey

/// Represent a BIP32 private key.
class BIP32PrivateKey
{
  private:
    /// Private key (unencrypted).
    ed25519::ExtendedPrivateKey prv_;

    /// Chain code byte array (unencrypted).
    std::array<uint8_t, CHAIN_CODE_SIZE> cc_{};

    /// Make the default constructor private so that it can only be used
    /// internally.
    // BIP32PrivateKey() = default;

    /// Clear the contents of the private key array.
    // bool clear();

  public:
    BIP32PrivateKey(
        std::array<uint8_t, ENCRYPTED_KEY_SIZE> priv,
        std::array<uint8_t, CHAIN_CODE_SIZE> cc
    )
        : prv_{priv}, cc_{cc}
    {
    }

    /// Factory methods
    static auto fromBytes(std::span<const uint8_t> xpriv)
        -> BIP32PrivateKey;  // prv + cc
    static auto fromBech32(std::string_view bech32_str) -> BIP32PrivateKey;
    static auto fromMnemonic(const cardano::Mnemonic& mn) -> BIP32PrivateKey;
    static auto fromMnemonicByron(const cardano::Mnemonic& mn)
        -> BIP32PrivateKey;
    static auto fromMnemonic(
        const cardano::Mnemonic& mn, std::string_view passphrase
    ) -> BIP32PrivateKey;
    // static BIP32PrivateKey fromCBOR(std::string bech32); // TODO

    /// Return the private key as a byte vector.
    /// @param with_cc Flag to include the chain code with the key.
    [[nodiscard]] auto toBytes(bool with_cc = true) const
        -> std::vector<uint8_t>;

    /// Encode the private key as a bech32 string.
    /// @param hrp The bech32 human readable header.
    [[nodiscard]] auto toBech32(std::string_view hrp) const -> std::string;

    /// Encode the private key as a hex string.
    [[nodiscard]] auto toBase16() const -> std::string;

    /// Encode the private key as a CBOR hex string.
    /// @param with_cc Flag to include the chain code with the key.
    [[nodiscard]] auto toCBOR(bool with_cc = true) const -> std::string;

    /// Encode the private key, public key, and chain code all concatenated as
    /// a CBOR hex string.
    [[nodiscard]] auto toExtendedCBOR() const -> std::string;

    /// Derive the Ed25519 public key from the private key.
    [[nodiscard]] auto toPublic() const -> BIP32PublicKey;

    /// Derive a child key from the private key.
    /// @param index BIP32 derivation index.
    /// @param derivation_mode V1 - Byron, V2 - Shelley
    [[nodiscard]] auto deriveChild(
        const uint32_t index,
        const DerivationMode derivation_mode = DerivationMode::V2
    ) const -> BIP32PrivateKey;

    /// @brief Sign a message using the private key.
    /// @param msg The message to sign.
    /// @return The signature bytes.
    [[nodiscard]] auto sign(std::span<const uint8_t> msg) const
        -> std::array<uint8_t, ed25519::ED25519_SIGNATURE_SIZE>;

    /// Encrypt the private key bytes with a password using the same method as
    /// that used by the Daedalus wallet. This clears the unencrypted private
    /// key of the calling object.
    /// @param password The password to use for the encryption.
    auto encrypt(std::string_view password) -> BIP32PrivateKeyEncrypted;

};  // BIP32PrivateKey

/// Represent a BIP32 private key encrypted with a password.
class BIP32PrivateKeyEncrypted
{
  private:
    /// Private key byte array (encrypted)
    std::array<uint8_t, ENCRYPTED_KEY_SIZE> xprv_{};

    /// Chain code byte array (unencrypted).
    std::array<uint8_t, CHAIN_CODE_SIZE> cc_{};

    /// Make the default constructor private so that it can only be used
    /// internally.
    BIP32PrivateKeyEncrypted() = default;

  public:
    /// @brief Construct a new BIP32PrivateKeyEncrypted object.
    /// @param prv The encrypted private key bytes.
    /// @param cc The chain code bytes.
    constexpr BIP32PrivateKeyEncrypted(
        std::array<uint8_t, ENCRYPTED_KEY_SIZE> prv,
        std::array<uint8_t, CHAIN_CODE_SIZE> cc
    )
        : xprv_{prv}, cc_{cc}
    {
    }

    /// @brief Construct a new BIP32PrivateKeyEncrypted object.
    /// @param prv_enc The encrypted private key hex string.
    /// @param cc The chain code hex string.
    BIP32PrivateKeyEncrypted(const std::string& prv_enc, const std::string& cc);

    /// @brief Encode the encrypted private key as a hex string.
    /// @return The bech32 encoded private key.
    [[nodiscard]] auto toBase16() const -> std::string;

    /// Encode the private key (encrypted), public key (unencrypted), and chain
    /// code (unencrypted) all concatenated as a CBOR hex string.
    /// @param password Password to decrypt the private key for public key
    /// derivation.
    [[nodiscard]] auto toExtendedCBOR(std::string_view password) const
        -> std::string;

    /// @brief Derive a child key from the private key.
    /// @param index Derivation index.
    /// @param password Password to decrypt the private key.
    /// @param derivation_mode The key derivation mode. (V1 - Byron, V2 -
    /// Shelley).
    /// @return An encrypted BIP32 private key.
    [[nodiscard]] auto deriveChild(
        const uint32_t index,
        std::string_view password,
        const DerivationMode derivation_mode = DerivationMode::V2
    ) const -> BIP32PrivateKeyEncrypted;

    /// @brief Derive the Ed25519 public key from the private key.
    /// @param password The password to decrypt the private key.
    /// @return A BIP32 public key.
    [[nodiscard]] auto toPublic(std::string_view password) const
        -> BIP32PublicKey;

    /// @brief Decrypt the private key bytes with a password.
    /// @param password The password to use for the decryption.
    /// @return An unencrypted BIP32 private key.
    [[nodiscard]] auto decrypt(std::string_view password) const
        -> BIP32PrivateKey;

    /// @brief Sign a message using the private key.
    /// @param password Password to decrypt the private key for signature.
    /// @param msg The message to sign.
    /// @return The signature bytes.
    [[nodiscard]] auto sign(
        std::string_view password, std::span<const uint8_t> msg
    ) const -> std::array<uint8_t, ed25519::ED25519_SIGNATURE_SIZE>;

};  // BIP32PrivateKeyEncrypted

}  // namespace cardano

#endif  // _CARDANO_CRYPTO_HPP_