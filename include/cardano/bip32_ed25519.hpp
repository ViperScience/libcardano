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

#ifndef _CARDANO_BIP32ED25519_HPP_
#define _CARDANO_BIP32ED25519_HPP_

// Standard library headers
#include <cstdint>
#include <span>
#include <string_view>

// Public libcardano headers
#include <cardano/mnemonic.hpp>
#include <cardano/secmem.hpp>

namespace cardano
{

/// @brief Root namespace for the BIP32-Ed25519 key classes.
namespace bip32_ed25519
{

/// ED25519 seed size.
inline constexpr size_t SEED_SIZE = 32;

/// ED25519 signature size.
inline constexpr size_t SIGNATURE_SIZE = 64;

/// ED25519 public key size.
inline constexpr size_t PUBLIC_KEY_SIZE = 32;

/// BIP32-ED25519 private key size (extended).
inline constexpr size_t KEY_SIZE = 64;

/// BIP32-ED25519 chain code size.
inline constexpr size_t CHAIN_CODE_SIZE = 32;

/// BIP32-Ed25519 extended public key size (key + cc).
inline constexpr size_t XPUBLIC_KEY_SIZE = PUBLIC_KEY_SIZE + CHAIN_CODE_SIZE;

/// BIP32-Ed25519 extended key size (key + cc).
inline constexpr size_t XKEY_SIZE = KEY_SIZE + CHAIN_CODE_SIZE;

using KeyByteArray = SecureByteArray<KEY_SIZE>;
using PubKeyByteArray = ByteArray<PUBLIC_KEY_SIZE>;
using ChainCodeByteArray = ByteArray<CHAIN_CODE_SIZE>;

// Forward Declarations
class PublicKey;
class PrivateKey;
class EncryptedPrivateKey;

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

/// @brief Represent a BIP32-Ed25519 prublic key.
/// @details The BIP32-Ed25519 public key is the same as a regular Ed25519
///   public key only it contains a chain code for non-hardened key derivation.
class PublicKey
{
  private:
    /// Public key byte array (unencrypted).
    PubKeyByteArray pub_{};

    /// Chain code byte array (unencrypted).
    ChainCodeByteArray cc_{};

  protected:
    /// Make the default constructor protected so that it can only be used
    /// internally. The key will be all zeros.
    PublicKey() = default;

  public:
    /// @brief Construct a key object from a span of key bytes.
    /// @param pub A span of bytes containing the public key and chain code that
    ///   will be copied into the object.
    explicit PublicKey(std::span<const uint8_t, XPUBLIC_KEY_SIZE> pub);

    /// @brief Construct a key object from bytes.
    /// @param pub The public key as a span of bytes.
    /// @param cc The chain code as a span of bytes.
    PublicKey(
        std::span<const uint8_t, PUBLIC_KEY_SIZE> pub,
        std::span<const uint8_t, CHAIN_CODE_SIZE> cc
    );

    /// @brief Return a constant reference to the public key byte array.
    [[nodiscard]] constexpr auto bytes() const -> const PubKeyByteArray&
    {
        return this->pub_;
    }

    /// @brief Return a byte array containing both the key and chain code.
    [[nodiscard]] auto xbytes() const -> ByteArray<XPUBLIC_KEY_SIZE>;

    /// @brief Verify a signature using the public key.
    /// @param msg A span of bytes (uint8_t) representing the original message.
    /// @param sig A span of 64 bytes (uint8_t) representing the signature.
    [[nodiscard]] auto verifySignature(
        std::span<const uint8_t> msg,
        std::span<const uint8_t, SIGNATURE_SIZE> sig
    ) const -> bool;

    /// @brief Derive a child (non-hardened) key from the public key.
    /// @param index Non-hardened BIP32 derivation index.
    /// @param derivation_mode V1 - Byron, V2 - Shelley
    [[nodiscard]] auto deriveChild(
        const uint32_t index,
        const DerivationMode derivation_mode = DerivationMode::V2
    ) const -> PublicKey;
};  // PublicKey

/// @brief Represent an BIP32-Ed25519 private key.
class PrivateKey
{
  private:
    /// Private key byte array (unencrypted)
    KeyByteArray prv_{};

    /// Chain code byte array (unencrypted).
    ChainCodeByteArray cc_{};

  protected:
    /// Make the default constructor protected so that it can only be used
    /// internally. The key will be all zeros.
    PrivateKey() = default;

  public:
    /// @brief Construct a key object from a span of key bytes.
    /// @param prv A span of bytes containing the key and chain code that will
    /// be moved into the object.
    /// @note The input may still contain a valid key after the move and must
    /// be wiped by the calling code.
    explicit PrivateKey(std::span<const uint8_t, XKEY_SIZE> prv);

    /// @brief Construct a key object from bytes.
    /// @param pub The private key as a span of bytes.
    /// @param cc The chain code as a span of bytes.
    PrivateKey(
        std::span<const uint8_t, KEY_SIZE> pub,
        std::span<const uint8_t, CHAIN_CODE_SIZE> cc
    );

    /// Factory method to create a new BIP32-Ed25519 private key from a
    /// cryptographically secure random number generator.
    [[nodiscard]] static auto generate() -> PrivateKey;

    /// @brief Create a new BIP32-Ed25519 private key from a root seed.
    /// @details The root seed is 32-bytes, i.e., a regular ed25519 private key.
    [[nodiscard]] static auto fromSeed(std::span<const uint8_t, SEED_SIZE> pub
    ) -> PrivateKey;

    /// @brief Generate a key from a mnemonic seed phrase.
    /// @param mn The mnemonic object.
    /// @return A new private key.
    static auto fromMnemonic(const Mnemonic& mn) -> PrivateKey;

    /// @brief Generate a key from a mnemonic seed phrase.
    /// @param mn The mnemonic object.
    /// @param passphrase An optional passphrase to combine with the seed.
    /// @return A new private key.
    static auto fromMnemonic(
        const cardano::Mnemonic& mn,
        std::string_view passphrase
    ) -> PrivateKey;

    /// @brief Generate a key from a mnemonic seed phrase.
    /// @param mn The mnemonic object.
    /// @return A new private key.
    /// @details Use the key generation method employed by Daedalus for
    /// generating Byron addresses.
    static auto fromMnemonicByron(const Mnemonic& mn) -> PrivateKey;

    /// @brief Return a constant reference to the private key secure byte
    /// array.
    [[nodiscard]] constexpr auto bytes() const -> const KeyByteArray&
    {
        return this->prv_;
    }

    /// @brief Return a byte array containing both the key and chain code.
    [[nodiscard]] auto xbytes() const -> SecureByteArray<XKEY_SIZE>;

    /// @brief Derive the public key paired with this private key.
    [[nodiscard]] auto publicKey() const -> PublicKey;

    /// @brief Generate a message signature from the private key.
    /// @param msg A span of bytes (uint8_t) representing the message to sign.
    [[nodiscard]] auto sign(std::span<const uint8_t> msg
    ) const -> ByteArray<SIGNATURE_SIZE>;

    /// @brief Derive a child key from the private key.
    /// @param index BIP32 derivation index.
    /// @param derivation_mode V1 - Byron, V2 - Shelley
    [[nodiscard]] auto deriveChild(
        const uint32_t index,
        const DerivationMode derivation_mode = DerivationMode::V2
    ) const -> PrivateKey;

    /// Encrypt the private key bytes with a password using the same method as
    /// that used by the Daedalus wallet. This clears the unencrypted private
    /// key of the calling object.
    /// @param password The password to use for the encryption.
    auto encrypt(std::string_view password) const -> EncryptedPrivateKey;
};  // PrivateKey

/// @brief Represent an encrypted BIP32-Ed25519 private key.
class EncryptedPrivateKey
{
  private:
    /// Private key byte array (encrypted)
    ByteArray<KEY_SIZE> prv_{};

    /// Chain code byte array (unencrypted).
    ChainCodeByteArray cc_{};

  public:
    /// @brief Construct a key object from a span of key bytes.
    /// @param prv A span of bytes containing the key (encrypted) and the chain
    /// code (unencrypted) that will be copied into the object.
    explicit EncryptedPrivateKey(std::span<const uint8_t, XKEY_SIZE> prv);

    /// @brief Construct a key object from bytes.
    /// @param pub The encrypted private key as a span of bytes.
    /// @param cc The chain code (unencrypted) as a span of bytes.
    EncryptedPrivateKey(
        std::span<const uint8_t, KEY_SIZE> pub,
        std::span<const uint8_t, CHAIN_CODE_SIZE> cc
    );

    /// @brief Decrypt the private key for usage.
    /// @param password The password used to encrypt the key.
    /// @return A decrypted private key object that may be used.
    [[nodiscard]] auto decrypt(std::string_view password) -> PrivateKey;
};

}  // namespace bip32_ed25519
}  // namespace cardano

#endif  // _CARDANO_BIP32ED25519_HPP_