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

#ifndef _CARDANO_ED25519_HPP_
#define _CARDANO_ED25519_HPP_

// Standard library headers
#include <cstdint>
#include <span>

// Public libcardano headers
#include <cardano/secmem.hpp>

namespace cardano
{

/// @brief Root namespace for the Ed25519 classes.
namespace ed25519
{

/// ED25519 secret key size.
inline constexpr size_t KEY_SIZE = 32;

/// ED25519 signature size.
inline constexpr size_t SIGNATURE_SIZE = 64;

/// ED25519 public key size.
inline constexpr size_t PUBLIC_KEY_SIZE = 32;

using KeyByteArray = SecureByteArray<KEY_SIZE>;
using PubKeyByteArray = ByteArray<PUBLIC_KEY_SIZE>;

/// @brief Represent an Ed25519 prublic key.
class PublicKey
{
  private:
    /// Public key byte array (unencrypted).
    PubKeyByteArray pub_{};

  public:
    /// @brief Construct a key object from a span of key bytes.
    /// @param pub An array of 32 bytes that will be copied into the object.
    explicit PublicKey(std::span<const uint8_t, PUBLIC_KEY_SIZE> pub);

    /// @brief Return a constant reference to the public key byte array.
    [[nodiscard]] constexpr auto bytes() const -> const PubKeyByteArray&
    {
        return this->pub_;
    }

    /// @brief Verify a signature using the public key.
    /// @param msg A span of bytes (uint8_t) representing the original message.
    /// @param sig A span of 64 bytes (uint8_t) representing the signature.
    [[nodiscard]] auto verifySignature(
        std::span<const uint8_t> msg,
        std::span<const uint8_t, SIGNATURE_SIZE> sig
    ) const -> bool;
};  // PublicKey

/// @brief Represent an Ed25519 private key.
/// @note This class is a wrapper around the libsodium ed25519 implementation.
class PrivateKey
{
  private:
    /// Private key byte array (unencrypted)
    KeyByteArray prv_{};

  protected:
    /// Make the default constructor protected so that it can only be used
    /// internally. The key will be all zeros.
    PrivateKey() = default;

  public:
    /// @brief Construct a key object from a span of key bytes.
    /// @param prv A span of 32 bytes that will be moved into the object.
    /// @note The input may still contain a valid key after the move and must
    /// be wiped by the calling code.
    explicit PrivateKey(std::span<const uint8_t, KEY_SIZE> prv);

    /// @brief Return a constant reference to the private key secure byte
    /// array.
    [[nodiscard]] constexpr auto bytes() const -> const KeyByteArray&
    {
        return this->prv_;
    }

    /// Factory method to create a new Ed25519 private key from a
    /// cryptographically secure random number generator.
    [[nodiscard]] static auto generate() -> PrivateKey;

    /// @brief Derive the public key paired with this private key.
    [[nodiscard]] auto publicKey() const -> PublicKey;

    /// @brief Generate a message signature from the private key.
    /// @param msg A span of bytes (uint8_t) representing the message to sign.
    [[nodiscard]] auto sign(std::span<const uint8_t> msg
    ) const -> ByteArray<SIGNATURE_SIZE>;
};  // PrivateKey

}  // namespace ed25519
}  // namespace cardano

#endif  // _CARDANO_ED25519_HPP_