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

#ifndef _CARDANO_VRF25519_HPP_
#define _CARDANO_VRF25519_HPP_

// Standard Library Headers
#include <array>
#include <cstdint>
#include <span>

// Public libcardano headers
#include <cardano/ed25519.hpp>
#include <cardano/secmem.hpp>

namespace cardano
{

static constexpr size_t VRF_SEED_SIZE = 32;
static constexpr size_t VRF_PUBLIC_KEY_SIZE = 32;
static constexpr size_t VRF_SECRET_KEY_SIZE = 64;
static constexpr size_t VRF_PROOF_SIZE = 80;
static constexpr size_t VRF_PROOF_HASH_SIZE = 64;

/// @brief Represent a VRF key as a secure byte array.
using VRFKeyByteArray = SecureByteArray<VRF_SECRET_KEY_SIZE>;

/// @brief Represents a VRF public key.
///
/// This class is a wrapper around the ed25519::PublicKey class.
/// As such, it inherits all of its methods. It adds the ability to
/// verify a VRF proof.
///
class VRFPublicKey : public ed25519::PublicKey
{
  public:
    /// @brief Construct a key object from a span of key bytes.
    /// @param pub A span of 32 bytes that will be copied into the object.
    explicit VRFPublicKey(std::span<const uint8_t, VRF_PUBLIC_KEY_SIZE> pub)
        : ed25519::PublicKey{pub}
    {
    }

    /// @brief Verify a VRF proof from the associated secret key.
    /// @param msg The message from which the proof and hash were derived.
    /// @param proof The proof to verify.
    /// @return True if the proof is valid, false otherwise.
    [[nodiscard]] auto verifyProof(
        std::span<const uint8_t> msg,
        std::span<const uint8_t> proof
    ) const -> bool;
};

/// @brief Represents a VRF secret key.
class VRFSecretKey
{
  private:
    /// Private key byte array (unencrypted)
    /// Stores the secret key and public key appended.
    // ExtKeyByteArray prv_;
    VRFKeyByteArray prv_{};

    /// Make the default constructor private so that it can only be used
    /// internally.
    VRFSecretKey() = default;

  public:
    /// @brief Construct a key object from a span of key bytes.
    /// @param prv A span of 64 bytes that will be copied into the object. The
    ///            bytes need to consist of the secret key (or seed) and the
    ///            public key concatenated.
    explicit VRFSecretKey(std::span<const uint8_t, VRF_SECRET_KEY_SIZE> prv);

    /// @brief Return a constant reference to the private key secure byte
    /// array.
    [[nodiscard]] constexpr auto bytes() const -> const VRFKeyByteArray&
    {
        return this->prv_;
    }

    /// Factory method to create a new VRF secret key from a
    /// cryptographically secure random number generator.
    [[nodiscard]] static auto generate() -> VRFSecretKey;

    /// Factory method to create a new VRF secret key from a seed.
    /// @param seed 32 byte seed.
    [[nodiscard]] static auto fromSeed(
        std::span<const uint8_t, VRF_SEED_SIZE> seed
    ) -> VRFSecretKey;

    /// @brief Ensure the key is a valid ed25519 key.
    [[nodiscard]] auto isValid() const -> bool;

    /// @brief Derive the public key paired with this private key.
    [[nodiscard]] auto publicKey() const -> VRFPublicKey;

    /// @brief Generate a message signature from the private key.
    /// @param msg A span of bytes (uint8_t) representing the message to sign.
    [[nodiscard]] auto sign(std::span<const uint8_t> msg
    ) const -> std::array<uint8_t, ed25519::SIGNATURE_SIZE>;

    /// @brief Construct a VRF proof from an initial message.
    /// @param msg A span of bytes (uint8_t) representing the message.
    /// @return A vector of bytes representing the VRF proof.
    [[nodiscard]] auto constructProof(std::span<const uint8_t> msg
    ) -> std::array<uint8_t, VRF_PROOF_SIZE>;

    /// @brief Convert a VRF proof to a VRF hash.
    /// @param proof The VRF proof.
    /// @return The VRF hash.
    [[nodiscard]] static auto proofToHash(
        std::span<const uint8_t, VRF_PROOF_SIZE> proof
    ) -> std::array<uint8_t, VRF_PROOF_HASH_SIZE>;

    /// @brief Compute the VRF hash of a message.
    /// @param msg The message to hash.
    /// @return The VRF hash.
    [[nodiscard]] auto hash(std::span<const uint8_t> msg
    ) -> std::array<uint8_t, VRF_PROOF_HASH_SIZE>;

    /// @brief Verify a VRF proof from the associated secret key.
    /// @param msg The message from which the proof and hash were derived.
    /// @param proof The proof to verify.
    /// @return True if the proof is valid, false otherwise.
    [[nodiscard]] auto verifyProof(
        std::span<const uint8_t> msg,
        std::span<const uint8_t, VRF_PROOF_SIZE> proof
    ) const -> bool;
};

}  // namespace cardano

#endif  // _CARDANO_VRF25519_HPP_