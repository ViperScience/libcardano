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

#ifndef _CARDANO_ADDRESS_HPP_
#define _CARDANO_ADDRESS_HPP_

// Standard library headers
#include <array>
#include <cstdint>
#include <span>
#include <string>
#include <vector>

// Third-party library headers

// Public libcardano headers
#include <cardano/bip32_ed25519.hpp>

/// @brief	The root namespace for all Cardano functions and types.
namespace cardano
{

/// @brief The length of a key hash used for an address.
static constexpr size_t KEY_HASH_LENGTH = 28;

/// @brief An enum representing the network ID of a Cardano address.
enum class NetworkID
{
    mainnet,
    testnet
};

/// @brief A Cardano base address object.
class BaseAddress
{
  private:
    uint8_t header_byte_ = 0;
    std::array<uint8_t, KEY_HASH_LENGTH> pmt_key_hash_{};
    std::array<uint8_t, KEY_HASH_LENGTH> stk_key_hash_{};

    // Make the default constructor private to prevent use outside of static
    // factory methods.
    BaseAddress() = default;

  public:
    /// @brief Construct a new BaseAddress object.
    /// @param nid The network ID.
    /// @param pmt_key_hash The payment key hash.
    /// @param stake_key_hash The stake key hash.
    /// @note The payment and stake key hashes must be of length
    /// KEY_HASH_LENGTH.
    BaseAddress(
        NetworkID nid,
        std::array<uint8_t, KEY_HASH_LENGTH> pmt_key_hash,
        std::array<uint8_t, KEY_HASH_LENGTH> stake_key_hash
    );

    /// @brief Create a new BaseAddress object from the public keys.
    /// @param nid The network ID.
    /// @param pmt_key The payment key.
    /// @param stake_key The stake key.
    /// @return The created BaseAddress object.
    static auto
    fromKeys(NetworkID nid, const bip32_ed25519::PublicKey& pmt_key, const bip32_ed25519::PublicKey& stake_key)
        -> BaseAddress;

    /// @brief Create a new BaseAddress object from a bech32 address.
    static auto fromBech32(const std::string_view addr) -> BaseAddress;

    /// @brief Return the address as a byte array.
    /// @param with_header Whether to include the header byte in the output.
    /// @return The address as a byte array.
    [[nodiscard]] auto toBytes(bool with_header = false) const
        -> std::vector<uint8_t>;

    /// @brief Encode the address as a base16 string.
    /// @param with_header Whether to include the header byte in the output.
    /// @return The base16 encoded address.
    [[nodiscard]] auto toBase16(bool with_header = false) const -> std::string;

    /// @brief Encode the address as a bech32 string.
    /// @param hrp The human-readable part of the bech32 string.
    /// @return The bech32 encoded address.
    [[nodiscard]] auto toBech32(const std::string_view hrp) const -> std::string;
};  // BaseAddress

/// @brief A Cardano enterprise address object.
class EnterpriseAddress
{
  private:
    std::array<uint8_t, KEY_HASH_LENGTH> key_hash_{};
    uint8_t header_byte_ = 0;

    // Make the default constructor private to prevent use outside of static
    // factory methods.
    EnterpriseAddress() = default;

  public:
    /// @brief Construct a new EnterpriseAddress object.
    /// @param nid The network ID enum.
    /// @param key_hash The key hash.
    EnterpriseAddress(
        NetworkID nid,
        std::array<uint8_t, KEY_HASH_LENGTH> key_hash
    );

    /// @brief Factory method to create an EnterpriseAddress object from a key.
    /// @param nid The network ID enum.
    /// @param pub_key The public key.
    /// @return The created EnterpriseAddress object.
    static auto fromKey(NetworkID nid, const bip32_ed25519::PublicKey& pub_key)
        -> EnterpriseAddress;

    /// @brief Factory method to create an EnterpriseAddress object from a
    /// bech32 address.
    /// @param addr The bech32 address.
    /// @return The created EnterpriseAddress object.
    static auto fromBech32(const std::string_view addr) -> EnterpriseAddress;

    /// @brief Return the address as a byte array.
    /// @param with_header Whether to include the header byte in the output.
    /// @return The address as a byte array.
    [[nodiscard]] auto toBytes(bool with_header = false) const
        -> std::vector<uint8_t>;

    /// @brief Encode the address as a base16 string.
    /// @param with_header Whether to include the header byte in the output.
    /// @return The base16 encoded address.
    [[nodiscard]] auto toBase16(bool with_header = false) const -> std::string;

    /// @brief Encode the address as a bech32 string.
    /// @param hrp The human-readable part of the bech32 string.
    /// @return The bech32 encoded address.
    [[nodiscard]] auto toBech32(const std::string_view addr) const -> std::string;
};  // EnterpriseAddress

class PointerAddress
{
};

/// @brief A Cardano rewards address object.
class RewardsAddress
{
  private:
    std::array<uint8_t, KEY_HASH_LENGTH> key_hash_{};
    uint8_t header_byte_ = 0;

    // Make the default constructor private to prevent use outside of static
    // factory methods.
    RewardsAddress() = default;

  public:
    /// @brief Construct a new RewardsAddress object.
    /// @param nid The network ID enum.
    /// @param key_hash The key hash.
    RewardsAddress(
        NetworkID nid,
        std::array<uint8_t, KEY_HASH_LENGTH> key_hash
    );

    /// @brief Factory method to create a RewardsAddress object from a key.
    /// @param nid The network ID enum.
    /// @param stake_key The stake key.
    /// @return The created RewardsAddress object.
    static auto fromKey(NetworkID nid, const bip32_ed25519::PublicKey& stake_key)
        -> RewardsAddress;

    /// @brief Factory method to create a RewardsAddress object from a bech32
    /// address.
    /// @param addr The bech32 address.
    /// @return The created RewardsAddress object.
    static auto fromBech32(const std::string_view addr) -> RewardsAddress;

    /// @brief Return the address as a byte array.
    /// @param with_header Whether to include the header byte in the output.
    /// @return The address as a byte array.
    [[nodiscard]] auto toBytes(bool with_header = false) const
        -> std::vector<uint8_t>;

    /// @brief Encode the address as a base16 string.
    /// @param with_header Whether to include the header byte in the output.
    /// @return The base16 encoded address.
    [[nodiscard]] auto toBase16(bool with_header = false) const -> std::string;

    /// @brief Encode the address as a bech32 string.
    /// @param hrp The human-readable part of the bech32 string.
    /// @return The bech32 encoded address.
    [[nodiscard]] auto toBech32(const std::string_view hrp) const -> std::string;
};  // RewardsAddress

/// @brief A Cardano Byron era address object.
class ByronAddress
{
  public:
    /// @brief The attributes of a ByronAddress.
    struct Attributes
    {
        /// Address derivation path ciphertext.
        std::vector<uint8_t> ciphertext;

        /// Protocol magic (if not 0, then its a testnet).
        uint32_t magic = 0;

        /// Default Constructor
        /// The default constructor is needed for the default ByronAddress
        /// constructor to exist.
        Attributes() = default;

        /// Constructor
        /// Take ownership of the chipertext vector (move it into the object).
        Attributes(std::vector<uint8_t> bytes, uint32_t network_magic)
            : ciphertext{std::move(bytes)}, magic{network_magic}
        {
        }

        /// Factory method to create an attributes object from a root public key
        /// and unencrypted path. The key is used to encrypt the address
        /// derivation path and the resulting ciphertext stored in the object.
        static auto fromKey(
            const bip32_ed25519::PublicKey& xpub,
            std::span<const uint32_t> path,
            uint32_t magic = 0
        ) -> Attributes;
    };

    /// Address type enum contained within the ByronAddress class scope.
    enum class Type
    {
        pubkey,
        script,
        redeem
    };

    /// Constructor - take ownership of the inputs.
    ByronAddress(
        std::array<uint8_t, KEY_HASH_LENGTH> root,
        ByronAddress::Attributes attrs,
        ByronAddress::Type type
    )
        : root_{root}, attrs_{std::move(attrs)}, type_{type}
    {
    }

    /// @brief Factory method to create a ByronAddress object from a root key.
    /// @param xprv The root private key.
    /// @param derivation_path The address derivation path.
    /// @param network_magic The network magic (if not 0, then its a testnet).
    /// @return The created ByronAddress object.
    static auto fromRootKey(
        const bip32_ed25519::PrivateKey& xprv,
        std::span<const uint32_t> derivation_path,
        uint32_t network_magic = 0
    ) -> ByronAddress;

    /// @brief Factory method to create a ByronAddress object from a CBOR
    /// encoded address.
    /// @param cbor_data The CBOR encoded address.
    /// @return The created ByronAddress object.
    static auto fromCBOR(std::span<const uint8_t> cbor_data) -> ByronAddress;

    /// Factory method to create a ByronAddress object from a base58 encoded
    /// address.
    /// @param addr The base58 encoded address.
    /// @return The created ByronAddress object.
    static auto fromBase58(std::string addr) -> ByronAddress;

    /// Serialize to vector of CBOR bytes.
    [[nodiscard]] auto toCBOR() const -> std::vector<uint8_t>;

    /// Serialize to Base58 encoded string.
    [[nodiscard]] auto toBase58() const -> std::string;

  private:
    std::array<uint8_t, KEY_HASH_LENGTH> root_{};
    ByronAddress::Attributes attrs_{};
    ByronAddress::Type type_ = ByronAddress::Type::pubkey;

    /// Convert an ByronAddress::Type enum to unsigned int for CBOR encoding.
    static constexpr auto typeToUint(ByronAddress::Type t) -> uint8_t;

    /// Convert a unsigned int to ByronAddress::Type enum for CBOR decoding.
    static constexpr auto uintToType(uint64_t v) -> ByronAddress::Type;

    /// Compute the CRC of the provided CBOR and verify it with the given CRC.
    static auto crc_check(std::span<const uint8_t> cbor, uint32_t crc) -> bool;

    /// Make the default constructor private so it can only be used by the
    /// static factory methods.
    ByronAddress() = default;
};  // ByronAddress

}  // namespace cardano

#endif