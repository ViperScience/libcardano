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
#include <cardano/crypto.hpp>

namespace cardano
{

static constexpr size_t KEY_HASH_LENGTH = 28;

enum class NetworkID
{
    mainnet,
    testnet
};

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
    BaseAddress(
        NetworkID nid,
        std::array<uint8_t, KEY_HASH_LENGTH> pmt_key_hash,
        std::array<uint8_t, KEY_HASH_LENGTH> stake_key_hash
    );

    static auto fromKeys(
        NetworkID nid, BIP32PublicKey pmt_key, BIP32PublicKey stake_key
    ) -> BaseAddress;
    static auto fromBech32(std::string addr) -> BaseAddress;
    [[nodiscard]] auto toBytes(bool with_header = false) const
        -> std::vector<uint8_t>;
    [[nodiscard]] auto toBase16(bool with_header = false) const -> std::string;
    [[nodiscard]] auto toBech32(std::string hrp) const -> std::string;
};  // BaseAddress

class EnterpriseAddress
{
  private:
    std::array<uint8_t, KEY_HASH_LENGTH> key_hash_{};
    uint8_t header_byte_ = 0;

    // Make the default constructor private to prevent use outside of static
    // factory methods.
    EnterpriseAddress() = default;

  public:
    EnterpriseAddress(
        NetworkID nid, std::array<uint8_t, KEY_HASH_LENGTH> key_hash
    );
    static auto fromKey(NetworkID nid, BIP32PublicKey pub_key)
        -> EnterpriseAddress;
    static auto fromBech32(std::string addr) -> EnterpriseAddress;
    [[nodiscard]] auto toBytes(bool with_header = false) const
        -> std::vector<uint8_t>;
    [[nodiscard]] auto toBase16(bool with_header = false) const -> std::string;
    [[nodiscard]] auto toBech32(std::string hrp) const -> std::string;
};  // EnterpriseAddress

class PointerAddress
{
};

class RewardsAddress
{
  private:
    std::array<uint8_t, KEY_HASH_LENGTH> key_hash_{};
    uint8_t header_byte_ = 0;

    // Make the default constructor private to prevent use outside of static
    // factory methods.
    RewardsAddress() = default;

  public:
    RewardsAddress(
        NetworkID nid, std::array<uint8_t, KEY_HASH_LENGTH> key_hash
    );
    static auto fromKey(NetworkID nid, BIP32PublicKey stake_key)
        -> RewardsAddress;
    static auto fromBech32(std::string addr) -> RewardsAddress;
    [[nodiscard]] auto toBytes(bool with_header = false) const
        -> std::vector<uint8_t>;
    [[nodiscard]] auto toBase16(bool with_header = false) const -> std::string;
    [[nodiscard]] auto toBech32(std::string hrp) const -> std::string;
};

class ByronAddress
{
  public:
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
        Attributes(std::vector<uint8_t> bytes, uint32_t magic)
            : ciphertext{std::move(bytes)}, magic{magic}
        {
        }

        /// Factory method to create an attributes object from a root public key
        /// and unencrypted path. The key is used to encrypt the address
        /// derivation path and the resulting ciphertext stored in the object.
        static auto fromKey(
            BIP32PublicKey xpub,
            std::span<const uint32_t> path,
            uint32_t magic = 0
        ) -> Attributes;

        /// Serialize the object to CBOR bytes.
        [[nodiscard]] auto toCBOR() const -> std::vector<uint8_t>;
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

    /// Facotry methods
    static auto fromRootKey(
        BIP32PrivateKey xprv,
        std::span<const uint32_t> derivation_path,
        uint32_t network_magic = 0
    ) -> ByronAddress;
    static auto fromCBOR(std::span<const uint8_t> cbor_data) -> ByronAddress;
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
};

}  // namespace cardano

#endif