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

#include <array>
#include <cstdint>
#include <span>
#include <string>
#include <vector>

#include <cardano/crypto.hpp>

namespace cardano {

constexpr size_t KEY_HASH_LENGTH = 28;

enum class NetworkID { mainnet, testnet };

class BaseAddress {
  private:
    uint8_t header_byte_;
    std::array<uint8_t, KEY_HASH_LENGTH> pmt_key_hash_{};
    std::array<uint8_t, KEY_HASH_LENGTH> stk_key_hash_{};

    // Make the default constructor private so it can only be used by the static factory methods.
    BaseAddress() = default;

  public:
    BaseAddress(NetworkID nid,
                std::array<uint8_t, KEY_HASH_LENGTH> pmt_key_hash,
                std::array<uint8_t, KEY_HASH_LENGTH> stake_key_hash);

    static BaseAddress fromKeys(NetworkID nid, BIP32PublicKey pmt_key,
                                BIP32PublicKey stake_key);
    static BaseAddress fromBech32(std::string addr);
    std::string toBech32(std::string hrp) const;
    std::string toBase16(bool with_header = false) const;
}; // BaseAddress

class EnterpriseAddress {
  private:
    std::array<uint8_t, KEY_HASH_LENGTH> key_hash_{};
    uint8_t header_byte_;

    // Make the default constructor private so it can only be used by the static factory methods.
    EnterpriseAddress() = default;

  public:
    EnterpriseAddress(NetworkID nid, std::array<uint8_t, KEY_HASH_LENGTH> key_hash);
    static EnterpriseAddress fromKey(NetworkID nid, BIP32PublicKey pub_key);
    static EnterpriseAddress fromBech32(std::string addr);
    std::string toBech32(std::string hrp) const;
    std::string toBase16(bool with_header = false) const;
}; // EnterpriseAddress

class PointerAddress {};

class RewardsAddress {
  private:
    std::array<uint8_t, KEY_HASH_LENGTH> key_hash_{};
    uint8_t header_byte_;

    // Make the default constructor private so it can only be used by the static factory methods.
    RewardsAddress() = default;

  public:
    RewardsAddress(NetworkID nid, std::array<uint8_t, KEY_HASH_LENGTH> key_hash);
    static RewardsAddress fromKey(NetworkID nid, BIP32PublicKey stake_key);
    static RewardsAddress fromBech32(std::string addr);
    std::string toBech32(std::string hrp) const;
    std::string toBase16(bool with_header = false) const;
};

enum class ByronAddressType { pubkey, script, redeem };

struct ByronAddressAttributes {
    std::vector<uint8_t> derivation_path_ciphertext;
    uint32_t protocol_magic = 0;
    ByronAddressAttributes() = default;
    ByronAddressAttributes(std::vector<uint8_t> path, uint32_t magic)
        : derivation_path_ciphertext{std::move(path)}, protocol_magic{magic} {}
    ByronAddressAttributes(BIP32PublicKey xprv, std::span<const uint32_t> path, uint32_t magic = 0);
};

class ByronAddress {
  private:
    std::array<uint8_t, KEY_HASH_LENGTH> root_;
    ByronAddressAttributes attrs_;
    ByronAddressType type_;

    // Make the default constructor private so it can only be used by the static factory methods.
    ByronAddress() = default;

  public:
    ByronAddress(std::array<uint8_t, KEY_HASH_LENGTH> root, ByronAddressAttributes attrs,
                 ByronAddressType type)
        : root_{std::move(root)}, attrs_{std::move(attrs)}, type_{type} {}
    static ByronAddress fromRootKey(BIP32PrivateKey xprv, std::span<const uint32_t> derivation_path, uint32_t network_magic = 0);
    static ByronAddress fromCBOR(std::span<const uint8_t> cbor_data);
    static ByronAddress fromBase58(std::string addr);
    std::vector<uint8_t> toCBOR() const;
    std::string toBase58() const;
};

} // namespace cardano

#endif