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

// Standard Library Headers
#include <array>
#include <stdexcept>
#include <string>
#include <vector>

// Public Cardano++ Headers 
#include <cardano/address.hpp>
#include <cardano/crypto.hpp>
#include <cardano/encodings.hpp>

// Private Cardano++ Headers
#include "cardano_crypto_interface.h"
#include "utils.hpp"

using namespace cardano;

// Define header bytes as constants so they can be changed if need be.
constexpr uint8_t NETWORK_TAG_MAINNET = 0b0001;
constexpr uint8_t NETWORK_TAG_TESTNET = 0b0000;
constexpr uint8_t SHELLY_ADDR_PAYMENTKEYHASH_STAKEKEYHASH = 0b0000;
constexpr uint8_t SHELLY_ADDR_SCRIPTHASH_STAKEKEYHASH = 0b0001;
constexpr uint8_t SHELLY_ADDR_PAYMENTKEYHASH_SCRIPTHASH = 0b0010;
constexpr uint8_t SHELLY_ADDR_SCRIPTHASH_SCRIPTHASH = 0b0011;
constexpr uint8_t SHELLY_ADDR_PAYMENTKEYHASH_POINTER = 0b0100;
constexpr uint8_t SHELLY_ADDR_SCRIPTHASH_POINTER = 0b0101;
constexpr uint8_t SHELLY_ADDR_PAYMENTKEYHASH = 0b0110;
constexpr uint8_t SHELLY_ADDR_SCRIPTHASH = 0b0111;
constexpr uint8_t STAKE_ADDR_STAKEKEYHASH = 0b1110;
constexpr uint8_t STAKE_ADDR_SCRIPTHASH = 0b1111;

BaseAddress::BaseAddress(NetworkID nid,
                         std::array<uint8_t, KEY_HASH_LENGTH> pmt_key_hash,
                         std::array<uint8_t, KEY_HASH_LENGTH> stake_key_hash) {
    this->pmt_key_hash_ = std::move(pmt_key_hash);
    this->stk_key_hash_ = std::move(stake_key_hash);
    this->header_byte_ = SHELLY_ADDR_PAYMENTKEYHASH_STAKEKEYHASH << 4;
    if (nid == NetworkID::mainnet)
        this->header_byte_ |= NETWORK_TAG_MAINNET;
    else
        this->header_byte_ |= NETWORK_TAG_TESTNET;
} // BaseAddress::BaseAddress

BaseAddress BaseAddress::fromKeys(NetworkID nid, BIP32PublicKey pmt_key,
                                  BIP32PublicKey stake_key) {
    std::array<uint8_t, KEY_HASH_LENGTH> pmt_key_hash;
    std::array<uint8_t, KEY_HASH_LENGTH> stake_key_hash;
    blake2b_224_hash(pmt_key.pkey.data(), pmt_key.pkey.size(),
                     pmt_key_hash.data());
    blake2b_224_hash(stake_key.pkey.data(), stake_key.pkey.size(),
                     stake_key_hash.data());
    return BaseAddress(nid, pmt_key_hash, stake_key_hash);
} // BaseAddress::fromKeys

BaseAddress BaseAddress::fromBech32(std::string addr_bech32) {
    auto addr = BaseAddress();
    auto [hrp, data] = cardano::BECH32::decode(addr_bech32);
    if (data.size() != KEY_HASH_LENGTH * 2 + 1)
        throw std::runtime_error("Invalid Bech32 data.");
    addr.header_byte_ = data[0];
    if (addr.header_byte_ >> 4 != SHELLY_ADDR_PAYMENTKEYHASH_STAKEKEYHASH)
        throw std::runtime_error("Invalid address header byte.");
    for (size_t i = 0; i < KEY_HASH_LENGTH; i++) {
        addr.pmt_key_hash_[i] = data[i + 1];
        addr.stk_key_hash_[i] = data[i + 1 + KEY_HASH_LENGTH];
    }
    return addr;
} // BaseAddress::fromBech32

std::string BaseAddress::toBech32(std::string hrp) const {
    auto bytes = concat_bytes(this->pmt_key_hash_, this->stk_key_hash_);
    bytes.insert(bytes.begin(), this->header_byte_);
    return BECH32::encode(hrp, bytes);
} // BaseAddress::toBech32

std::string BaseAddress::toBase16(bool include_header_byte) const {
    auto bytes = concat_bytes(this->pmt_key_hash_, this->stk_key_hash_);
    if (include_header_byte)
        bytes.insert(bytes.begin(), this->header_byte_);
    return BASE16::encode(bytes);
} // BaseAddress::toBase16

EnterpriseAddress::EnterpriseAddress(
    NetworkID nid, std::array<uint8_t, KEY_HASH_LENGTH> key_hash) {
    this->key_hash_ = std::move(key_hash);
    this->header_byte_ = SHELLY_ADDR_PAYMENTKEYHASH << 4;
    if (nid == NetworkID::mainnet)
        this->header_byte_ |= NETWORK_TAG_MAINNET;
    else
        this->header_byte_ |= NETWORK_TAG_TESTNET;
} // EnterpriseAddress::RewardsAddress

EnterpriseAddress EnterpriseAddress::fromKey(NetworkID nid,
                                             BIP32PublicKey key) {
    std::array<uint8_t, KEY_HASH_LENGTH> key_hash;
    blake2b_224_hash(key.pkey.data(), key.pkey.size(), key_hash.data());
    return EnterpriseAddress(nid, key_hash);
} // EnterpriseAddress::fromKeys

EnterpriseAddress EnterpriseAddress::fromBech32(std::string addr_bech32) {
    auto addr = EnterpriseAddress();
    auto [hrp, data] = cardano::BECH32::decode(addr_bech32);
    if (data.size() != KEY_HASH_LENGTH + 1)
        throw std::runtime_error("Invalid Bech32 data.");
    addr.header_byte_ = data[0];
    if (addr.header_byte_ >> 4 != SHELLY_ADDR_PAYMENTKEYHASH)
        throw std::runtime_error("Invalid address header byte.");
    for (size_t i = 0; i < KEY_HASH_LENGTH; i++)
        addr.key_hash_[i] = data[i + 1];
    return addr;
} // EnterpriseAddress::fromBech32

std::string EnterpriseAddress::toBech32(std::string hrp) const {
    std::vector<uint8_t> bytes;
    bytes.reserve(KEY_HASH_LENGTH + 1);
    bytes.insert(bytes.begin(), this->header_byte_);
    bytes.insert(bytes.begin() + 1, this->key_hash_.begin(),
                 this->key_hash_.end());
    return BECH32::encode(hrp, bytes);
} // EnterpriseAddress::toBech32

std::string EnterpriseAddress::toBase16(bool include_header_byte) const {
    if (include_header_byte) {
        std::vector<uint8_t> bytes;
        bytes.reserve(KEY_HASH_LENGTH + 1);
        bytes.insert(bytes.begin(), this->header_byte_);
        bytes.insert(bytes.begin() + 1, this->key_hash_.begin(),
                    this->key_hash_.end());
        return BASE16::encode(bytes);
    }
    return BASE16::encode(this->key_hash_);
} // EnterpriseAddress::toBase16

RewardsAddress::RewardsAddress(NetworkID nid,
                               std::array<uint8_t, KEY_HASH_LENGTH> key_hash) {
    this->key_hash_ = std::move(key_hash);
    this->header_byte_ = STAKE_ADDR_STAKEKEYHASH << 4;
    if (nid == NetworkID::mainnet)
        this->header_byte_ |= NETWORK_TAG_MAINNET;
    else
        this->header_byte_ |= NETWORK_TAG_TESTNET;
} // RewardsAddress::RewardsAddress

RewardsAddress RewardsAddress::fromKey(NetworkID nid,
                                       BIP32PublicKey stake_key) {
    std::array<uint8_t, KEY_HASH_LENGTH> stake_key_hash;
    blake2b_224_hash(stake_key.pkey.data(), stake_key.pkey.size(),
                     stake_key_hash.data());
    return RewardsAddress(nid, stake_key_hash);
} // RewardsAddress::fromKeys

RewardsAddress RewardsAddress::fromBech32(std::string addr_bech32) {
    auto addr = RewardsAddress();
    auto [hrp, data] = BECH32::decode(addr_bech32);
    if (data.size() != KEY_HASH_LENGTH + 1)
        throw std::runtime_error("Invalid Bech32 data.");
    addr.header_byte_ = data[0];
    if (addr.header_byte_ >> 4 != STAKE_ADDR_STAKEKEYHASH)
        throw std::runtime_error("Invalid address header byte.");
    for (size_t i = 0; i < KEY_HASH_LENGTH; i++)
        addr.key_hash_[i] = data[i + 1];
    return addr;
} // RewardsAddress::fromBech32

std::string RewardsAddress::toBech32(std::string hrp) const {
    std::vector<uint8_t> bytes;
    bytes.reserve(KEY_HASH_LENGTH + 1);
    bytes.insert(bytes.begin(), this->header_byte_);
    bytes.insert(bytes.begin() + 1, this->key_hash_.begin(),
                 this->key_hash_.end());
    return BECH32::encode(hrp, bytes);
} // RewardsAddress::toBech32

std::string RewardsAddress::toBase16(bool include_header_byte) const {
    if (include_header_byte) {
        std::vector<uint8_t> bytes;
        bytes.reserve(KEY_HASH_LENGTH + 1);
        bytes.insert(bytes.begin(), this->header_byte_);
        bytes.insert(bytes.begin() + 1, this->key_hash_.begin(),
                    this->key_hash_.end());
        return BASE16::encode(bytes);
    }
    return BASE16::encode(this->key_hash_);
} // RewardsAddress::toBase16

// // calculate the hash of the data using SHA3 digest then using Blake2b224
// fn sha3_then_blake2b224(data: &[u8]) -> [u8; 28] {
//     let mut sh3 = sha3::Sha3_256::new();
//     let mut sh3_out = [0; 32];
//     sh3.input(data.as_ref());
//     sh3.result(&mut sh3_out);

//     let mut b2b = Blake2b::new(28);
//     let mut out = [0; 28];
//     b2b.input(&sh3_out[..]);
//     b2b.result(&mut out);
//     out
// }

#include <span>

#include <botan/hash.h>
#include <botan/hex.h>

auto sha3_then_blake2b224(std::span<const uint8_t> data) -> std::array<uint8_t, 28> {
    // std::unique_ptr<Botan::HashFunction> sha3(Botan::HashFunction::create("SHA-3(256)"));
    auto sha3 = Botan::HashFunction::create("SHA-3(256)");
    sha3->update(data.data(), data.size());
    // auto sha3_out = sha3->final();

    // std::unique_ptr<Botan::HashFunction> blake2b(Botan::HashFunction::create("Blake2b(224)"));
    auto blake2b = Botan::HashFunction::create("Blake2b(224)");
    blake2b->update(sha3->final().data(), 32);
    auto blake2b_out = blake2b->final();

    std::array<uint8_t, 28> hashed_data;
    std::move(std::begin(blake2b_out), std::end(blake2b_out), hashed_data.begin());
    return hashed_data;
} // sha3_then_blake2b224