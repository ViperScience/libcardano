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
#include <algorithm>
#include <stdexcept>

// Third Party Library Headers
#include "cbor.h"

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

//////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////// Byron Era Addresses ///////////////////////////////////
//////////////////////////////////////////////////////////////////////////////////////////



//
// Add a function here that breaks down an address CBOR using the C lib
//
#include <ostream>
#include <iostream>

auto byron_address_type_to_byte(ByronAddressType type) -> uint8_t {
    uint8_t byte; 
    switch (type)
    {
    case ByronAddressType::pubkey:
        byte = 0;
        break;
    case ByronAddressType::script:
        byte = 1;
        break;
    case ByronAddressType::redeem:
        byte = 1;
        break;
    default:
        throw std::invalid_argument("Not a valid Byron era address type.");
        break;
    }
    return byte;
} // byron_address_type_to_byte

auto uint_to_byron_address_type(uint32_t addr_type_val) -> ByronAddressType {
    ByronAddressType type;
    switch (addr_type_val)
    {
    case 0:
        type = ByronAddressType::pubkey;
        break;
    case 1:
        type = ByronAddressType::script;
        break;
    case 2:
        type = ByronAddressType::redeem;
        break;
    default:
        throw std::invalid_argument("Not a valid Byron era address type.");
        break;
    }
    return type;
} // uint_to_byron_address_type

auto ByronAddress::fromCBOR(std::span<const uint8_t> addr_cbor) -> ByronAddress {
    auto baddr = ByronAddress();

    struct cbor_load_result result;
    auto addr_item = cbor_load(addr_cbor.data(), addr_cbor.size(), &result);
    // check errors....
    // check array is the right size...

    // Grab the CRC32 of the payload
    auto crc32 = cbor_get_uint32(cbor_array_get(addr_item, 1));    
    // maybe use this to check later...

    // Get the tagged CBOR metadata (check for the CBOR tag)
    auto tag = cbor_tag_value(cbor_array_get(addr_item, 0));
    if (tag != 24)
        throw std::invalid_argument("Provided CBOR data is not a valid bootstrap address.");
    auto tagged_item = cbor_tag_item(cbor_array_get(addr_item, 0));
    auto payload = cbor_bytestring_handle(tagged_item);
    auto payload_len = cbor_bytestring_length(tagged_item);

    // Decode the address payload which is itself CBOR data
    auto payload_item = cbor_load(payload, payload_len, &result);

    // Access the address root (hash of address data)
    auto root_ptr = std::span(cbor_bytestring_handle(cbor_array_get(payload_item, 0)), 28);
    std::move(root_ptr.begin(), root_ptr.end(), baddr.root_.begin());

    // Access the address attributes (if present)
    auto map_size = cbor_map_size(cbor_array_get(payload_item, 1));
    if (map_size > 0) {
        auto attrs_map = cbor_map_handle(cbor_array_get(payload_item, 1));
        for (size_t i = 0; i < map_size; ++i) {
            // Each of the attributes are themselves CBOR encoded.
            auto attr_cbor_len = cbor_bytestring_length(attrs_map[i].value);
            auto attr_cbor = cbor_bytestring_handle(attrs_map[i].value);
            auto attr_item = cbor_load(attr_cbor, attr_cbor_len, &result);

            if (cbor_get_uint32(attrs_map[i].key) == 1) {
                // Key = 1: ciphered derivation path (CBOR encoded)
                auto n_bytes = cbor_bytestring_length(attr_item);
                auto bytes_ptr = cbor_bytestring_handle(attr_item);
                baddr.attrs_.derivation_path_ciphertext = std::vector<uint8_t>(
                    bytes_ptr, bytes_ptr + n_bytes
                );
            } else if (cbor_get_uint32(attrs_map[i].key) == 2) {
                // Key = 2: network tag (CBOR encoded)
                baddr.attrs_.protocol_magic = cbor_get_uint32(attr_item);
            }

            cbor_decref(&attr_item);
        }
    }

    // Get the address type
    auto addr_type_val = cbor_get_uint32(cbor_array_get(payload_item, 2));
    baddr.type_ =  uint_to_byron_address_type(addr_type_val);

    // memory clean up 
    cbor_decref(&addr_item);
    cbor_decref(&payload_item);

    return baddr;
} // ByronAddress::fromCBOR

auto ByronAddress::fromBase58(std::string addr) -> ByronAddress {
    // Decode the Base58 address to get the CBOR data as a byte vector. 
    auto addr_cbor = BASE58::decode(addr);

    return ByronAddress::fromCBOR(addr_cbor);
} // ByronAddress::fromBase58

auto ByronAddress::toCBOR() const -> std::vector<uint8_t> {
    std::vector<uint8_t> cbor;

    cbor_item_t *d = cbor_build_bytestring(this->root_.data(), this->root_.size());

    return cbor;
} // ByronAddress::toBase58

auto ByronAddress::toBase58() const -> std::string {
    return std::string("");
} // ByronAddress::toBase58

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

// #include <span>

// #include <botan/hash.h>
// #include <botan/hex.h>

// auto sha3_then_blake2b224(std::span<const uint8_t> data) -> std::array<uint8_t, 28> {
//     // std::unique_ptr<Botan::HashFunction> sha3(Botan::HashFunction::create("SHA-3(256)"));
//     auto sha3 = Botan::HashFunction::create("SHA-3(256)");
//     sha3->update(data.data(), data.size());
//     // auto sha3_out = sha3->final();

//     // std::unique_ptr<Botan::HashFunction> blake2b(Botan::HashFunction::create("Blake2b(224)"));
//     auto blake2b = Botan::HashFunction::create("Blake2b(224)");
//     blake2b->update(sha3->final().data(), 32);
//     auto blake2b_out = blake2b->final();

//     std::array<uint8_t, 28> hashed_data;
//     std::move(std::begin(blake2b_out), std::end(blake2b_out), hashed_data.begin());
//     return hashed_data;
// } // sha3_then_blake2b224

// #include <botan/stream_cipher.h>
// #include <botan/auto_rng.h>
// #include <botan/hex.h>
// #include <iostream>

// auto make_derivation_path_ciphertext(std::vector<uint32_t> path, BIP32PublicKey root_key) -> std::array<uint8_t, 28> {
//     std::unique_ptr<Botan::StreamCipher> cipher(Botan::StreamCipher::create("ChaCha(20)"));

// }

// // pub fn new(xpub: &XPub, attrs: Attributes) -> Self {
// //         ExtendedAddr {
// //             addr: hash_spending_data(AddrType::ATPubKey, xpub, &attrs),
// //             attributes: attrs,
// //             addr_type: AddrType::ATPubKey,
// //         }
// //     }

// ByronAddress::ByronAddress(BIP32PublicKey xpub, attrs) {

// }

// ByronAddress::ByronAddress(ByronAddressType type, std::vector<uint32_t> path, BIP32PrivateKey root_key) {

//     // BYRON_DERIVATION_PATH =
//     //     [ * uint32 ]

//     // BYRON_DERIVATION_PATH_CIPHERTEXT = ; Obtained by encrypting a serialized derivation path
//     //     bytes .size 28
//     auto der_path_enc = make_derivation_path_ciphertext(path, root_key.toPublic());

//     // BYRON_ADDRESS_ATTRIBUTES =
//     //     { 1 : <<bytes .cbor BYRON_DERIVATION_PATH_CIPHERTEXT>>  ; Double CBOR-encoded ChaCha20/Poly1305 encrypted digest, see CIP for details.
//     //     , 2 : <<uint32>>                             ; CBOR-encoded network discriminant
//     //     }
    

//     // BYRON_ADDRESS_TYPE =
//     //        0  ; Public key
//     //     // 2  ; Redemption
//     // Byron address type as a byte to be concatenated with other data.
//     uint8_t type_byte;
//     switch(type) {
//         case ByronAddressType::script :
//             type_byte = 1;
//             break;
//         case ByronAddressType::redeem :
//             type_byte = 2;
//             break;
//         case ByronAddressType::pubkey :
//         default :
//             type_byte = 0;
//     }

//     // BYRON_ADDRESS_SPENDING_DATA =
//     //     ( 0, bytes .size 64 ) ; Ed25519 Public key | Associated BIP-32 chain code
//     //     //
//     //     ( 2, bytes .size 32 ) ; Ed25519 Public key
//     auto spending_data
    

//     std::array<uint8_t, 28> root_hash;
//     std::vector<uint8_t> attributes;

//     // Convert the payload to CBOR

//     // CRC32 of the payload

//     // BYRON_ADDRESS_ROOT =
//     //     ( BYRON_ADDRESS_TYPE
//     //     , BYRON_ADDRESS_SPENDING_DATA
//     //     , BYRON_ADDRESS_ATTRIBUTES
//     //     )
//     auto root = concat_bytes(spending_data, attributes);
//     root.insert(root.begin(), type_byte);

//     // BYRON_ADDRESS_PAYLOAD =
//     //     ( bytes .size 28            ; blake2b_224(sha3_256(BYRON_ADDRESS_ROOT)) digest
//     //     , BYRON_ADDRESS_ATTRIBUTES
//     //     , BYRON_ADDRESS_TYPE
//     //     )
//     auto root_hash = sha3_then_blake2b224(root);
//     auto payload = concat_bytes(root_hash, attributes);
//     payload.push_back(type_byte);

//     // BYRON_ADDRESS =
//     //     ( #6.24(<<BYRON_ADDRESS_PAYLOAD>>)
//     //     , uint32 ; crc32 of the CBOR serialized address payload
//     //     )

// }
