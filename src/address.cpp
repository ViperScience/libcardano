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
#include <botan/cipher_mode.h>
#include <botan/hash.h>
#include <cbor.h>

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

// +-------------------------------------------------------------------------------+
// |                                                                               |
// |                        CBOR-Serialized Object with CRC                        |
// |                                                                               |
// +-------------------------------------------------------------------------------+
//                                         |
//                                         |
//                                         v
// +-------------------------------------------------------------------------------+
// |     Address Root    |     Address Attributes    |           AddrType          |
// |                     |                           |                             |
// |   Hash (224 bits)   |  Der. Path  + Stake + NM  |  PubKey | (Script) | Redeem |
// |                     |    (open for extension)   |     (open for extension)    |
// +-------------------------------------------------------------------------------+
//              |                 |
//              |                 |     +----------------------------------+
//              v                 |     |        Derivation Path           |
// +---------------------------+  |---->|                                  |
// | SHA3-256                  |  |     | ChaChaPoly⁴ AccountIx/AddressIx  |
// |   |> Blake2b 224          |  |     +----------------------------------+
// |   |> CBOR                 |  |
// |                           |  |
// |  -AddrType                |  |     +----------------------------------+
// |  -ASD  (~AddrType+PubKey) |  |     |       Stake Distribution         |
// |  -Address Attributes      |  |     |                                  |
// +---------------------------+  |---->|  BootstrapEra | (Single | Multi) |
//                                |     +----------------------------------+
//                                |
//                                |
//                                |     +----------------------------------+
//                                |     |          Network Magic           |
//                                |---->|                                  |
//                                      | Addr Discr: MainNet vs TestNet   |
//                                      +----------------------------------+
//
// CRC: Cyclic Redundancy Check; sort of checksum, a bit (pun intended) more reliable.
// ASD: Address Spending Data; Some data that are bound to an address. It’s an extensible object
//      with payload which identifies one of the three elements:
//  * A Public Key (Payload is thereby a PublicKey)
//  * A Script (Payload is thereby a script and its version)
//  * A Redeem Key (Payload is thereby a RedeemPublicKey)
// Derivation Path: Note that there’s no derivation path for Redeem nor Scripts addresses!
// ChaChaPoly: Authenticated Encryption with Associated Data (see RFC 7539. We use it as a way to
//             cipher the derivation path using a passphrase (the root public key).
//
// https://input-output-hk.github.io/cardano-wallet/concepts/byron-address-format

auto byron_address_type_to_byte(ByronAddressType type) -> uint8_t {
    uint32_t type_val; 
    switch (type)
    {
    case ByronAddressType::pubkey:
        type_val = 0;
        break;
    case ByronAddressType::script:
        type_val = 1;
        break;
    case ByronAddressType::redeem:
        type_val = 1;
        break;
    default:
        throw std::invalid_argument("Not a valid Byron era address type.");
        break;
    }
    return type_val;
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

/// Compute the CRC32 checksum of the provided bytes
auto compute_crc32(std::span<const uint8_t> bytes) -> uint32_t {
    auto crc32 = Botan::HashFunction::create("CRC32");
    crc32->update(bytes.data(), bytes.size());
    auto hash = crc32->final();
    uint32_t val = (hash[0] << 24) | (hash[1] << 16) | (hash[2] << 8) | hash[3];
    return val;
} // compute_crc32

auto check_byron_address_crc(std::span<const uint8_t> cbor, uint32_t crc) -> bool {
    auto cbor_crc32 = compute_crc32(cbor);
    return (cbor_crc32 == crc);
} // check_byron_address_crc

auto byron_address_attributes_to_libcbor_item(ByronAddressAttributes attrs) -> cbor_item_t* {
    auto adp = attrs.derivation_path_ciphertext;
    auto apm = attrs.protocol_magic;

    cbor_item_t *map_item;
    if ((adp.size() > 0) && (apm != 0))
        map_item = cbor_new_definite_map(2);
    else if ((adp.size() > 0) || (apm != 0))
        map_item = cbor_new_definite_map(1);
    else
        map_item = cbor_new_definite_map(0);

    if (adp.size() > 0) {
        // Encode the derivation path ciphertext as item 1.
        uint8_t dpath_cbor_buff[32];
        size_t dpath_cbor_len = cbor_serialize(
            cbor_build_bytestring(adp.data(), adp.size()), dpath_cbor_buff, 32);
        cbor_map_add(map_item, (struct cbor_pair) {
            .key = cbor_move(cbor_build_uint8(1)),
            .value = cbor_move(cbor_build_bytestring(dpath_cbor_buff, dpath_cbor_len))
        });
    }

    if (apm != 0) {
        // Encode the protocol magic number as item 2.
        uint8_t proto_cbor_buff[5];
        cbor_serialize(cbor_build_uint32(apm), proto_cbor_buff, 5);
        cbor_map_add(map_item, (struct cbor_pair) {
            .key = cbor_move(cbor_build_uint8(2)),
            .value = cbor_move(cbor_build_bytestring(proto_cbor_buff, 5))
        });
    }

    return map_item;
} // byron_address_attributes_to_libcbor_item

ByronAddressAttributes::ByronAddressAttributes(BIP32PublicKey xpub, std::span<const uint32_t> path, 
                                               uint32_t magic) {
    // Create the passphrase for encrypting the derivation path.
    const uint32_t num_iterations = 500;
    const size_t key_size = 32;
    std::vector<uint8_t> key;
    key.resize(key_size);
    const std::array<uint8_t, 15> salt = {
        0x61, 0x64, 0x64, 0x72, 0x65, 0x73, 0x73, 0x2d, 0x68, 0x61, 0x73, 0x68, 0x69, 0x6e, 0x67
    }; // as string -> address-hashing
    auto xpub_bytes = xpub.toBytes(); // <- get vector of pub key and chain code
    cryptonite_fastpbkdf2_hmac_sha512(xpub_bytes.data(), xpub_bytes.size(), salt.data(), salt.size(),
                                      num_iterations, key.data(), key_size);

    // CBOR encode the derivation path.
    // Let libcbor allocate all the memory it needs. Then manually free the buffer.
    cbor_item_t *path_cbor_item = cbor_new_indefinite_array();
    for (auto idx : path)
        cbor_array_push(path_cbor_item, cbor_move(cbor_build_uint32(idx)));
    size_t buff_size;
    uint8_t *path_cbor_buff;
    auto cbor_len = cbor_serialize_alloc(path_cbor_item, &path_cbor_buff, &buff_size);

    // Create the nonce (hardcoded in legacy Bryon code) used for the encryption cipher.
    std::string nonce_str = "serokellfore";
    Botan::secure_vector<uint8_t> iv(nonce_str.data(), nonce_str.data() + nonce_str.length());

    // Encrypt the derivation path (CBOR encoded) using a ChaCha20Poly1305 cipher.
    Botan::secure_vector<uint8_t> pt(path_cbor_buff, path_cbor_buff + cbor_len);
    auto enc = Botan::Cipher_Mode::create("ChaCha20Poly1305", Botan::ENCRYPTION);
    enc->set_key(key);
    enc->start(iv);
    enc->finish(pt);

    // Clean up memory
    free(path_cbor_buff);
    cbor_decref(&path_cbor_item);

    // Set the object members
    this->protocol_magic = magic;
    this->derivation_path_ciphertext = std::vector(pt.data(), pt.data() + pt.size());
} // ByronAddressAttributes::ByronAddressAttributes

auto ByronAddress::fromCBOR(std::span<const uint8_t> addr_cbor) -> ByronAddress {
    auto baddr = ByronAddress();

    struct cbor_load_result result;
    auto addr_item = cbor_load(addr_cbor.data(), addr_cbor.size(), &result);
    if (result.error.code != CBOR_ERR_NONE)
        throw std::invalid_argument("Provided CBOR data is not a valid bootstrap address.");
    // Also check if the array is the right size?

    // Get the tagged CBOR metadata (check for the CBOR tag)
    auto tag = cbor_tag_value(cbor_array_get(addr_item, 0));
    if (tag != 24)
        throw std::invalid_argument("Provided CBOR data is not a valid bootstrap address.");
    auto tagged_item = cbor_tag_item(cbor_array_get(addr_item, 0));
    auto payload = cbor_bytestring_handle(tagged_item);
    auto payload_len = cbor_bytestring_length(tagged_item);

    // Check the CRC32 of the payload.
    auto crc32 = cbor_get_uint32(cbor_array_get(addr_item, 1));    
    if (!check_byron_address_crc({payload, payload_len}, crc32))
        throw std::invalid_argument("Provided CBOR data is not a valid bootstrap address.");

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
                // Key = 1: ciphered derivation path (double CBOR encoded)
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
    baddr.type_ = uint_to_byron_address_type(addr_type_val);

    // Clean up memory 
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
    // CBOR encode the address attributes
    cbor_item_t *attrs_item = byron_address_attributes_to_libcbor_item(this->attrs_);

    // Create the payload item, which constists of the root, attributes, and address type in a
    // three item array.
    cbor_item_t * payload_item = cbor_new_definite_array(3);
    cbor_array_set(payload_item, 0,
                   cbor_move(cbor_build_bytestring(this->root_.data(), this->root_.size())));
    cbor_array_set(payload_item, 1, attrs_item);
    cbor_array_set(payload_item, 2,
                   cbor_move(cbor_build_uint8(byron_address_type_to_byte(this->type_))));

    // Serialize the payload to CBOR
    size_t buffer_size;
    uint8_t *payload_buffer;
    size_t payload_cbor_len = cbor_serialize_alloc(payload_item, &payload_buffer, &buffer_size);

    // Tag the payload CBOR data as encoded CBOR data (tag 24)
    cbor_item_t *cbor_tag = cbor_new_tag(24);
    auto temp = cbor_build_bytestring(payload_buffer, payload_cbor_len);
    cbor_tag_set_item(cbor_tag, temp);

    // Finally, pack the tagged payload and CRC32 into a two element array.
    auto addr_item = cbor_new_definite_array(2);
    cbor_array_set(addr_item, 0, cbor_move(cbor_tag));

    // Compute the CRC32 of the CBOR serialized address payload
    std::vector<uint8_t> payload_vec(payload_buffer, payload_buffer + payload_cbor_len);
    cbor_array_set(addr_item, 1, cbor_build_uint32(compute_crc32(payload_vec)) );

    // CBOR encode the CBOR-Serialized Object with CRC.
    uint8_t *addr_buffer;
    size_t addr_cbor_len = cbor_serialize_alloc(addr_item, &addr_buffer, &buffer_size);
    std::vector<uint8_t> cbor(addr_buffer, addr_buffer + addr_cbor_len);

    // Clean up memory
    free(payload_buffer);
    free(addr_buffer);
    cbor_decref(&payload_item);
    cbor_decref(&addr_item);

    return cbor;
} // ByronAddress::toBase58

auto ByronAddress::toBase58() const -> std::string {
    auto cbor = this->toCBOR();
    return BASE58::encode(cbor);
} // ByronAddress::toBase58

auto sha3_then_blake2b224(std::span<const uint8_t> data) -> std::array<uint8_t, 28> {
    auto sha3 = Botan::HashFunction::create("SHA-3(256)");
    auto blake2b = Botan::HashFunction::create("Blake2b(224)");

    sha3->update(data.data(), data.size());   
    blake2b->update(sha3->final().data(), 32);
    auto blake2b_out = blake2b->final();

    std::array<uint8_t, 28> hashed_data;
    std::move(std::begin(blake2b_out), std::end(blake2b_out), hashed_data.begin());
    return hashed_data;
} // sha3_then_blake2b224

auto ByronAddress::fromRootKey(BIP32PrivateKey xprv, std::span<const uint32_t> dpath, 
                               uint32_t network_magic) -> ByronAddress {
    const auto addr_type = ByronAddressType::pubkey;
    const auto addr_type_byte = byron_address_type_to_byte(addr_type);

    // Get the root public key
    const auto xpub = xprv.toPublic();

    // Create the address attributes
    auto attrs = ByronAddressAttributes(xpub, dpath);

    // CBOR encode the address attributes
    cbor_item_t *attrs_item = byron_address_attributes_to_libcbor_item(attrs);

    // Derive the address public key from the root private key.
    if (dpath.size() != 2)
        throw std::invalid_argument("Invalid Byron address derivation path.");
    auto addr_xpub = xprv.deriveChild(dpath[0], 1).deriveChild(dpath[1], 1).toPublic();

    // CBOR encode the address spending data
    const auto xpb = addr_xpub.toBytes();
    cbor_item_t * spending_item = cbor_new_definite_array(2);
    cbor_array_set(spending_item, 0, cbor_move(cbor_build_uint8(addr_type_byte)));
    cbor_array_set(spending_item, 1, cbor_move(cbor_build_bytestring(xpb.data(), xpb.size())));

    // Create the address root
    cbor_item_t * root_item = cbor_new_definite_array(3);
    cbor_array_set(root_item, 0, cbor_move(cbor_build_uint8(addr_type_byte)));
    cbor_array_set(root_item, 1, cbor_move(spending_item));
    cbor_array_set(root_item, 2, cbor_move(attrs_item));
    
    // Serialize the address root to CBOR data.
    // Let libcbor allocate all the memory it needs. Then manually free the buffer.
    size_t buffer_size;
    uint8_t *buffer;
    auto cbor_len = cbor_serialize_alloc(root_item, &buffer, &buffer_size);
    std::vector<uint8_t> root_cbor(buffer, buffer + cbor_len);
    free(buffer);
    cbor_decref(&root_item);

    // Hash the address root
    auto root = sha3_then_blake2b224(root_cbor);    

    return ByronAddress(root, attrs, addr_type);
} // ByronAddress::fromKey
