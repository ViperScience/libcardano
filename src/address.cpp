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
#include <botan/pbkdf2.h>
#include <botan/pwdhash.h>

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
                                  BIP32PublicKey stake_key)
{
    auto pmt_key_bytes = pmt_key.toBytes(false);
    auto stake_key_bytes = stake_key.toBytes(false);
    auto pmt_key_hash = std::array<uint8_t, KEY_HASH_LENGTH>();
    auto stake_key_hash = std::array<uint8_t, KEY_HASH_LENGTH>();
    blake2b_224_hash(pmt_key_bytes.data(), pmt_key_bytes.size(),
                     pmt_key_hash.data());
    blake2b_224_hash(stake_key_bytes.data(), stake_key_bytes.size(),
                     stake_key_hash.data());
    return BaseAddress(nid, pmt_key_hash, stake_key_hash);
} // BaseAddress::fromKeys

auto BaseAddress::fromBech32(std::string addr_bech32) -> BaseAddress
{
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

auto BaseAddress::toBech32(std::string hrp) const -> std::string
{
    auto bytes = concat_bytes(this->pmt_key_hash_, this->stk_key_hash_);
    bytes.insert(bytes.begin(), this->header_byte_);
    return BECH32::encode(hrp, bytes);
} // BaseAddress::toBech32

auto BaseAddress::toBase16(bool include_header_byte) const -> std::string
{
    auto bytes = concat_bytes(this->pmt_key_hash_, this->stk_key_hash_);
    if (include_header_byte)
        bytes.insert(bytes.begin(), this->header_byte_);
    return BASE16::encode(bytes);
} // BaseAddress::toBase16

EnterpriseAddress::EnterpriseAddress(
    NetworkID nid, std::array<uint8_t, KEY_HASH_LENGTH> key_hash)
{
    this->key_hash_ = std::move(key_hash);
    this->header_byte_ = SHELLY_ADDR_PAYMENTKEYHASH << 4;
    if (nid == NetworkID::mainnet)
        this->header_byte_ |= NETWORK_TAG_MAINNET;
    else
        this->header_byte_ |= NETWORK_TAG_TESTNET;
} // EnterpriseAddress::RewardsAddress

auto EnterpriseAddress::fromKey(NetworkID nid, BIP32PublicKey key)
    -> EnterpriseAddress
{
    auto key_bytes = key.toBytes(false);
    auto key_hash = std::array<uint8_t, KEY_HASH_LENGTH>();
    blake2b_224_hash(key_bytes.data(), key_bytes.size(), key_hash.data());
    return EnterpriseAddress(nid, key_hash);
} // EnterpriseAddress::fromKeys

auto EnterpriseAddress::fromBech32(std::string addr_bech32) -> EnterpriseAddress
{
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

auto EnterpriseAddress::toBech32(std::string hrp) const -> std::string
{
    std::vector<uint8_t> bytes;
    bytes.reserve(KEY_HASH_LENGTH + 1);
    bytes.insert(bytes.begin(), this->header_byte_);
    bytes.insert(bytes.begin() + 1, this->key_hash_.begin(),
                 this->key_hash_.end());
    return BECH32::encode(hrp, bytes);
} // EnterpriseAddress::toBech32

auto EnterpriseAddress::toBase16(bool include_header_byte) const -> std::string
{
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
                               std::array<uint8_t, KEY_HASH_LENGTH> key_hash)
{
    this->key_hash_ = std::move(key_hash);
    this->header_byte_ = STAKE_ADDR_STAKEKEYHASH << 4;
    if (nid == NetworkID::mainnet)
        this->header_byte_ |= NETWORK_TAG_MAINNET;
    else
        this->header_byte_ |= NETWORK_TAG_TESTNET;
} // RewardsAddress::RewardsAddress

auto RewardsAddress::fromKey(NetworkID nid, BIP32PublicKey stake_key)
    -> RewardsAddress
{
    auto stake_key_bytes = stake_key.toBytes(false);
    auto stake_key_hash = std::array<uint8_t, KEY_HASH_LENGTH>();
    blake2b_224_hash(stake_key_bytes.data(), stake_key_bytes.size(),
                     stake_key_hash.data());
    return RewardsAddress(nid, stake_key_hash);
} // RewardsAddress::fromKeys

auto RewardsAddress::fromBech32(std::string addr_bech32) -> RewardsAddress
{
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

auto RewardsAddress::toBech32(std::string hrp) const -> std::string
{
    std::vector<uint8_t> bytes;
    bytes.reserve(KEY_HASH_LENGTH + 1);
    bytes.insert(bytes.begin(), this->header_byte_);
    bytes.insert(bytes.begin() + 1, this->key_hash_.begin(),
                 this->key_hash_.end());
    return BECH32::encode(hrp, bytes);
} // RewardsAddress::toBech32

auto RewardsAddress::toBase16(bool include_header_byte) const -> std::string
{
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

// The number of key derivation iterations when generating the key for 
// encrypting the address derivation path.
static constexpr size_t DP_KEY_ITERATIONS = 500;

// Size of key to be used for encrypting the address derivation path.
static constexpr size_t DP_KEY_SIZE = 32;

// Salt parameter used during generation of the derivation path encryption key.
// This value was hard coded in the legacy Byron code.
// String value: "address-hashing"
static constexpr auto DP_SALT = std::array<uint8_t, 15>{
    0x61, 0x64, 0x64, 0x72, 0x65, 0x73, 0x73, 0x2d, 0x68, 0x61, 0x73, 0x68,
    0x69, 0x6e, 0x67
};

// Nonce (hardcoded in legacy Bryon code) used for the address derivation path
// encryption cipher.
// String value: "serokellfore"
static constexpr auto DP_NONCE = std::array<uint8_t, 12>{
    0x73, 0x65, 0x72, 0x6f, 0x6b, 0x65, 0x6c, 0x6c, 0x66, 0x6f, 0x72, 0x65
};

/// Compute the CRC32 checksum of the provided bytes
static auto compute_crc32(std::span<const uint8_t> bytes) -> uint32_t
{
    auto crc32 = Botan::HashFunction::create("CRC32");
    crc32->update(bytes.data(), bytes.size());
    auto hash = crc32->final();
    uint32_t val = (hash[0] << 24) | (hash[1] << 16) | (hash[2] << 8) | hash[3];
    return val;
} // compute_crc32

constexpr auto ByronAddress::typeToUint(ByronAddress::Type t) -> uint8_t
{
    uint8_t type_val; 
    switch (t)
    {
    case ByronAddress::Type::pubkey:
        type_val = 0;
        break;
    case ByronAddress::Type::script:
        type_val = 1;
        break;
    case ByronAddress::Type::redeem:
        type_val = 1;
        break;
    default:
        throw std::invalid_argument("Not a valid Byron era address type.");
        break;
    }
    return type_val;
} // ByronAddress::typeToUint()

constexpr auto ByronAddress::uintToType(uint64_t v) -> ByronAddress::Type
{
    ByronAddress::Type type;
    switch (v)
    {
    case 0:
        type = ByronAddress::Type::pubkey;
        break;
    case 1:
        type = ByronAddress::Type::script;
        break;
    case 2:
        type = ByronAddress::Type::redeem;
        break;
    default:
        throw std::invalid_argument("Not a valid Byron era address type.");
        break;
    }
    return type;
} // ByronAddress::uintToType

auto ByronAddress::crc_check(std::span<const uint8_t> cbor, uint32_t crc)
    -> bool
{
    auto cbor_crc32 = compute_crc32(cbor);
    return (cbor_crc32 == crc);
} // check_byron_address_crc

auto ByronAddress::Attributes::fromKey(BIP32PublicKey xpub, 
                                       std::span<const uint32_t> path, 
                                       uint32_t magic)
    -> ByronAddress::Attributes
{
    // Create the passphrase for encrypting the derivation path.
    auto key = Botan::SecureVector<uint8_t>(DP_KEY_SIZE);
    auto xpub_bytes = xpub.toBytes(); // <- get vector of pub key and chain code
    auto fam = Botan::PasswordHashFamily::create("PBKDF2(SHA-512)");
    const auto pbkdf2 = fam->from_params(DP_KEY_ITERATIONS);
    pbkdf2->derive_key(key.data(), key.size(), (const char*)xpub_bytes.data(),
                       xpub_bytes.size(), DP_SALT.data(), DP_SALT.size());

    // CBOR encode the derivation path(s). The CBOR is what is encrypted.
    auto cbor = CBOR::Encoder::newIndefArray();
    for (auto idx : path)
        cbor.add((uint64_t)idx);
    cbor.endIndefArray();
    const auto bytes = cbor.serialize();

    // The encryption function needs a Botan::secure_vector as input.
    auto pt = Botan::secure_vector<uint8_t>(bytes.begin(), bytes.end());

    // Encrypt the derivation path (CBOR encoded) using a ChaCha20Poly1305
    // cipher.
    auto cm = Botan::Cipher_Mode::create("ChaCha20Poly1305", Botan::ENCRYPTION);
    cm->set_key(key);
    cm->start(DP_NONCE.data(), DP_NONCE.size());
    cm->finish(pt);

    // Set the object members
    auto attrs = ByronAddress::Attributes(std::vector(pt.begin(), pt.end()), magic);
    return attrs;
} // ByronAddress::Attributes::fromKey

/// Serialize the object to CBOR bytes.
auto ByronAddress::Attributes::toCBOR() const -> std::vector<uint8_t>
{
    auto cbor = CBOR::Encoder::newMap();
    if (this->ciphertext.size() > 0)
    {
        // The ciphertext is double CBOR encoded
        cbor.addToMap(1, CBOR::encode(this->ciphertext));
    }
    if (this->magic != 0)
    {
        // The protocol magic ID is also double CBOR encoded, first as an
        // unsigned int and then as a bytestring.
        cbor.addToMap(2, CBOR::encode((uint64_t)this->magic));
    }
    cbor.endMap();

    return cbor.serialize();
} // ByronAddress::Attributes::toCBOR

auto ByronAddress::fromCBOR(std::span<const uint8_t> addr_cbor) -> ByronAddress
{
    auto baddr = ByronAddress();
    
    try
    {
        auto addr_decoder = CBOR::Decoder::fromArrayData(addr_cbor);
        auto payload_bytes = addr_decoder.getTaggedCborBytes();
        auto payload_crc32 = addr_decoder.getUint32();

        // Check the CRC32 of the payload.
        if (!ByronAddress::crc_check(payload_bytes, payload_crc32))
            throw std::logic_error("");

        // Decode the address payload which is itself CBOR data
        auto payload_decoder = CBOR::Decoder::fromArrayData(payload_bytes);

        // Access the address root (hash of address data)
        auto root_bytes = payload_decoder.getBytes();
        std::copy(root_bytes.begin(), root_bytes.end(), baddr.root_.begin());

        // Access the address attributes (if present)
        payload_decoder.enterMap();
        auto map_size1 = payload_decoder.getMapSize();
        if (map_size1 > 0)
        {
            // Each of the attributes are themselves CBOR encoded.
            if (payload_decoder.keyInMap(1))
            {
                auto cbor_bytes1 = payload_decoder.getBytesFromMap(1);
                baddr.attrs_.ciphertext = CBOR::decodeBytes(cbor_bytes1);
            }
            if (payload_decoder.keyInMap(2))
            {
                auto cbor_bytes2 = payload_decoder.getBytesFromMap(2);
                baddr.attrs_.magic = CBOR::decodeUint32(cbor_bytes2);
            }
        }
        payload_decoder.exitMap();

        // Get the address type
        auto addr_type_val = payload_decoder.getUint64();
        baddr.type_ = ByronAddress::uintToType(addr_type_val);
    }
    catch(const std::exception& e)
    {
        throw std::invalid_argument(
            "Provided CBOR data is not a valid Byron-era address."
        );
    }

    return baddr;
} // ByronAddress::fromCBOR

auto ByronAddress::fromBase58(std::string addr) -> ByronAddress
{
    // Decode the Base58 address to get the CBOR data as a byte vector.
    auto addr_cbor = BASE58::decode(addr);
    return ByronAddress::fromCBOR(addr_cbor);
} // ByronAddress::fromBase58

auto ByronAddress::toCBOR() const -> std::vector<uint8_t>
{
    // Create the payload item, which constists of the root, attributes, and
    // address type in a three item array.
    auto payload_cbor = CBOR::Encoder::newArray();

    // Add the hash of the root key to the CBOR payload as the first element.
    payload_cbor.add(this->root_);

    // Add the address attributes as the second element in the payload. The 
    // attributes themselves are a CBOR structure.
    payload_cbor.addEncoded(this->attrs_.toCBOR());

    // Add the address type as the last element in the payload.
    payload_cbor.add((uint64_t)ByronAddress::typeToUint(this->type_));
    
    // Serialize the payload to a vector of bytes.
    payload_cbor.endArray();
    auto payload_vec = payload_cbor.serialize();

    // Finally, pack the tagged payload and CRC32 into a two element array.
    auto addr_cbor = CBOR::Encoder::newArray();
    addr_cbor.addTagged(24, payload_vec);
    addr_cbor.add((uint64_t)compute_crc32(payload_vec));
    addr_cbor.endArray();

    // CBOR encode the CBOR-serialized object with CRC.
    return addr_cbor.serialize();
} // ByronAddress::toCBOR

auto ByronAddress::toBase58() const -> std::string
{
    return BASE58::encode(this->toCBOR());
} // ByronAddress::toBase58

auto sha3_then_blake2b224(std::span<const uint8_t> data)
    -> std::array<uint8_t, 28>
{
    auto sha3 = Botan::HashFunction::create("SHA-3(256)");
    auto blake2b = Botan::HashFunction::create("Blake2b(224)");

    sha3->update(data.data(), data.size());   
    blake2b->update(sha3->final().data(), 32);
    auto blake2b_out = blake2b->final();

    std::array<uint8_t, 28> hashed_data;
    std::move(std::begin(blake2b_out), std::end(blake2b_out),
              hashed_data.begin());
    return hashed_data;
} // sha3_then_blake2b224

auto ByronAddress::fromRootKey(BIP32PrivateKey xprv,
                               std::span<const uint32_t> dpath,
                               uint32_t network_magic)
    -> ByronAddress
{
    const auto addr_type = ByronAddress::Type::pubkey;
    const auto addr_type_int = (uint64_t)ByronAddress::typeToUint(addr_type);

    // Get the root public key
    const auto xpub = xprv.toPublic();

    // Create the address attributes
    auto attrs = ByronAddress::Attributes::fromKey(xpub, dpath);

    // Derive the address public key from the root private key.
    if (dpath.size() != 2)
        throw std::invalid_argument("Invalid Byron address derivation path.");
    auto addr_xpub = xprv.deriveChild(dpath[0], 1)
                         .deriveChild(dpath[1], 1)
                         .toPublic();

    // CBOR encode the address spending data
    auto spending_cbor = CBOR::Encoder::newArray();
    spending_cbor.add(addr_type_int);
    spending_cbor.add(addr_xpub.toBytes());
    spending_cbor.endArray();

    // Create the address root
    auto root_cbor = CBOR::Encoder::newArray();
    root_cbor.add(addr_type_int);
    root_cbor.addEncoded(spending_cbor.serialize());
    root_cbor.addEncoded(attrs.toCBOR());
    root_cbor.endArray();

    // Serialize the address root to CBOR data.
    // Hash the address root
    auto root = sha3_then_blake2b224(root_cbor.serialize());    

    return ByronAddress(root, attrs, addr_type);
} // ByronAddress::fromKey
