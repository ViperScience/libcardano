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

// Standard library headers
#include <algorithm>
#include <stdexcept>

// Third-party library headers
#include <botan/cipher_mode.h>
#include <botan/hash.h>
#include <botan/pbkdf2.h>
#include <botan/pwdhash.h>
#include <cppbor/cppbor.h>
#include <cppbor/cppbor_parse.h>

// Public libcardano headers
#include <cardano/address.hpp>
#include <cardano/crypto.hpp>
#include <cardano/encodings.hpp>

// Private libcardano source
#include "utils.hpp"
#include "debug_utils.hpp"

using namespace cardano;

// Define header bytes as constants so they can be changed if need be.
constexpr uint8_t NETWORK_TAG_MAINNET = 0b0001;
constexpr uint8_t NETWORK_TAG_TESTNET = 0b0000;
constexpr uint8_t SHELLY_ADDR_PAYMENTKEYHASH_STAKEKEYHASH = 0b0000;
// constexpr uint8_t SHELLY_ADDR_SCRIPTHASH_STAKEKEYHASH = 0b0001;
// constexpr uint8_t SHELLY_ADDR_PAYMENTKEYHASH_SCRIPTHASH = 0b0010;
// constexpr uint8_t SHELLY_ADDR_SCRIPTHASH_SCRIPTHASH = 0b0011;
// constexpr uint8_t SHELLY_ADDR_PAYMENTKEYHASH_POINTER = 0b0100;
// constexpr uint8_t SHELLY_ADDR_SCRIPTHASH_POINTER = 0b0101;
constexpr uint8_t SHELLY_ADDR_PAYMENTKEYHASH = 0b0110;
// constexpr uint8_t SHELLY_ADDR_SCRIPTHASH = 0b0111;
constexpr uint8_t STAKE_ADDR_STAKEKEYHASH = 0b1110;
// constexpr uint8_t STAKE_ADDR_SCRIPTHASH = 0b1111;

BaseAddress::BaseAddress(
    NetworkID nid,
    std::array<uint8_t, KEY_HASH_LENGTH> pmt_key_hash,
    std::array<uint8_t, KEY_HASH_LENGTH> stake_key_hash
)
{
    this->pmt_key_hash_ = std::move(pmt_key_hash);
    this->stk_key_hash_ = std::move(stake_key_hash);
    this->header_byte_ = SHELLY_ADDR_PAYMENTKEYHASH_STAKEKEYHASH << 4;
    if (nid == NetworkID::mainnet)
        this->header_byte_ |= NETWORK_TAG_MAINNET;
    else
        this->header_byte_ |= NETWORK_TAG_TESTNET;
}  // BaseAddress::BaseAddress

BaseAddress BaseAddress::fromKeys(
    NetworkID nid, BIP32PublicKey pmt_key, BIP32PublicKey stake_key
)
{
    const auto blake2b = Botan::HashFunction::create("Blake2b(224)");

    const auto pmt_key_bytes = pmt_key.toBytes(false);
    blake2b->update(pmt_key_bytes.data(), pmt_key_bytes.size());
    const auto pmt_key_hash = blake2b->final();

    // Put the hash in a std::array of bytes for the address constructor.
    auto pmt_key_hash_array = std::array<uint8_t, KEY_HASH_LENGTH>();
    std::copy_n(
        pmt_key_hash.begin(), KEY_HASH_LENGTH, pmt_key_hash_array.begin()
    );

    const auto stake_key_bytes = stake_key.toBytes(false);
    blake2b->update(stake_key_bytes.data(), stake_key_bytes.size());
    const auto stake_key_hash = blake2b->final();

    // Put the hash in a std::array of bytes for the address constructor.
    auto stake_key_hash_array = std::array<uint8_t, KEY_HASH_LENGTH>();
    std::copy_n(
        stake_key_hash.begin(), KEY_HASH_LENGTH, stake_key_hash_array.begin()
    );

    return BaseAddress(nid, pmt_key_hash_array, stake_key_hash_array);
}  // BaseAddress::fromKeys

auto BaseAddress::fromBech32(std::string addr_bech32) -> BaseAddress
{
    auto addr = BaseAddress();
    auto [hrp, data] = cardano::BECH32::decode(addr_bech32);
    if (data.size() != KEY_HASH_LENGTH * 2 + 1)
        throw std::runtime_error("Invalid Bech32 data.");
    addr.header_byte_ = data[0];
    if (addr.header_byte_ >> 4 != SHELLY_ADDR_PAYMENTKEYHASH_STAKEKEYHASH)
        throw std::runtime_error("Invalid address header byte.");
    for (size_t i = 0; i < KEY_HASH_LENGTH; i++)
    {
        addr.pmt_key_hash_[i] = data[i + 1];
        addr.stk_key_hash_[i] = data[i + 1 + KEY_HASH_LENGTH];
    }
    return addr;
}  // BaseAddress::fromBech32

auto BaseAddress::toBytes(bool include_header_byte) const
    -> std::vector<uint8_t>
{
    auto bytes = concat_bytes(this->pmt_key_hash_, this->stk_key_hash_);
    if (include_header_byte) bytes.insert(bytes.begin(), this->header_byte_);
    return bytes;
}  // BaseAddress::toBytes

auto BaseAddress::toBase16(bool include_header_byte) const -> std::string
{
    return BASE16::encode(this->toBytes(include_header_byte));
}  // BaseAddress::toBase16

auto BaseAddress::toBech32(std::string hrp) const -> std::string
{
    auto bytes = concat_bytes(this->pmt_key_hash_, this->stk_key_hash_);
    bytes.insert(bytes.begin(), this->header_byte_);
    return BECH32::encode(hrp, bytes);
}  // BaseAddress::toBech32

EnterpriseAddress::EnterpriseAddress(
    NetworkID nid, std::array<uint8_t, KEY_HASH_LENGTH> key_hash
)
{
    this->key_hash_ = std::move(key_hash);
    this->header_byte_ = SHELLY_ADDR_PAYMENTKEYHASH << 4;
    if (nid == NetworkID::mainnet)
        this->header_byte_ |= NETWORK_TAG_MAINNET;
    else
        this->header_byte_ |= NETWORK_TAG_TESTNET;
}  // EnterpriseAddress::RewardsAddress

auto EnterpriseAddress::fromKey(NetworkID nid, BIP32PublicKey key)
    -> EnterpriseAddress
{
    const auto key_bytes = key.toBytes(false);
    const auto blake2b = Botan::HashFunction::create("Blake2b(224)");
    blake2b->update(key_bytes.data(), key_bytes.size());
    const auto key_hash = blake2b->final();

    // Put the hash in a std::array of bytes for the address constructor.
    auto key_hash_array = std::array<uint8_t, KEY_HASH_LENGTH>();
    std::copy_n(key_hash.begin(), KEY_HASH_LENGTH, key_hash_array.begin());

    return EnterpriseAddress(nid, key_hash_array);
}  // EnterpriseAddress::fromKeys

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
}  // EnterpriseAddress::fromBech32

auto EnterpriseAddress::toBytes(bool include_header_byte) const
    -> std::vector<uint8_t>
{
    auto offset = (size_t)include_header_byte;
    auto bytes = std::vector<uint8_t>(KEY_HASH_LENGTH + offset);
    if (include_header_byte)
    {
        bytes[0] = this->header_byte_;
    }
    std::copy_n(
        this->key_hash_.begin(), KEY_HASH_LENGTH, bytes.begin() + offset
    );
    return bytes;
}  // EnterpriseAddress::toBytes

auto EnterpriseAddress::toBase16(bool include_header_byte) const -> std::string
{
    return BASE16::encode(this->toBytes(include_header_byte));
}  // EnterpriseAddress::toBase16

auto EnterpriseAddress::toBech32(std::string hrp) const -> std::string
{
    return BECH32::encode(hrp, this->toBytes(true));
}  // EnterpriseAddress::toBech32

RewardsAddress::RewardsAddress(
    NetworkID nid, std::array<uint8_t, KEY_HASH_LENGTH> key_hash
)
{
    this->key_hash_ = std::move(key_hash);
    this->header_byte_ = STAKE_ADDR_STAKEKEYHASH << 4;
    if (nid == NetworkID::mainnet)
        this->header_byte_ |= NETWORK_TAG_MAINNET;
    else
        this->header_byte_ |= NETWORK_TAG_TESTNET;
}  // RewardsAddress::RewardsAddress

auto RewardsAddress::fromKey(NetworkID nid, BIP32PublicKey stake_key)
    -> RewardsAddress
{
    const auto stake_key_bytes = stake_key.toBytes(false);
    const auto blake2b = Botan::HashFunction::create("Blake2b(224)");
    blake2b->update(stake_key_bytes.data(), stake_key_bytes.size());
    const auto key_hash = blake2b->final();

    // Put the hash in a std::array of bytes for the address constructor.
    auto key_hash_array = std::array<uint8_t, KEY_HASH_LENGTH>();
    std::copy_n(key_hash.begin(), KEY_HASH_LENGTH, key_hash_array.begin());

    return RewardsAddress(nid, key_hash_array);
}  // RewardsAddress::fromKeys

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
}  // RewardsAddress::fromBech32

auto RewardsAddress::toBytes(bool include_header_byte) const
    -> std::vector<uint8_t>
{
    auto offset = (size_t)include_header_byte;
    auto bytes = std::vector<uint8_t>(KEY_HASH_LENGTH + offset);
    if (include_header_byte)
    {
        bytes[0] = this->header_byte_;
    }
    std::copy_n(
        this->key_hash_.begin(), KEY_HASH_LENGTH, bytes.begin() + offset
    );
    return bytes;
}  // RewardsAddress::toBytes

auto RewardsAddress::toBase16(bool include_header_byte) const -> std::string
{
    return BASE16::encode(this->toBytes(include_header_byte));
}  // RewardsAddress::toBase16

auto RewardsAddress::toBech32(std::string hrp) const -> std::string
{
    return BECH32::encode(hrp, this->toBytes(true));
}  // RewardsAddress::toBech32

////////////////////////////////////////////////////////////////////////////////
//////////////////////////// Byron Era Addresses ///////////////////////////////
////////////////////////////////////////////////////////////////////////////////

// +---------------------------------------------------------------------------+
// |                                                                           |
// |                      CBOR-Serialized Object with CRC¹                     |
// |                                                                           |
// +---------------------------------------------------------------------------+
//                                       |
//                                       |
//                                       v
// +---------------------------------------------------------------------------+
// |    Address Root   |    Address Attributes    |          AddrType          |
// |                   |                          |                            |
// |  Hash (224 bits)  | Der. Path² + Stake + NM  | PubKey | (Script) | Redeem |
// |                   |   (open for extension)   |    (open for extension)    |
// +---------------------------------------------------------------------------+
//              |                |
//              |                |     +----------------------------------+
//              v                |     |        Derivation Path           |
// +--------------------------+  |---->|                                  |
// |SHA3-256                  |  |     | ChaChaPoly⁴ AccountIx/AddressIx  |
// |  |> Blake2b 224          |  |     +----------------------------------+
// |  |> CBOR                 |  |
// |                          |  |
// | -AddrType                |  |     +----------------------------------+
// | -ASD³ (~AddrType+PubKey) |  |     |       Stake Distribution         |
// | -Address Attributes      |  |     |                                  |
// +--------------------------+  |---->|  BootstrapEra | (Single | Multi) |
//                               |     +----------------------------------+
//                               |
//                               |
//                               |     +----------------------------------+
//                               |     |          Network Magic           |
//                               |---->|                                  |
//                                     | Addr Discr: MainNet vs TestNet   |
//                                     +----------------------------------+
//
// CRC: Cyclic Redundancy Check; sort of checksum, a bit (pun intended) more
// reliable. ASD: Address Spending Data; Some data that are bound to an address.
// It’s an extensible object
//      with payload which identifies one of the three elements:
//  * A Public Key (Payload is thereby a PublicKey)
//  * A Script (Payload is thereby a script and its version)
//  * A Redeem Key (Payload is thereby a RedeemPublicKey)
// Derivation Path: Note that there’s no derivation path for Redeem nor Scripts
// addresses! ChaChaPoly: Authenticated Encryption with Associated Data (see RFC
// 7539. We use it as a way to
//             cipher the derivation path using a passphrase (the root public
//             key).
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
static constexpr auto DP_SALT =
    std::array<uint8_t, 15>{0x61, 0x64, 0x64, 0x72, 0x65, 0x73, 0x73, 0x2d,
                            0x68, 0x61, 0x73, 0x68, 0x69, 0x6e, 0x67};

// Nonce (hardcoded in legacy Bryon code) used for the address derivation path
// encryption cipher.String value: "serokellfore".
static constexpr auto DP_NONCE = std::array<uint8_t, 12>{
    0x73, 0x65, 0x72, 0x6f, 0x6b, 0x65, 0x6c, 0x6c, 0x66, 0x6f, 0x72, 0x65};

/// Compute the CRC32 checksum of the provided bytes
static auto compute_crc32(std::span<const uint8_t> bytes) -> uint32_t
{
    auto crc32 = Botan::HashFunction::create("CRC32");
    crc32->update(bytes.data(), bytes.size());
    auto hash = crc32->final();
    uint32_t val = (hash[0] << 24) | (hash[1] << 16) | (hash[2] << 8) | hash[3];
    return val;
}  // compute_crc32

/// Parse the CBOR bytes and return the cppbor::Item.
static auto cbor_decode(std::span<const uint8_t> bytes)
    -> std::unique_ptr<cppbor::Item>
{
    auto [item, pos, message] =
        cppbor::parse(bytes.data(), bytes.data() + bytes.size());
    if (item.get() == nullptr) throw std::invalid_argument(message);
    return std::move(item);
}  // cbor_decode

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
}  // ByronAddress::typeToUint()

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
}  // ByronAddress::uintToType

auto ByronAddress::crc_check(std::span<const uint8_t> cbor, uint32_t crc)
    -> bool
{
    auto cbor_crc32 = compute_crc32(cbor);
    return (cbor_crc32 == crc);
}  // check_byron_address_crc

auto ByronAddress::Attributes::fromKey(
    BIP32PublicKey xpub, std::span<const uint32_t> path, uint32_t magic
) -> ByronAddress::Attributes
{
    // Create the passphrase for encrypting the derivation path.
    auto key = Botan::SecureVector<uint8_t>(DP_KEY_SIZE);
    auto xpub_bytes =
        xpub.toBytes();  // <- get vector of pub key and chain code
    auto fam = Botan::PasswordHashFamily::create("PBKDF2(SHA-512)");
    const auto pbkdf2 = fam->from_params(DP_KEY_ITERATIONS);
    pbkdf2->derive_key(
        key.data(), key.size(), (const char*)xpub_bytes.data(),
        xpub_bytes.size(), DP_SALT.data(), DP_SALT.size()
    );

    // CBOR encode the derivation path(s). The CBOR is what is encrypted.
    auto cbor = cppbor::Array();
    for (auto idx : path) cbor.add((uint64_t)idx);
    auto bytes = cbor.encode();
    
    // Adjust the CBOR to be encoded as an indefinite array.
    bytes[0] = 0x9F;
    bytes.push_back(0xFF);

    // The encryption function needs a Botan::secure_vector as input.
    auto pt = Botan::secure_vector<uint8_t>(bytes.begin(), bytes.end());

    // Encrypt the derivation path (CBOR encoded) using a ChaCha20Poly1305
    // cipher.
    auto cm = Botan::Cipher_Mode::create("ChaCha20Poly1305", Botan::ENCRYPTION);
    cm->set_key(key);
    cm->start(DP_NONCE.data(), DP_NONCE.size());
    cm->finish(pt);

    // Set the object members
    auto attrs =
        ByronAddress::Attributes(std::vector(pt.begin(), pt.end()), magic);
    return attrs;
}  // ByronAddress::Attributes::fromKey

auto ByronAddress::fromCBOR(std::span<const uint8_t> addr_cbor) -> ByronAddress
{
    auto baddr = ByronAddress();

    try
    {
        // Decode the address CBOR bytes
        auto item = cbor_decode(addr_cbor);
        auto payload_bytes = item->asArray()->get(0)->asBstr()->value();
        auto payload_crc32 = item->asArray()->get(1)->asUint()->unsignedValue();

        // Check the CRC32 of the payload.
        if (!ByronAddress::crc_check(payload_bytes, (uint32_t)payload_crc32))
            throw std::logic_error("");

        // Decode the address payload which is itself CBOR data
        auto payload_item = cbor_decode(payload_bytes);
        auto payload_root = payload_item->asArray()->get(0)->asBstr();
        auto payload_attr = payload_item->asArray()->get(1)->asMap();
        auto payload_type = payload_item->asArray()->get(2)->asUint();

        // Access the address root (hash of address data)
        auto root_bytes = payload_root->value();
        std::copy(root_bytes.begin(), root_bytes.end(), baddr.root_.begin());

        // Access the address attributes (if present)
        if (payload_attr->get(1).get() != nullptr)
        {
            // The ciphertext is a double CBOR encoded byte string.
            auto decoded = cbor_decode(payload_attr->get(1)->asBstr()->value());
            baddr.attrs_.ciphertext = decoded->asBstr()->value();
        }
        if (payload_attr->get(2).get() != nullptr)
        {
            // The network magic is a double CBOR encoded unsigned integer.
            auto decoded = cbor_decode(payload_attr->get(2)->asBstr()->value());
            baddr.attrs_.magic =
                static_cast<uint32_t>(decoded->asUint()->unsignedValue());
        }

        // Get the address type
        baddr.type_ = ByronAddress::uintToType(payload_type->unsignedValue());
    }
    catch (const std::exception& e)
    {
        throw std::invalid_argument(
            "Provided CBOR data is not a valid Byron-era address."
        );
    }

    return baddr;
}  // ByronAddress::fromCBOR

auto ByronAddress::fromBase58(std::string addr) -> ByronAddress
{
    // Decode the Base58 address to get the CBOR data as a byte vector.
    auto addr_cbor = BASE58::decode(addr);
    return ByronAddress::fromCBOR(addr_cbor);
}  // ByronAddress::fromBase58

auto ByronAddress::toCBOR() const -> std::vector<uint8_t>
{
    // Create the payload item, which constists of the root, attributes, and
    // address type in a three item array.
    auto payload_cbor = cppbor::Array();

    // Add the hash of the root key to the CBOR payload as the first element.
    payload_cbor.add(cppbor::Bstr({this->root_.data(), this->root_.size()}));

    // Create a map of the address attributes, then add the map to the payload
    // array.
    auto attrs_cbor = cppbor::Map();
    if (this->attrs_.ciphertext.size() > 0)
    {
        // The ciphertext is double CBOR encoded
        attrs_cbor.add(1, cppbor::Bstr(this->attrs_.ciphertext).encode());
    }
    if (this->attrs_.magic != 0)
    {
        // The protocol magic ID is also double CBOR encoded, first as an
        // unsigned int and then as a bytestring.
        attrs_cbor.add(2, cppbor::Uint((uint64_t)this->attrs_.magic).encode());
    }
    payload_cbor.add(std::move(attrs_cbor));

    // Add the address type as the last element in the payload.
    payload_cbor.add(ByronAddress::typeToUint(this->type_));

    // Serialize the payload to a vector of bytes.
    auto payload_vec = payload_cbor.encode();

    // Finally, pack the tagged payload and CRC32 into a two element array.
    auto addr_cbor = cppbor::Array(
        cppbor::SemanticTag(24, payload_vec), compute_crc32(payload_vec)
    );

    // CBOR encode the CBOR-serialized object with CRC.
    return addr_cbor.encode();
}  // ByronAddress::toCBOR

auto ByronAddress::toBase58() const -> std::string
{
    return BASE58::encode(this->toCBOR());
}  // ByronAddress::toBase58

auto sha3_then_blake2b224(std::span<const uint8_t> data)
    -> std::array<uint8_t, 28>
{
    auto sha3 = Botan::HashFunction::create("SHA-3(256)");
    auto blake2b = Botan::HashFunction::create("Blake2b(224)");

    sha3->update(data.data(), data.size());
    blake2b->update(sha3->final().data(), 32);
    auto blake2b_out = blake2b->final();

    std::array<uint8_t, 28> hashed_data;
    std::move(
        std::begin(blake2b_out), std::end(blake2b_out), hashed_data.begin()
    );
    return hashed_data;
}  // sha3_then_blake2b224

auto ByronAddress::fromRootKey(
    BIP32PrivateKey xprv,
    std::span<const uint32_t> dpath,
    uint32_t network_magic
) -> ByronAddress
{
    const auto addr_type = ByronAddress::Type::pubkey;
    const auto addr_type_int = (uint64_t)ByronAddress::typeToUint(addr_type);

    // Get the root public key
    const auto xpub = xprv.toPublic();

    // Create the address attributes
    auto attrs = ByronAddress::Attributes::fromKey(xpub, dpath, network_magic);

    // Derive the address public key from the root private key.
    if (dpath.size() != 2)
        throw std::invalid_argument("Invalid Byron address derivation path.");
    auto addr_xpub = xprv.deriveChild(dpath[0], DerivationMode::V1)
                         .deriveChild(dpath[1], DerivationMode::V1)
                         .toPublic();

    // CBOR encode the address spending data
    auto spending_cbor = cppbor::Array(addr_type_int, addr_xpub.toBytes());

    auto attrs_cbor = cppbor::Map();
    if (attrs.ciphertext.size() > 0)
    {
        // The ciphertext is double CBOR encoded
        attrs_cbor.add(1, cppbor::Bstr(attrs.ciphertext).encode());
    }
    if (attrs.magic != 0)
    {
        // The protocol magic ID is also double CBOR encoded, first as an
        // unsigned int and then as a bytestring.
        attrs_cbor.add(2, cppbor::Uint((uint64_t)attrs.magic).encode());
    }

    // Create the address root
    auto root_cbor = cppbor::Array(
        addr_type_int, std::move(spending_cbor), std::move(attrs_cbor)
    );

    // Serialize the address root to CBOR bytes and then hash it to form the
    // address root.
    auto root = sha3_then_blake2b224(root_cbor.encode());

    return ByronAddress(root, attrs, addr_type);
}  // ByronAddress::fromKey
