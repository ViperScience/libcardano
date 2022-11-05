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
#include <numeric>
#include <stdexcept>
#include <vector>

// Third-Party Library Headers
#include <botan/hash.h>
#include <botan/mac.h>
#include <botan/pbkdf2.h>
#include <botan/pwdhash.h>

#include "botan/secmem.h"
#include "botan/stream_cipher.h"

// Public Cardano++ Headers
#include <cardano/crypto.hpp>
#include <cardano/encodings.hpp>

// Private Cardano++ Headers
#include "cardano_crypto_interface.h"
#include "utils.hpp"

using namespace cardano;

static constexpr size_t NB_ITERATIONS = 15000;
static constexpr size_t SYM_KEY_SIZE = 32;
static constexpr size_t SYM_NONCE_SIZE = 8;
#define SYM_BUF_SIZE (SYM_KEY_SIZE + SYM_NONCE_SIZE)

auto BIP32PublicKey::fromBech32(std::string bech32_str) -> BIP32PublicKey
{
    BIP32PublicKey k;
    const auto [hrp1, data] = BECH32::decode(bech32_str);
    std::copy_n(data.begin(), k.pub_.size(), k.pub_.begin());
    std::copy_n(data.begin() + k.pub_.size(), k.cc_.size(), k.cc_.begin());
    return k;
}  // BIP32PublicKey::fromBech32

auto BIP32PublicKey::fromBase16(std::string_view xpub) -> BIP32PublicKey
{
    if (xpub.size() != (PUBLIC_KEY_SIZE + CHAIN_CODE_SIZE) * 2)
        throw std::invalid_argument("Invalid hex public key size.");
    const auto bytes = BASE16::decode(xpub);
    auto pub = std::array<uint8_t, PUBLIC_KEY_SIZE>();
    auto cc = std::array<uint8_t, CHAIN_CODE_SIZE>();
    std::copy_n(bytes.begin(), pub.size(), pub.begin());
    std::copy_n(bytes.begin() + pub.size(), cc.size(), cc.begin());
    return BIP32PublicKey(pub, cc);
}  // BIP32PublicKey::fromBase16

auto BIP32PublicKey::fromBase16(
    const std::string& pub_hex, const std::string& cc_hex
) -> BIP32PublicKey
{
    if (pub_hex.size() != PUBLIC_KEY_SIZE * 2)
        throw std::invalid_argument("Invalid hex public key size.");
    if (cc_hex.size() != CHAIN_CODE_SIZE * 2)
        throw std::invalid_argument("Invalid hex chain code size.");
    const auto bytes = BASE16::decode(pub_hex + cc_hex);
    auto pub = std::array<uint8_t, PUBLIC_KEY_SIZE>();
    auto cc = std::array<uint8_t, CHAIN_CODE_SIZE>();
    std::copy_n(bytes.begin(), pub.size(), pub.begin());
    std::copy_n(bytes.begin() + pub.size(), cc.size(), cc.begin());
    return BIP32PublicKey(pub, cc);
}  // BIP32PublicKey::fromBase16

auto BIP32PublicKey::toBytes(bool with_cc) const -> std::vector<uint8_t>
{
    if (!with_cc)
        return std::vector<uint8_t>(
            this->pub_.data(), this->pub_.data() + this->pub_.size()
        );
    return concat_bytes(this->pub_, this->cc_);
}  // BIP32PublicKey::toBytes

auto BIP32PublicKey::toBech32(std::string_view hrp) const -> std::string
{
    const auto data = concat_bytes(this->pub_, this->cc_);
    return BECH32::encode(hrp, data);
}  // BIP32PublicKey::toBech32

auto BIP32PublicKey::toBase16() const -> std::string
{
    const auto bytes = concat_bytes(this->pub_, this->cc_);
    return BASE16::encode(bytes);
}  // ExtendedPublicKey::toBase16

auto BIP32PublicKey::toCBOR(bool with_cc) const -> std::string
{
    if (!with_cc) return BASE16::encode(CBOR::encode(this->pub_));
    const auto bytes = concat_bytes(this->pub_, this->cc_);
    return BASE16::encode(CBOR::encode(bytes));
}  // BIP32PublicKey::toCBOR

auto BIP32PublicKey::deriveChild(uint32_t index, uint32_t derivation_mode) const
    -> BIP32PublicKey
{
    const uint8_t* pub_in = this->pub_.data();
    const uint8_t* cc_in = this->cc_.data();

    BIP32PublicKey k;
    uint8_t* pub_out = k.pub_.data();
    uint8_t* cc_out = k.cc_.data();

    // Derive the child public key for the soft index.
    derivation_scheme_mode mode;
    switch (derivation_mode)
    {
        case 1:
            mode = DERIVATION_V1;
            break;
        case 2:
        default:
            mode = DERIVATION_V2;
            break;
    }
    int flag = wallet_encrypted_derive_public_v2(
        pub_in, cc_in, index, pub_out, cc_out, mode
    );
    if (flag != 0)
        throw std::runtime_error("Cannot derive hardened index from public key."
        );

    return k;
}  // BIP32PublicKey::deriveChild

auto BIP32PrivateKey::clear() -> bool
{
    std::fill(this->prv_.begin(), this->prv_.end(), 0);
    return std::accumulate(this->prv_.begin(), this->prv_.end(), 0) == 0;
}  // BIP32PrivateKey::clear

BIP32PrivateKey::BIP32PrivateKey(std::span<const uint8_t> xpriv)
{
    if (xpriv.size() != this->prv_.size() + this->cc_.size())
        throw std::invalid_argument("Invalid extended private key size.");
    std::copy_n(xpriv.begin(), this->prv_.size(), this->prv_.begin());
    std::copy_n(
        xpriv.begin() + this->prv_.size(), this->cc_.size(), this->cc_.begin()
    );
}  // BIP32PrivateKey::BIP32PrivateKey

BIP32PrivateKey::BIP32PrivateKey(std::string_view xprv)
{
    if (xprv.size() != (ENCRYPTED_KEY_SIZE + CHAIN_CODE_SIZE) * 2)
        throw std::invalid_argument("Invalid hex extended private key size.");
    const auto bytes = BASE16::decode(xprv);
    std::copy_n(bytes.begin(), this->prv_.size(), this->prv_.begin());
    std::copy_n(
        bytes.begin() + this->prv_.size(), this->cc_.size(), this->cc_.begin()
    );
}  // BIP32PrivateKey::BIP32PrivateKey

BIP32PrivateKey::BIP32PrivateKey(const std::string& prv, const std::string& cc)
{
    if (prv.size() != this->prv_.size() * 2)
        throw std::invalid_argument("Invalid hex private key size.");
    if (cc.size() != this->cc_.size() * 2)
        throw std::invalid_argument("Invalid hex chain code size.");
    auto bytes = BASE16::decode(prv + cc);
    std::copy_n(bytes.begin(), this->prv_.size(), this->prv_.begin());
    std::copy_n(
        bytes.begin() + this->prv_.size(), this->cc_.size(), this->cc_.begin()
    );
}  // BIP32PrivateKey::BIP32PrivateKey

auto BIP32PrivateKey::fromBech32(std::string_view bech32_str) -> BIP32PrivateKey
{
    const auto [hrp1, data] = cardano::BECH32::decode(bech32_str);
    auto skey = std::array<uint8_t, ENCRYPTED_KEY_SIZE>();
    auto cc = std::array<uint8_t, CHAIN_CODE_SIZE>();
    std::copy_n(data.begin(), ENCRYPTED_KEY_SIZE, skey.begin());
    std::copy_n(data.begin() + ENCRYPTED_KEY_SIZE, CHAIN_CODE_SIZE, cc.begin());
    return BIP32PrivateKey(skey, cc);
}  // BIP32PrivateKey::fromBech32

auto tweak_bits_byron(std::span<uint8_t> data) -> void
{
    // clear the lowest 3 bits
    // clear the highest bit
    // set the highest 2nd bit
    data[0] &= 0b11111000;
    data[31] &= 0b01111111;
    data[31] |= 0b01000000;
}  // tweak_bits_byron

auto tweak_bits_icarus(std::span<uint8_t> data) -> void
{
    // on the ed25519 scalar leftmost 32 bytes:
    // * clear the lowest 3 bits
    // * clear the highest bit
    // * clear the 3rd highest bit
    // * set the highest 2nd bit
    data[0] &= 0b11111000;
    data[31] &= 0b00011111;
    data[31] |= 0b01000000;
}  // tweak_bits_icarus

auto hash_repeatedly(const std::vector<uint8_t>& key, size_t count)
    -> std::vector<uint8_t>
{
    if (count > 1000)
        throw std::runtime_error("Cannot generate root key (looping forever).");

    const auto mac = Botan::MessageAuthenticationCode::create("HMAC(SHA-512)");
    if (!mac) throw std::runtime_error("Unable to create HMAC object.");

    const auto message = "Root Seed Chain " + std::to_string(count);
    const auto data = std::vector<uint8_t>(message.begin(), message.end());
    mac->set_key(key);
    mac->update(data);
    const auto tag = mac->final();

    const auto iL = std::vector<uint8_t>(tag.begin(), tag.begin() + 32);
    const auto iR = std::vector<uint8_t>(tag.begin() + 32, tag.end());

    const auto sha512 = Botan::HashFunction::create("SHA-512");
    sha512->update(iL.data(), iL.size());
    auto prv = sha512->final();
    tweak_bits_byron(prv);

    if (prv[31] & 0b00100000) return hash_repeatedly(key, count + 1);

    return concat_bytes(prv, iR);
}  // hash_repeatedly

auto hash_seed(std::span<const uint8_t> seed) -> std::vector<uint8_t>
{
    // CBOR encode the seed.
    auto buffer = CBOR::encode(seed);

    // Blake2b-SHA256 encode the CBOR encoded seed (32 byte result).
    const auto blake2b = Botan::HashFunction::create("Blake2b(256)");
    blake2b->update(buffer.data(), buffer.size());
    const auto hashed = blake2b->final();

    // CBOR encode the hashed seed (34 bytes after CBOR encoding).
    auto hashed_seed = CBOR::encode(hashed);

    return hashed_seed;
}  // hash_seed

auto BIP32PrivateKey::fromMnemonicByron(const cardano::Mnemonic& mn)
    -> BIP32PrivateKey
{
    const auto hashed_seed = hash_seed(mn.toSeed());
    return BIP32PrivateKey(hash_repeatedly(hashed_seed, 1));
}  // BIP32PrivateKey::fromMnemonicByron

auto BIP32PrivateKey::fromMnemonic(
    const cardano::Mnemonic& mn, std::string_view passphrase
) -> BIP32PrivateKey
{
    auto mac = Botan::MessageAuthenticationCode::create("HMAC(SHA-512)");
    const auto pbkdf2 = std::make_unique<Botan::PBKDF2>(*mac.release(), 4096);
    const auto seed = mn.toSeed();
    auto key = std::vector<uint8_t>(96);
    pbkdf2->derive_key(
        key.data(), key.size(), passphrase.data(), passphrase.size(),
        seed.data(), seed.size()
    );
    tweak_bits_icarus(key);
    return BIP32PrivateKey(key);
};  // BIP32PrivateKey::fromMnemonic

auto BIP32PrivateKey::fromMnemonic(const cardano::Mnemonic& mn)
    -> BIP32PrivateKey
{
    return BIP32PrivateKey::fromMnemonic(mn, "");
};  // BIP32PrivateKey::fromMnemonic

auto BIP32PrivateKey::toBech32(std::string_view hrp) const -> std::string
{
    auto data = std::vector<uint8_t>();
    data.reserve(ENCRYPTED_KEY_SIZE + CHAIN_CODE_SIZE);
    data.insert(data.begin(), this->prv_.begin(), this->prv_.end());
    data.insert(
        data.begin() + ENCRYPTED_KEY_SIZE, this->cc_.begin(), this->cc_.end()
    );
    return BECH32::encode(hrp, data);
}  // BIP32PrivateKey::toBech32

auto BIP32PrivateKey::toBase16() const -> std::string
{
    const auto bytes = concat_bytes(this->prv_, this->cc_);
    return BASE16::encode(bytes);
}  // ExtendedPublicKey::toBase16

auto BIP32PrivateKey::toCBOR(bool with_cc) const -> std::string
{
    if (!with_cc) return BASE16::encode(CBOR::encode(this->prv_));
    const auto bytes = concat_bytes(this->prv_, this->cc_);
    return BASE16::encode(CBOR::encode(bytes));
}  // BIP32PrivateKey::toCBOR

auto BIP32PrivateKey::toExtendedCBOR() const -> std::string
{
    auto pubkey = this->toPublic().toBytes();  // <- includes the chain code
    auto bytes = concat_bytes(this->prv_, pubkey);
    return BASE16::encode(CBOR::encode(bytes));
}  // BIP32PrivateKey::toExtendedCBOR

auto BIP32PrivateKey::toPublic() const -> BIP32PublicKey
{
    auto cc = std::array<uint8_t, CHAIN_CODE_SIZE>(this->cc_);
    auto pub_key = std::array<uint8_t, PUBLIC_KEY_SIZE>();
    cardano_crypto_ed25519_publickey(this->prv_.data(), pub_key.data());
    return {pub_key, cc};
}  // BIP32PrivateKey::toPublic

auto BIP32PrivateKey::deriveChild(uint32_t index, uint32_t derivation_mode)
    const -> BIP32PrivateKey
{
    // Build the encrypted key struct for the derive function.
    encrypted_key ek;
    std::copy(this->prv_.begin(), this->prv_.end(), std::begin(ek.ekey));
    std::copy(this->cc_.begin(), this->cc_.end(), std::begin(ek.cc));
    cardano_crypto_ed25519_publickey(this->prv_.data(), ek.pkey);

    // Perform the child key derivation using the cardano crypto C library.
    derivation_scheme_mode mode;
    switch (derivation_mode)
    {
        case 1:
            mode = DERIVATION_V1;
            break;
        case 2:
        default:
            mode = DERIVATION_V2;
            break;
    }
    uint32_t pw_len = 0;  // This will skip the decryption
    uint8_t* pw = nullptr;
    encrypted_key ek_out;
    wallet_encrypted_derive_private(&ek, pw, pw_len, index, &ek_out, mode);

    auto skey = std::array<uint8_t, ENCRYPTED_KEY_SIZE>();
    auto cc = std::array<uint8_t, CHAIN_CODE_SIZE>();
    std::copy_n(std::begin(ek_out.ekey), ENCRYPTED_KEY_SIZE, skey.begin());
    std::copy_n(std::begin(ek_out.cc), CHAIN_CODE_SIZE, cc.begin());
    return {skey, cc};
}  // BIP32PrivateKey::deriveChild

auto BIP32PrivateKey::encrypt(std::string_view password)
    -> BIP32PrivateKeyEncrypted
{
    auto prv = std::array<uint8_t, ENCRYPTED_KEY_SIZE>{};
    wallet_decrypt_private(
        (const uint8_t*)password.data(), password.size(), this->prv_.data(),
        prv.data()
    );
    auto enc_key = BIP32PrivateKeyEncrypted(prv, this->cc_);
    this->clear();
    return enc_key;
}  // BIP32PrivateKey::encrypt

BIP32PrivateKeyEncrypted::BIP32PrivateKeyEncrypted(
    const std::string& prv, const std::string& cc
)
{
    if (prv.size() != this->xprv_.size() * 2)
        throw std::invalid_argument("Invalid hex public key size.");
    if (cc.size() != this->cc_.size() * 2)
        throw std::invalid_argument("Invalid hex chain code size.");
    const auto bytes = BASE16::decode(prv + cc);
    std::copy_n(bytes.begin(), ENCRYPTED_KEY_SIZE, this->xprv_.begin());
    std::copy_n(
        bytes.begin() + ENCRYPTED_KEY_SIZE, CHAIN_CODE_SIZE, this->cc_.begin()
    );
}  // BIP32PrivateKeyEncrypted::ExtendedPublicKey

BIP32PrivateKeyEncrypted::BIP32PrivateKeyEncrypted(std::string_view xprv)
{
    if (xprv.size() != (ENCRYPTED_KEY_SIZE + CHAIN_CODE_SIZE) * 2)
        throw std::invalid_argument("Invalid extended hex private key size.");
    const auto bytes = BASE16::decode(xprv);
    std::copy_n(bytes.begin(), ENCRYPTED_KEY_SIZE, this->xprv_.begin());
    std::copy_n(
        bytes.begin() + ENCRYPTED_KEY_SIZE, CHAIN_CODE_SIZE, this->cc_.begin()
    );
}  // BIP32PrivateKeyEncrypted::ExtendedPublicKey

auto BIP32PrivateKeyEncrypted::deriveChild(
    uint32_t index, std::string_view password, uint32_t derivation_mode
) const -> BIP32PrivateKeyEncrypted
{
    const auto decrypted = this->decrypt(password);
    auto child = decrypted.deriveChild(index, derivation_mode);
    return child.encrypt(password);
}  // BIP32PrivateKeyEncrypted::deriveChild

auto BIP32PrivateKeyEncrypted::toPublic(std::string_view password) const
    -> BIP32PublicKey
{
    const auto decrypted = this->decrypt(password);
    return decrypted.toPublic();
}  // BIP32PrivateKeyEncrypted::toPublic

auto BIP32PrivateKeyEncrypted::decrypt(std::string_view password) const
    -> BIP32PrivateKey
{
    // This is the password encryption used in Daedalus.
    auto cc = std::array<uint8_t, CHAIN_CODE_SIZE>(this->cc_);
    auto prv = std::array<uint8_t, ENCRYPTED_KEY_SIZE>(this->xprv_);
    if (!password.empty())
    {
        static constexpr uint8_t salt[] = "encrypted wallet salt";
        auto buf = Botan::SecureVector<uint8_t>(SYM_BUF_SIZE);
        auto fam = Botan::PasswordHashFamily::create("PBKDF2(SHA-512)");
        const auto pbkdf2 = fam->from_params(NB_ITERATIONS);
        pbkdf2->derive_key(
            buf.data(), buf.size(), password.data(), password.size(), salt,
            sizeof(salt)
        );
        auto cipher = Botan::StreamCipher::create("ChaCha(20)");
        cipher->set_key({buf.data(), SYM_KEY_SIZE});
        cipher->set_iv(buf.data() + SYM_KEY_SIZE, SYM_NONCE_SIZE);
        cipher->cipher(prv.data(), prv.data(), prv.size());
    }
    return {prv, cc};
}  // BIP32PrivateKeyEncrypted::decrypt

auto BIP32PrivateKeyEncrypted::toBase16() const -> std::string
{
    const auto bytes = concat_bytes(this->xprv_, this->cc_);
    return BASE16::encode(bytes);
}  // BIP32PrivateKeyEncrypted::toBase16

auto BIP32PrivateKeyEncrypted::toExtendedCBOR(std::string_view password) const
    -> std::string
{
    auto pubkey =
        this->toPublic(password).toBytes();  // <- includes the chain code
    auto bytes = concat_bytes(this->xprv_, pubkey);
    return BASE16::encode(CBOR::encode(bytes));
}  // BIP32PrivateKeyEncrypted::toExtendedCBOR
