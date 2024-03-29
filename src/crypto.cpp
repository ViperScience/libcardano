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
#include <botan/stream_cipher.h>
#include <cppbor/cppbor.h>

// Public libcardano headers
#include <cardano/crypto.hpp>
#include <cardano/encodings.hpp>

// Private libcardano source code
#include "utils.hpp"

using namespace cardano;

namespace  // unnamed namespace
{

constexpr auto TAG_DERIVE_Z_HARDENED = static_cast<uint8_t>(0x00);
constexpr auto TAG_DERIVE_CC_HARDENED = static_cast<uint8_t>(0x01);
constexpr auto TAG_DERIVE_Z_NORMAL = static_cast<uint8_t>(0x02);
constexpr auto TAG_DERIVE_CC_NORMAL = static_cast<uint8_t>(0x03);

// Return true if the index is hardened
constexpr auto index_is_hardened(uint32_t index) -> bool
{
    return (index & (1 << 31)) ? true : false;
}  // index_is_hardened

// Serialize the 32 bit index into an array of four bytes.
constexpr auto serialize_index32(uint32_t index, const DerivationMode mode)
    -> std::array<uint8_t, 4>
{
    auto out = std::array<uint8_t, 4>{};
    switch (mode)
    {
        case DerivationMode::V1:  // BIG ENDIAN
        {
            out[0] = static_cast<uint8_t>(index >> 24);
            out[1] = static_cast<uint8_t>(index >> 16);
            out[2] = static_cast<uint8_t>(index >> 8);
            out[3] = static_cast<uint8_t>(index);
            break;
        }
        case DerivationMode::V2:  // LITTLE ENDIAN
        {
            out[3] = static_cast<uint8_t>(index >> 24);
            out[2] = static_cast<uint8_t>(index >> 16);
            out[1] = static_cast<uint8_t>(index >> 8);
            out[0] = static_cast<uint8_t>(index);
            break;
        }
    }
    return out;
}  // serialize_index32

constexpr auto tweak_bits_byron(std::span<uint8_t> data) -> void
{
    // clear the lowest 3 bits
    // clear the highest bit
    // set the highest 2nd bit
    data[0] &= 0b11111000;
    data[31] &= 0b01111111;
    data[31] |= 0b01000000;
}  // tweak_bits_byron

constexpr auto tweak_bits_icarus(std::span<uint8_t> data) -> void
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

    return utils::concatBytes(prv, iR);
}  // hash_repeatedly

auto hash_seed(std::span<const uint8_t> seed) -> std::vector<uint8_t>
{
    // CBOR encode the seed.
    auto buffer = cppbor::Bstr({seed.data(), seed.size()}).encode();

    // Blake2b-SHA256 encode the CBOR encoded seed (32 byte result).
    const auto blake2b = Botan::HashFunction::create("Blake2b(256)");
    blake2b->update(buffer.data(), buffer.size());
    const auto hashed = blake2b->final();

    // CBOR encode the hashed seed (34 bytes after CBOR encoding).
    auto hashed_seed = cppbor::Bstr({hashed.data(), hashed.size()}).encode();

    return hashed_seed;
}  // hash_seed

}  // unnamed namespace

static constexpr size_t NB_ITERATIONS = 15000;
static constexpr size_t SYM_KEY_SIZE = 32;
static constexpr size_t SYM_NONCE_SIZE = 8;
#define SYM_BUF_SIZE (SYM_KEY_SIZE + SYM_NONCE_SIZE)

auto BIP32PublicKey::fromBech32(std::string bech32_str) -> BIP32PublicKey
{
    const auto [hrp1, data] = BECH32::decode(bech32_str);
    auto pub = std::array<uint8_t, PUBLIC_KEY_SIZE>();
    auto cc = std::array<uint8_t, CHAIN_CODE_SIZE>();
    std::copy_n(data.begin(), pub.size(), pub.begin());
    std::copy_n(data.begin() + pub.size(), cc.size(), cc.begin());
    return BIP32PublicKey(pub, cc);
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
    const std::string& pub_hex,
    const std::string& cc_hex
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
    auto pub_bytes = this->pub_.bytes();
    if (!with_cc)
    {
        std::vector<uint8_t> ret;
        ret.reserve(pub_bytes.size());
        ret.insert(ret.end(), begin(pub_bytes), end(pub_bytes));
        return ret;
    }
    return utils::concatBytes(pub_bytes, this->cc_);
}  // BIP32PublicKey::toBytes

auto BIP32PublicKey::toBech32(std::string_view hrp) const -> std::string
{
    const auto data = utils::concatBytes(this->pub_.bytes(), this->cc_);
    return BECH32::encode(hrp, data);
}  // BIP32PublicKey::toBech32

auto BIP32PublicKey::toBase16() const -> std::string
{
    return BASE16::encode(this->toBytes(true));
}  // ExtendedPublicKey::toBase16

auto BIP32PublicKey::toCBOR(bool with_cc) const -> std::string
{
    auto cbor_bytes = cppbor::Bstr(this->toBytes(with_cc)).encode();
    return BASE16::encode(cbor_bytes);  // return the bytes as a hex string
}  // BIP32PublicKey::toCBOR

auto BIP32PublicKey::deriveChild(
    const uint32_t index,
    const DerivationMode mode
) const -> BIP32PublicKey
{
    if (index_is_hardened(index)) throw std::exception();

    auto idxBuf = serialize_index32(index, mode);

    /* calculate Z */
    const auto pub_bytes_in = this->pub_.bytes();
    const auto mac = Botan::MessageAuthenticationCode::create("HMAC(SHA-512)");
    if (!mac) throw std::runtime_error("Unable to create HMAC object.");
    mac->set_key(this->cc_.data(), this->cc_.size());
    mac->update(TAG_DERIVE_Z_NORMAL);
    mac->update(pub_bytes_in.data(), pub_bytes_in.size());
    mac->update(idxBuf.data(), idxBuf.size());
    const auto z = mac->final();

    // calculate 8 * Zl
    auto zl8 = std::array<uint8_t, ed25519::ED25519_EXTENDED_KEY_SIZE>{};
    // This effectively zero pads to 64 bytes as needed for the extended secret
    // key constructor.
    switch (mode)
    {
        case DerivationMode::V1:
        {
            // multiply by 8
            auto prev_acc = uint8_t(0);
            for (auto i = 0UL; i < 32; i++)
            {
                zl8[i] = static_cast<uint8_t>((z[i] << 3) + (prev_acc & 0x8));
                prev_acc = z[i] >> 5;
            }
            break;
        }
        case DerivationMode::V2:
        {
            // multiply by 8
            uint8_t prev_acc = 0;
            for (auto i = 0UL; i < 28; i++)
            {
                zl8[i] = static_cast<uint8_t>((z[i] << 3) + (prev_acc & 0x7));
                prev_acc = z[i] >> 5;
            }
            zl8[28] = z[27] >> 5;
            break;
        }
    }
    auto prv_zl8 = ed25519::ExtendedPrivateKey(zl8);
    auto pub_new = prv_zl8.publicKey().pointAdd(this->pub_);

    // calculate the new chain code
    mac->set_key(this->cc_.data(), this->cc_.size());
    mac->update(TAG_DERIVE_CC_NORMAL);
    mac->update(pub_bytes_in.data(), pub_bytes_in.size());
    mac->update(idxBuf.data(), idxBuf.size());
    const auto hmac_out = mac->final();

    // The upper half is the new chain code
    auto cc_new = std::array<uint8_t, 32>();
    std::copy_n(hmac_out.begin() + 32, 32, cc_new.begin());

    return BIP32PublicKey(pub_new.bytes(), cc_new);
}  // BIP32PublicKey::deriveChild

auto BIP32PrivateKey::fromBytes(std::span<const uint8_t> xpriv)
    -> BIP32PrivateKey
{
    if (xpriv.size() != ENCRYPTED_KEY_SIZE + CHAIN_CODE_SIZE)
        throw std::invalid_argument("Invalid extended private key size.");
    auto skey = ed25519::ExtendedPrivateKey({xpriv.data(), ENCRYPTED_KEY_SIZE});
    auto cc = std::array<uint8_t, CHAIN_CODE_SIZE>();
    std::copy(xpriv.begin() + ENCRYPTED_KEY_SIZE, xpriv.end(), cc.begin());
    return BIP32PrivateKey(skey.bytes(), cc);
}  // BIP32PrivateKey::fromBytes

auto BIP32PrivateKey::fromBech32(std::string_view bech32_str) -> BIP32PrivateKey
{
    const auto [hrp1, data] = cardano::BECH32::decode(bech32_str);
    auto skey = std::array<uint8_t, ENCRYPTED_KEY_SIZE>();
    auto cc = std::array<uint8_t, CHAIN_CODE_SIZE>();
    std::copy_n(data.begin(), ENCRYPTED_KEY_SIZE, skey.begin());
    std::copy_n(data.begin() + ENCRYPTED_KEY_SIZE, CHAIN_CODE_SIZE, cc.begin());
    return BIP32PrivateKey(skey, cc);
}  // BIP32PrivateKey::fromBech32

auto BIP32PrivateKey::fromMnemonicByron(const cardano::Mnemonic& mn)
    -> BIP32PrivateKey
{
    const auto hashed_seed = hash_seed(mn.toSeed());
    return BIP32PrivateKey::fromBytes(hash_repeatedly(hashed_seed, 1));
}  // BIP32PrivateKey::fromMnemonicByron

auto BIP32PrivateKey::fromMnemonic(
    const cardano::Mnemonic& mn,
    std::string_view passphrase
) -> BIP32PrivateKey
{
    auto mac = Botan::MessageAuthenticationCode::create("HMAC(SHA-512)");
    const auto pbkdf2 = std::make_unique<Botan::PBKDF2>(*mac.release(), 4096);
    const auto seed = mn.toSeed();
    auto key = std::vector<uint8_t>(96);
    pbkdf2->derive_key(
        key.data(),
        key.size(),
        passphrase.data(),
        passphrase.size(),
        seed.data(),
        seed.size()
    );
    tweak_bits_icarus(key);
    return BIP32PrivateKey::fromBytes(key);
};  // BIP32PrivateKey::fromMnemonic

auto BIP32PrivateKey::fromMnemonic(const cardano::Mnemonic& mn)
    -> BIP32PrivateKey
{
    return BIP32PrivateKey::fromMnemonic(mn, "");
};  // BIP32PrivateKey::fromMnemonic

auto BIP32PrivateKey::toBytes(bool with_cc) const -> std::vector<uint8_t>
{
    auto prv_bytes = this->prv_.bytes();
    if (!with_cc)
    {
        return std::vector<uint8_t>(prv_bytes.begin(), prv_bytes.end());
    }
    return utils::concatBytes(prv_bytes, this->cc_);
}  // BIP32PrivateKey::toBytes

auto BIP32PrivateKey::toBech32(std::string_view hrp) const -> std::string
{
    return BECH32::encode(hrp, this->toBytes(true));
}  // BIP32PrivateKey::toBech32

auto BIP32PrivateKey::toBase16() const -> std::string
{
    return BASE16::encode(this->toBytes(true));
}  // ExtendedPublicKey::toBase16

auto BIP32PrivateKey::toCBOR(bool with_cc) const -> std::string
{
    return BASE16::encode(cppbor::Bstr(this->toBytes(with_cc)).encode());
}  // BIP32PrivateKey::toCBOR

auto BIP32PrivateKey::toExtendedCBOR() const -> std::string
{
    auto pubkey = this->toPublic().toBytes();  // <- includes the chain code
    auto bytes = utils::concatBytes(this->prv_.bytes(), pubkey);
    return BASE16::encode(cppbor::Bstr(bytes).encode());
}  // BIP32PrivateKey::toExtendedCBOR

auto BIP32PrivateKey::toPublic() const -> BIP32PublicKey
{
    return {this->prv_.publicKey().bytes(), this->cc_};
}  // BIP32PrivateKey::toPublic

auto BIP32PrivateKey::deriveChild(
    const uint32_t index,
    const DerivationMode mode
) const -> BIP32PrivateKey
{
    const auto pkey_bytes = this->prv_.publicKey().bytes();
    const auto skey_bytes = this->prv_.bytes();

    const auto idxBuf = serialize_index32(index, mode);

    // calculate Z
    const auto mac = Botan::MessageAuthenticationCode::create("HMAC(SHA-512)");
    if (!mac) throw std::runtime_error("Unable to create HMAC object.");
    mac->set_key(this->cc_.data(), CHAIN_CODE_SIZE);
    if (index_is_hardened(index))
    {
        mac->update(TAG_DERIVE_Z_HARDENED);
        mac->update(skey_bytes.data(), skey_bytes.size());
    }
    else
    {
        mac->update(TAG_DERIVE_Z_NORMAL);
        mac->update(pkey_bytes.data(), pkey_bytes.size());
    }
    mac->update(idxBuf.data(), idxBuf.size());
    const auto z = mac->final();

    // Fill the key array
    // Kr = Zr + parent(K)r
    auto res_key = std::array<uint8_t, ENCRYPTED_KEY_SIZE>();
    auto zl8 = std::array<uint8_t, ed25519::ED25519_EXTENDED_KEY_SIZE>{};
    switch (mode)
    {
        case DerivationMode::V1:
        {
            // get 8 * Zl
            auto prev_acc = static_cast<uint8_t>(0);
            for (auto i = 0UL; i < 32; i++)
            {
                zl8[i] = static_cast<uint8_t>((z[i] << 3) + (prev_acc & 0x8));
                prev_acc = z[i] >> 5;
            }

            // Kl = 8*Zl + parent(K)l
            auto prv_zl8 = ed25519::ExtendedPrivateKey(zl8);
            auto lbytes = prv_zl8.scalerAddLowerBytes(this->prv_);
            std::copy_n(lbytes.begin(), 32, res_key.begin());

            // Fill in the right-most bytes
            for (auto i = 0UL; i < 32; i++)
            {
                auto a = z[i + 32];
                auto b = skey_bytes[i + 32];
                auto r = static_cast<uint16_t>(a) + static_cast<uint16_t>(b);
                res_key[i + 32] = static_cast<uint8_t>(r & 0xff);
            }
            break;
        }
        case DerivationMode::V2:
        {
            // get 8 * Zl
            auto prev_acc = static_cast<uint8_t>(0);
            for (auto i = 0UL; i < 28; i++)
            {
                zl8[i] = static_cast<uint8_t>((z[i] << 3) + (prev_acc & 0x7));
                prev_acc = z[i] >> 5;
            }
            zl8[28] = z[27] >> 5;

            // Kl = 8*Zl + parent(K)l
            auto r = 0;
            for (auto i = 0UL; i < 32; i++)
            {
                r = zl8[i] + skey_bytes[i] + r;
                res_key[i] = static_cast<uint8_t>(r);
                r >>= 8;
            }

            // Fill in the right-most bytes
            auto carry = static_cast<uint8_t>(0);
            for (auto i = 0UL; i < 32; i++)
            {
                auto a = z[i + 32];
                auto b = skey_bytes[i + 32];
                r = a + b + carry;
                res_key[i + 32] = static_cast<uint8_t>(r) & 0xff;
                carry = (r >= 0x100) ? 1 : 0;
            }
            break;
        }
    }

    // calculate the new chain code
    mac->set_key(this->cc_.data(), this->cc_.size());
    if (index_is_hardened(index))
    {
        mac->update(TAG_DERIVE_CC_HARDENED);
        mac->update(skey_bytes.data(), skey_bytes.size());
    }
    else
    {
        mac->update(TAG_DERIVE_CC_NORMAL);
        mac->update(pkey_bytes.data(), pkey_bytes.size());
    }
    mac->update(idxBuf.data(), idxBuf.size());
    const auto hmac_out = mac->final();

    // The upper half is the new chain code
    auto cc = std::array<uint8_t, CHAIN_CODE_SIZE>();
    std::copy_n(hmac_out.begin() + 32, CHAIN_CODE_SIZE, cc.begin());

    return {res_key, cc};
}  // BIP32PrivateKey::deriveChild

auto BIP32PrivateKey::sign(std::span<const uint8_t> msg) const
    -> std::array<uint8_t, ed25519::ED25519_SIGNATURE_SIZE>
{
    return this->prv_.sign(msg);
}  // BIP32PrivateKey::sign

auto BIP32PrivateKey::encrypt(std::string_view password)
    -> BIP32PrivateKeyEncrypted
{
    if (password.empty())
        return BIP32PrivateKeyEncrypted(this->prv_.bytes(), this->cc_);

    // Stretch the password
    static constexpr uint8_t salt[] = "encrypted wallet salt";
    auto stretched_password = Botan::SecureVector<uint8_t>(SYM_BUF_SIZE);
    const auto fam = Botan::PasswordHashFamily::create("PBKDF2(SHA-512)");
    const auto pbkdf2 = fam->from_params(NB_ITERATIONS);
    pbkdf2->derive_key(
        stretched_password.data(),
        stretched_password.size(),
        password.data(),
        password.size(),
        salt,
        sizeof(salt)
    );

    // Encrypt the key with the strecthed password
    const auto prv_bytes = this->prv_.bytes();
    auto enc_prv_bytes = std::array<uint8_t, ENCRYPTED_KEY_SIZE>{};
    auto cipher = Botan::StreamCipher::create("ChaCha(20)");
    cipher->set_key(
        {stretched_password.begin(), stretched_password.begin() + SYM_KEY_SIZE}
    );
    cipher->set_iv(stretched_password.data() + SYM_KEY_SIZE, SYM_NONCE_SIZE);
    cipher->cipher(prv_bytes.data(), enc_prv_bytes.data(), ENCRYPTED_KEY_SIZE);

    return BIP32PrivateKeyEncrypted(enc_prv_bytes, this->cc_);
}  // BIP32PrivateKey::encrypt

BIP32PrivateKeyEncrypted::BIP32PrivateKeyEncrypted(
    const std::string& prv,
    const std::string& cc
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

auto BIP32PrivateKeyEncrypted::deriveChild(
    const uint32_t index,
    std::string_view password,
    const DerivationMode derivation_mode
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
            buf.data(),
            buf.size(),
            password.data(),
            password.size(),
            salt,
            sizeof(salt)
        );
        auto cipher = Botan::StreamCipher::create("ChaCha(20)");
        cipher->set_key({buf.begin(), buf.begin() + SYM_KEY_SIZE});
        cipher->set_iv(buf.data() + SYM_KEY_SIZE, SYM_NONCE_SIZE);
        cipher->cipher(prv.data(), prv.data(), prv.size());
    }
    return {prv, cc};
}  // BIP32PrivateKeyEncrypted::decrypt

auto BIP32PrivateKeyEncrypted::toBase16() const -> std::string
{
    const auto bytes = utils::concatBytes(this->xprv_, this->cc_);
    return BASE16::encode(bytes);
}  // BIP32PrivateKeyEncrypted::toBase16

auto BIP32PrivateKeyEncrypted::toExtendedCBOR(std::string_view password) const
    -> std::string
{
    auto pubkey =
        this->toPublic(password).toBytes();  // <- includes the chain code
    auto bytes = utils::concatBytes(this->xprv_, pubkey);
    return BASE16::encode(cppbor::Bstr(bytes).encode());
}  // BIP32PrivateKeyEncrypted::toExtendedCBOR

auto BIP32PrivateKeyEncrypted::sign(
    std::string_view password,
    std::span<const uint8_t> msg
) const -> std::array<uint8_t, ed25519::ED25519_SIGNATURE_SIZE>
{
    auto unenc_key = this->decrypt(password);
    return unenc_key.sign(msg);
}  // BIP32PrivateKeyEncrypted::sign