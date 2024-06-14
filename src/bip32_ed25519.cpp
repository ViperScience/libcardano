// Copyright (c) 2024 Viper Science LLC
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

// Third-Party Library Headers
#include <botan/auto_rng.h>
#include <botan/hash.h>
#include <botan/mac.h>
#include <botan/pbkdf2.h>
#include <botan/pwdhash.h>
#include <botan/rng.h>
#include <botan/stream_cipher.h>
#include <botan/system_rng.h>
#include <cppbor/cppbor.h>
#include <cryptopp/donna.h>

// Public libcardano headers
#include <cardano/bip32_ed25519.hpp>
#include <cardano/util.hpp>

using namespace cardano;
using namespace cardano::bip32_ed25519;
using namespace std::string_view_literals;

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

    return util::concatBytes(prv, iR);
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
static constexpr size_t SYM_BUF_SIZE = SYM_KEY_SIZE + SYM_NONCE_SIZE;

PublicKey::PublicKey(std::span<const uint8_t, XPUBLIC_KEY_SIZE> pub)
{
    std::copy_n(pub.begin(), PUBLIC_KEY_SIZE, this->pub_.begin());
    std::copy_n(
        pub.begin() + PUBLIC_KEY_SIZE, CHAIN_CODE_SIZE, this->cc_.begin()
    );
}  // PublicKey::PublicKey

PublicKey::PublicKey(
    std::span<const uint8_t, PUBLIC_KEY_SIZE> pub,
    std::span<const uint8_t, CHAIN_CODE_SIZE> cc
)
{
    std::ranges::copy(
        pub | std::views::take(PUBLIC_KEY_SIZE), this->pub_.begin()
    );
    std::ranges::copy(
        cc | std::views::take(CHAIN_CODE_SIZE), this->cc_.begin()
    );
}  // PublicKey::PublicKey

auto PublicKey::xbytes() const -> ByteArray<XPUBLIC_KEY_SIZE>
{
    auto xkey_bytes = ByteArray<XPUBLIC_KEY_SIZE>();
    std::copy_n(this->pub_.data(), PUBLIC_KEY_SIZE, xkey_bytes.begin());
    std::copy_n(
        this->cc_.data(), CHAIN_CODE_SIZE, xkey_bytes.begin() + PUBLIC_KEY_SIZE
    );
    return xkey_bytes;
}  // PrivateKey::xbytes

auto PublicKey::verifySignature(
    std::span<const uint8_t> msg,
    std::span<const uint8_t, SIGNATURE_SIZE> sig
) const -> bool
{
    return CryptoPP::Donna::ed25519_sign_open(
               msg.data(), msg.size(), this->pub_.data(), sig.data()
           ) == 0;
}  // PublicKey::verifySignature

auto PublicKey::deriveChild(const uint32_t index, const DerivationMode mode)
    const -> PublicKey
{
    if (index_is_hardened(index)) throw std::exception();

    auto idxBuf = serialize_index32(index, mode);

    /* calculate Z */
    const auto mac = Botan::MessageAuthenticationCode::create("HMAC(SHA-512)");
    if (!mac) throw std::runtime_error("Unable to create HMAC object.");
    mac->set_key(this->cc_.data(), this->cc_.size());
    mac->update(TAG_DERIVE_Z_NORMAL);
    mac->update(this->pub_.data(), this->pub_.size());
    mac->update(idxBuf.data(), idxBuf.size());
    const auto z = mac->final();

    // calculate 8 * Zl
    auto zl8 = ByteArray<64>{};
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

    auto pub_new = ByteArray<32>();
    CryptoPP::Donna::bip32_ed25519_publickey(pub_new.data(), zl8.data());
    CryptoPP::Donna::bip32_ed25519_point_add(
        pub_new.data(), this->pub_.data(), pub_new.data()
    );

    // calculate the new chain code
    mac->set_key(this->cc_.data(), this->cc_.size());
    mac->update(TAG_DERIVE_CC_NORMAL);
    mac->update(this->pub_.data(), this->pub_.size());
    mac->update(idxBuf.data(), idxBuf.size());
    const auto hmac_out = mac->final();

    // The upper half is the new chain code
    auto cc_new = std::array<uint8_t, 32>();
    std::copy_n(hmac_out.begin() + 32, 32, cc_new.begin());

    return PublicKey(pub_new, cc_new);
}  // PublicKey::deriveChild

PrivateKey::PrivateKey(std::span<const uint8_t, XKEY_SIZE> prv)
{
    std::ranges::move(prv | std::views::take(KEY_SIZE), this->prv_.begin());
    std::copy_n(prv.begin() + KEY_SIZE, CHAIN_CODE_SIZE, this->cc_.begin());
}  // PrivateKey::PrivateKey

PrivateKey::PrivateKey(
    std::span<const uint8_t, KEY_SIZE> prv,
    std::span<const uint8_t, CHAIN_CODE_SIZE> cc
)
{
    std::ranges::move(prv | std::views::take(KEY_SIZE), this->prv_.begin());
    std::ranges::move(
        cc | std::views::take(CHAIN_CODE_SIZE), this->cc_.begin()
    );
}  // PublicKey::PublicKey

auto PrivateKey::generate() -> PrivateKey
{
    // Use the Botan random number generator for generating the entropy.
    std::unique_ptr<Botan::RandomNumberGenerator> rng;
#if defined(BOTAN_HAS_SYSTEM_RNG)
    rng.reset(new Botan::System_RNG);
#else
    rng.reset(new Botan::AutoSeeded_RNG);
#endif

    auto seed = SecureByteArray<SEED_SIZE>();
    rng->randomize(seed.data(), SEED_SIZE);

    auto mac = Botan::MessageAuthenticationCode::create("HMAC(SHA-512)");
    const auto pbkdf2 = std::make_unique<Botan::PBKDF2>(*mac.release(), 4096);
    static constexpr auto passphrase = ""sv;
    auto key = SecureByteArray<XKEY_SIZE>();
    pbkdf2->derive_key(
        key.data(),
        key.size(),
        passphrase.data(),
        passphrase.size(),
        seed.data(),
        seed.size()
    );
    tweak_bits_icarus(key);

    return PrivateKey(key);
}  // PrivateKey::generate

auto PrivateKey::fromSeed(std::span<const uint8_t, SEED_SIZE> seed) -> PrivateKey
{
    auto key = SecureByteArray<KEY_SIZE>();
    CryptoPP::Donna::bip32_ed25519_extend(key.data(), seed.data());

    // Calculate the chain code
    auto cc = ByteArray<CHAIN_CODE_SIZE>();
    const auto hasher = Botan::HashFunction::create_or_throw("SHA-256");
    hasher->update(1);
    hasher->update(seed);
    hasher->final(cc);

    return PrivateKey(key, cc);
} //  PrivateKey::fromSeed

auto PrivateKey::fromMnemonic(
    const cardano::Mnemonic& mn,
    std::string_view passphrase
) -> PrivateKey
{
    auto mac = Botan::MessageAuthenticationCode::create("HMAC(SHA-512)");
    const auto pbkdf2 = std::make_unique<Botan::PBKDF2>(*mac.release(), 4096);
    const auto seed = mn.toSeed();
    auto key = ByteArray<XKEY_SIZE>();
    pbkdf2->derive_key(
        key.data(),
        key.size(),
        passphrase.data(),
        passphrase.size(),
        seed.data(),
        seed.size()
    );
    tweak_bits_icarus(key);
    return PrivateKey(std::span<uint8_t, XKEY_SIZE>(key).first<XKEY_SIZE>());
}

auto PrivateKey::fromMnemonic(const Mnemonic& mn) -> PrivateKey
{
    return PrivateKey::fromMnemonic(mn, "");
}

auto PrivateKey::fromMnemonicByron(const Mnemonic& mn) -> PrivateKey
{
    const auto hashed_seed = hash_seed(mn.toSeed());
    auto key = hash_repeatedly(hashed_seed, 1);
    return PrivateKey(std::span<uint8_t, XKEY_SIZE>(key).first<XKEY_SIZE>());
}

auto PrivateKey::xbytes() const -> SecureByteArray<XKEY_SIZE>
{
    auto xkey_bytes = SecureByteArray<XKEY_SIZE>();
    std::copy_n(this->prv_.data(), KEY_SIZE, xkey_bytes.begin());
    std::copy_n(
        this->cc_.data(), CHAIN_CODE_SIZE, xkey_bytes.begin() + KEY_SIZE
    );
    return xkey_bytes;
}  // PrivateKey::xbytes

auto PrivateKey::publicKey() const -> PublicKey
{
    auto pkey_bytes = ByteArray<PUBLIC_KEY_SIZE>();
    CryptoPP::Donna::bip32_ed25519_publickey(
        pkey_bytes.data(), this->prv_.data()
    );
    return PublicKey(pkey_bytes, this->cc_);
}  // PrivateKey::publicKey

auto PrivateKey::sign(std::span<const uint8_t> msg
) const -> ByteArray<SIGNATURE_SIZE>
{
    auto sig = ByteArray<SIGNATURE_SIZE>();
    CryptoPP::Donna::bip32_ed25519_sign(
        msg.data(),
        msg.size(),
        this->prv_.data(),
        this->publicKey().bytes().data(),
        sig.data()
    );
    return sig;
}

auto PrivateKey::deriveChild(const uint32_t index, const DerivationMode mode)
    const -> PrivateKey
{
    const auto pkey_bytes = this->publicKey().bytes();
    const auto skey_bytes = this->prv_;
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
    auto res_key = ByteArray<64>{};
    auto zl8 = ByteArray<64>{};
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
            CryptoPP::Donna::bip32_ed25519_scalar_add(
                zl8.data(), this->prv_.data(), res_key.data()
            );

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
}  // PrivateKey::deriveChild

auto PrivateKey::encrypt(std::string_view password) const -> EncryptedPrivateKey
{
    if (password.empty()) return EncryptedPrivateKey(this->prv_, this->cc_);

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
    auto enc_prv_bytes = std::array<uint8_t, KEY_SIZE>{};
    auto cipher = Botan::StreamCipher::create("ChaCha(20)");
    cipher->set_key(
        {stretched_password.begin(), stretched_password.begin() + SYM_KEY_SIZE}
    );
    cipher->set_iv(stretched_password.data() + SYM_KEY_SIZE, SYM_NONCE_SIZE);
    cipher->cipher(this->prv_.data(), enc_prv_bytes.data(), KEY_SIZE);

    return EncryptedPrivateKey(enc_prv_bytes, this->cc_);
}  // PrivateKey::encrypt

EncryptedPrivateKey::EncryptedPrivateKey(
    std::span<const uint8_t, XKEY_SIZE> encxkey
)
{
    std::copy_n(encxkey.begin(), KEY_SIZE, this->prv_.begin());
    std::copy_n(encxkey.begin() + KEY_SIZE, CHAIN_CODE_SIZE, this->cc_.begin());
}  // EncryptedPrivateKey::EncryptedPrivateKey

EncryptedPrivateKey::EncryptedPrivateKey(
    std::span<const uint8_t, KEY_SIZE> prv,
    std::span<const uint8_t, CHAIN_CODE_SIZE> cc
)
{
    std::ranges::copy(prv | std::views::take(KEY_SIZE), this->prv_.begin());
    std::ranges::copy(
        cc | std::views::take(CHAIN_CODE_SIZE), this->cc_.begin()
    );
}  // EncryptedPrivateKey::EncryptedPrivateKey

auto EncryptedPrivateKey::decrypt(std::string_view password) -> PrivateKey
{
    // This is the password encryption used in Daedalus.
    auto cc = std::array<uint8_t, CHAIN_CODE_SIZE>(this->cc_);
    auto prv = std::array<uint8_t, KEY_SIZE>(this->prv_);
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
}  // EncryptedPrivateKey::decrypt
