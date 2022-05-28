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

#ifndef _CARDANO_CRYPTO_HPP_
#define _CARDANO_CRYPTO_HPP_

#include <array>
#include <cstdint>
#include <string>
#include <vector>

#include <cardano/mnemonic.hpp>

namespace cardano {

static constexpr uint32_t SECRET_KEY_SEED_SIZE = 32;
static constexpr uint32_t ENCRYPTED_KEY_SIZE = 64;
static constexpr uint32_t PUBLIC_KEY_SIZE = 32;
static constexpr uint32_t CHAIN_CODE_SIZE = 32;

static constexpr uint32_t HardenIndex(uint32_t index) {
    if (index < 0x80000000)
        return index + 0x80000000;
    return index;
}

// Forward Declarations
class BIP32PublicKey;
class BIP32PrivateKey;
class BIP32PrivateKeyEncrypted;

class BIP32PublicKey {
  private:
    std::array<uint8_t, PUBLIC_KEY_SIZE> pub_{}; // Public key hex (unencrypted)
    std::array<uint8_t, CHAIN_CODE_SIZE> cc_{};  // Chain code hex (unencrypted)
    BIP32PublicKey() = default;

  public:
    BIP32PublicKey(std::string_view xpub);
    BIP32PublicKey(const std::string& pub, const std::string& cc);
    constexpr BIP32PublicKey(std::array<uint8_t, PUBLIC_KEY_SIZE> pub,
                             std::array<uint8_t, CHAIN_CODE_SIZE> cc)
        : pub_{std::move(pub)}, cc_{std::move(cc)} {}

    /// Static factory method
    static auto fromBech32(std::string bech32_str) -> BIP32PublicKey;

    // Key accessor
    const std::array<uint8_t, PUBLIC_KEY_SIZE> &pkey = pub_;

    /// Access methods
    auto toBech32(std::string_view hrp) const -> std::string;
    auto toBase16() const -> std::string;
    auto toBytes(bool with_cc = true) const -> std::vector<uint8_t>;

    /// Mutation methods
    auto deriveChild(uint32_t index, uint32_t derivation_mode = 2) const 
        -> BIP32PublicKey;
}; // BIP32PublicKey

class BIP32PrivateKey {
  private:
    // Private key hex (unencrypted)
    std::array<uint8_t, ENCRYPTED_KEY_SIZE> prv_{};
    // Chain code hex (unencrypted)
    std::array<uint8_t, CHAIN_CODE_SIZE> cc_{};
    // keep the default contructor private
    BIP32PrivateKey() = default;
    bool clear();

  public:
    constexpr BIP32PrivateKey(std::array<uint8_t, ENCRYPTED_KEY_SIZE> priv,
                              std::array<uint8_t, CHAIN_CODE_SIZE> cc)
        : prv_{std::move(priv)}, cc_{std::move(cc)} {}
    BIP32PrivateKey(std::span<const uint8_t> xpriv); // prv + cc
    BIP32PrivateKey(std::string_view xpriv); // prv + cc 
    BIP32PrivateKey(const std::string& prv, const std::string& cc);
    ~BIP32PrivateKey() { this->clear(); }

    /// Factory methods
    static auto fromBech32(std::string_view bech32_str) -> BIP32PrivateKey;
    static auto fromMnemonic(const cardano::Mnemonic& mn) -> BIP32PrivateKey;
    static auto fromMnemonicByron(const cardano::Mnemonic& mn)
        -> BIP32PrivateKey;
    static auto fromMnemonic(const cardano::Mnemonic& mn,
                             std::string_view passphrase) -> BIP32PrivateKey;
    // static BIP32PrivateKey fromCBOR(std::string bech32); // TODO

    /// Access methods
    auto toBech32(std::string_view hrp) const -> std::string;
    auto toBase16() const -> std::string;
    // auto toCBOR(std::string hrp) const -> std::string;

    /// Conversion methods
    auto toPublic() const -> BIP32PublicKey;
    auto deriveChild(uint32_t index, uint32_t derivation_mode = 2) const
        -> BIP32PrivateKey;
    auto encrypt(std::string_view password) -> BIP32PrivateKeyEncrypted;
}; // BIP32PrivateKey

class BIP32PrivateKeyEncrypted {
  private:
    // Private key bytes (encrypted)
    std::array<uint8_t, ENCRYPTED_KEY_SIZE> xprv_{};
    // Chain code bytes (unencrypted)
    std::array<uint8_t, CHAIN_CODE_SIZE> cc_{};

    BIP32PrivateKeyEncrypted() = default;

  public:
    constexpr BIP32PrivateKeyEncrypted(
        std::array<uint8_t, ENCRYPTED_KEY_SIZE> prv,
        std::array<uint8_t, CHAIN_CODE_SIZE> cc)
        : xprv_{std::move(prv)}, cc_{std::move(cc)} {}
    BIP32PrivateKeyEncrypted(const std::string& prv_enc, const std::string& cc);
    BIP32PrivateKeyEncrypted(std::string_view xprv_enc);

    /// Access methods
    auto toBase16() const -> std::string;

    /// Conversion methods
    auto deriveChild(uint32_t index, std::string_view password, 
                     uint32_t derivation_mode = 2) const
        -> BIP32PrivateKeyEncrypted;
    auto toPublic(std::string_view password) const -> BIP32PublicKey;
    auto decrypt(std::string_view password) const -> BIP32PrivateKey;
}; // BIP32PrivateKeyEncrypted

} // namespace cardano

#endif // _CARDANO_CRYPTO_HPP_