// Copyright (c) 2022 Viper Science LLC
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
#include <cmath>
#include <exception>
#include <memory>
#include <span>

// Third Party Library Headers
#include <botan/auto_rng.h>
#include <botan/hash.h>
#include <botan/rng.h>
#include <botan/system_rng.h>

// Public Cardano++ Headers 
#include <cardano/mnemonic.hpp>

using namespace cardano;

constexpr uint16_t WORD_INDEX_MASK = 0b0000011111111111;

constexpr auto is_valid_mnemonic_size(size_t sz) -> bool {
    switch (sz) {
      case 9:
      case 12:
      case 15:
      case 18:
      case 21:
      case 24:
        break;
      default:
        return false;
    }
    return true;
} // is_valid_mnemonic_size

Mnemonic::Mnemonic(std::span<std::string_view> seed_phrase, 
                   std::span<const uint16_t> word_indexes) {
    if (seed_phrase.size() != word_indexes.size())
        throw std::invalid_argument("Words and indexes must match lengths");
    if (!is_valid_mnemonic_size(seed_phrase.size()))
        throw std::invalid_argument("Not a valid mnemonic size");
    this->word_indexes_.assign(word_indexes.begin(), word_indexes.end());
    for (const auto w : seed_phrase)
        this->word_list_.emplace_back(std::string(w.begin(), w.end()));
} // Mnemonic::Mnemonic(std::span<std::string_view>, std::span<uint16_t>)

Mnemonic::Mnemonic(std::span<std::string> seed_phrase, 
                   std::span<const uint16_t> word_indexes) {
    if (seed_phrase.size() != word_indexes.size())
        throw std::invalid_argument("Words and indexes must match lengths");
    if (!is_valid_mnemonic_size(seed_phrase.size()))
        throw std::invalid_argument("Not a valid mnemonic size");
    this->word_indexes_.assign(word_indexes.begin(), word_indexes.end());
    for (const auto &w : seed_phrase)
        this->word_list_.push_back(w);
} // Mnemonic::Mnemonic(std::span<std::string>, std::span<uint16_t>)

Mnemonic::Mnemonic(std::span<std::string_view> seed_phrase, 
                   BIP39Language lang) {
    auto d = BIP39Dictionary::GetDictionary(lang);
    std::vector<uint16_t> indexes;
    for (const auto w : seed_phrase)    
        for (uint16_t i = 0; i < d.size(); i++) {
            if (d[i] == w) {
                indexes.push_back(i);
                break;
            }
            std::invalid_argument("Not a valid BIP39 mnemonic sentence.");
        }
    Mnemonic(seed_phrase, indexes);
} // Mnemonic::Mnemonic(std::span<std::string_view>, BIP39Language lang)

Mnemonic::Mnemonic(std::span<std::string> seed_phrase, 
                   BIP39Language lang) {
    auto d = BIP39Dictionary::GetDictionary(lang);
    std::vector<uint16_t> indexes;
    for (const auto &w : seed_phrase)    
        for (uint16_t i = 0; i < d.size(); i++) {
            if (d[i] == w) {
                indexes.push_back(i);
                break;
            }
            std::invalid_argument("Not a valid BIP39 mnemonic sentence.");
        }
    Mnemonic(seed_phrase, indexes);
} // Mnemonic::Mnemonic(std::span<std::string>, BIP39Language lang)

Mnemonic::Mnemonic(std::string_view seed_phrase, BIP39Language lang) {
    // Note: splitting on space may not work for all languages.
    auto seed = std::string(seed_phrase.begin(), seed_phrase.end());
    auto words = std::vector<std::string>{};
    auto delim = std::string(" ");
    size_t pos = 0;
    while ((pos = seed.find(delim)) != std::string::npos) {
        words.push_back(seed.substr(0, pos));
        seed.erase(0, pos + delim.length());
    }
    words.push_back(seed);
    Mnemonic(words, lang);
} // Mnemonic::Mnemonic(std::string_view seed_phrase, BIP39Language lang)

auto Mnemonic::generate(size_t mnemonic_size, BIP39Language lang) -> Mnemonic {

    // Verify the Mnemonic size is supported.
    if (!is_valid_mnemonic_size(mnemonic_size))
        throw std::invalid_argument("Not a valid mnemonic size");

    // CS = ENT / 32
    // MS = (ENT + CS) / 11
    //
    // |  ENT  | CS | ENT+CS |  MS  |
    // +-------+----+--------+------+
    // |  128  |  4 |   132  |  12  |
    // |  160  |  5 |   165  |  15  |
    // |  192  |  6 |   198  |  18  |
    // |  224  |  7 |   231  |  21  |
    // |  256  |  8 |   264  |  24  |
    const size_t checksum_size_bits = mnemonic_size/3;
    const size_t entropy_size_bits = checksum_size_bits*32;
    const size_t entropy_size_bytes = checksum_size_bits*4;

    // Use the Botan random number generator for generating the entropy.
    std::unique_ptr<Botan::RandomNumberGenerator> rng;
    #if defined(BOTAN_HAS_SYSTEM_RNG)
    rng.reset(new Botan::System_RNG);
    #else
    rng.reset(new Botan::AutoSeeded_RNG);
    #endif

    // Create the entropy
    auto entropy_byte_vector = std::vector<uint8_t>(entropy_size_bytes);
    rng->randomize(entropy_byte_vector.data(), entropy_size_bytes);

    // The check sum is the first few bits of the SHA-256 hash.
    auto sha256 = Botan::HashFunction::create("SHA-256");
    sha256->update(entropy_byte_vector.data(), entropy_byte_vector.size());
    auto hashed_entropy = sha256->final(); // <- std::vector

    // Add the checksum byte(s) to the end of the entropy vector.
    for (auto i = 0ul; i < std::ceil(checksum_size_bits/(float)8); i++)
        entropy_byte_vector.push_back(hashed_entropy[i]);
    
    // Use the dictionary for the specified language.
    auto d = BIP39Dictionary::GetDictionary(lang);

    // Seed phrase word indexes (11 bit values)
    size_t ent_idx = 0;
    uint16_t carry_bits = 0, n_carry_bits = 0, n_bits = 0;
    auto indexes = std::vector<uint16_t>(mnemonic_size);
    auto words = std::vector<std::string_view>();
    for (auto i = 0u; i < mnemonic_size; i++) {
        indexes[i] = carry_bits;
        n_bits = n_carry_bits;

        while (n_bits < 11) {
            indexes[i] |= ((uint16_t)entropy_byte_vector[ent_idx++]) << n_bits;
            n_bits += 8;
        }

        n_carry_bits = n_bits - 11;
        carry_bits = entropy_byte_vector[ent_idx - 1] >> (8 - n_carry_bits);
        indexes[i] &= WORD_INDEX_MASK; // clear any carry bits that were added

        words.push_back(d[indexes[i]]);
    }

    // TODO Much of the above could be replaced with treating the entropy as a 
    // continuous memory block and grabing out the 11 bits at a time.

    return Mnemonic(words, indexes);
} // Mnemonic::generate

auto Mnemonic::verify_checksum() -> bool {
    const auto mnemonic_size = this->word_indexes_.size();
    if (!is_valid_mnemonic_size(mnemonic_size))
        throw std::invalid_argument("Not a valid mnemonic size");
    const auto checksum_size_bits = mnemonic_size/3;
    const auto entropy_size_bytes = checksum_size_bits*4;
    const uint8_t checksum_mask = 0b11111111 >> (8 - checksum_size_bits);

    // Iterate through the seed phrase word indexes (11 bit words) packing the
    // entropy bits into a byte (8 bit) vector. The entropy checksum will then
    // be recalculated and verified with the current checksum.
    auto ent_idx = 0UL;
    uint8_t carry_bits = 0, n_carry_bits = 0, n_bits_remaining, n_bits_packed;
    auto entropy_byte_vector = std::vector<uint8_t>(entropy_size_bytes);
    for (const auto widx : this->word_indexes_) {
        auto word_index = widx & WORD_INDEX_MASK; // Use the mask to be safe

        // Fist add any bits from the last index that were not packed into a
        // byte.
        entropy_byte_vector[ent_idx] = carry_bits;

        // Finish filling the entropy byte with bits from the current mnemonic
        // word index. This byte will always be full at this point so increment
        // the entropy vector index.
        entropy_byte_vector[ent_idx] |= widx << n_carry_bits;
        ent_idx++;

        // If there are 8-bits remaining in the 11-bit word, pack them into the
        // next entropy byte. Unless, the entropy byte vector is full, in which
        // case the remaining bits are the checksum.
        n_bits_packed = 8 - n_carry_bits;
        n_bits_remaining = 11 - n_bits_packed;
        if (ent_idx < entropy_size_bytes) {
            if (n_bits_remaining >= 8) {
                entropy_byte_vector[ent_idx] = 0;
                entropy_byte_vector[ent_idx] |= word_index >> n_bits_packed;
                n_bits_remaining -= 8;
                ent_idx++;
            }
        }

        // Any remaining bits are carried over to start packing the next
        // entropy byte. If the entropy byte vector is full, the carry bits are
        // the checksum.
        n_carry_bits = n_bits_remaining;
        carry_bits = word_index >> (11 - n_bits_remaining);
    }
    auto old_checksum = carry_bits;

    // The check sum is the first few bits of the SHA-256 hash.
    auto sha256 = Botan::HashFunction::create("SHA-256");
    sha256->update(entropy_byte_vector.data(), entropy_byte_vector.size());
    auto hashed_entropy = sha256->final(); // <- std::vector
    auto new_checksum = hashed_entropy[0] & checksum_mask;

    return new_checksum == old_checksum;
} // Mnemonic::verify_checksum