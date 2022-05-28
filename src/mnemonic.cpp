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
constexpr uint16_t WORD_SIZE_BITS = 11;

constexpr auto is_valid_mnemonic_size(size_t sz) -> bool
{
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
                   std::span<const uint16_t> word_indexes)
{
    if (seed_phrase.size() != word_indexes.size())
        throw std::invalid_argument("Words and indexes must match lengths");
    if (!is_valid_mnemonic_size(seed_phrase.size()))
        throw std::invalid_argument("Not a valid mnemonic size");
    this->word_indexes_.assign(word_indexes.begin(), word_indexes.end());
    for (const auto w : seed_phrase)
        this->word_list_.emplace_back(std::string(w.begin(), w.end()));
} // Mnemonic::Mnemonic(std::span<std::string_view>, std::span<uint16_t>)

Mnemonic::Mnemonic(std::span<std::string> seed_phrase, 
                   std::span<const uint16_t> word_indexes)
{
    if (seed_phrase.size() != word_indexes.size())
        throw std::invalid_argument("Words and indexes must match lengths");
    if (!is_valid_mnemonic_size(seed_phrase.size()))
        throw std::invalid_argument("Not a valid mnemonic size");
    for (const auto &i : word_indexes)
        this->word_indexes_.push_back(i);
    for (const auto &w : seed_phrase)
        this->word_list_.push_back(w);
} // Mnemonic::Mnemonic(std::span<std::string>, std::span<uint16_t>)

Mnemonic::Mnemonic(std::span<std::string_view> seed_phrase, 
                   BIP39Language lang)
{
    if (!is_valid_mnemonic_size(seed_phrase.size()))
        throw std::invalid_argument(
            "Mnemonic does not contain a valid number of words.");
    for (const auto w : seed_phrase)
        this->word_list_.push_back(std::string(w));

    // Find the dictionary indexes for each word.
    auto d = BIP39Dictionary::GetDictionary(lang);
    for (const auto &w : this->word_list_)
    {
        for (uint16_t i = 0; i < d.size(); i++)
        {
            if (d[i] == w)
            {
                this->word_indexes_.push_back(i);
                break;
            }
        }
    }
    if (this->word_list_.size() != this->word_indexes_.size())
        throw std::invalid_argument("Words and indexes must match lengths");
} // Mnemonic::Mnemonic(std::span<std::string_view>, BIP39Language lang)

Mnemonic::Mnemonic(std::span<std::string> seed_phrase, 
                   BIP39Language lang)
{
    if (!is_valid_mnemonic_size(seed_phrase.size()))
        throw std::invalid_argument(
            "Mnemonic does not contain a valid number of words.");
    for (const auto &w : seed_phrase)
        this->word_list_.push_back(w);

    // Find the dictionary indexes for each word.
    auto d = BIP39Dictionary::GetDictionary(lang);
    for (const auto &w : this->word_list_)
    {
        for (uint16_t i = 0; i < d.size(); i++)
        {
            if (d[i] == w)
            {
                this->word_indexes_.push_back(i);
                break;
            }
        }
    }
    if (this->word_list_.size() != this->word_indexes_.size())
        throw std::invalid_argument("Words and indexes must match lengths");
} // Mnemonic::Mnemonic(std::span<std::string>, BIP39Language lang)

Mnemonic::Mnemonic(std::string_view seed_phrase, BIP39Language lang)
{
    // Split the given string of words separated by spaces.
    // Note: splitting on space may not work for all languages.
    auto seed = std::string(seed_phrase.begin(), seed_phrase.end());
    auto delim = std::string(" ");
    size_t pos = 0;
    while ((pos = seed.find(delim)) != std::string::npos)
    {
        this->word_list_.push_back(seed.substr(0, pos));
        seed.erase(0, pos + delim.length());
    }
    this->word_list_.push_back(seed);
    if (!is_valid_mnemonic_size(this->word_list_.size()))
        throw std::invalid_argument(
            "Mnemonic does not contain a valid number of words.");
    
    // Find the dictionary indexes for each word.
    auto d = BIP39Dictionary::GetDictionary(lang);
    for (const auto &w : this->word_list_)
    {
        for (uint16_t i = 0; i < d.size(); i++)
        {
            if (d[i] == w)
            {
                this->word_indexes_.push_back(i);
                break;
            }
        }
    }
    if (this->word_list_.size() != this->word_indexes_.size())
        throw std::invalid_argument("Words and indexes must match lengths");
} // Mnemonic::Mnemonic(std::string_view seed_phrase, BIP39Language lang)

auto Mnemonic::generate(size_t mnemonic_size, BIP39Language lang) -> Mnemonic
{
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

    // Seed phrase word indexes 0-2047 (11 bit values).
    size_t ent_idx = 0;
    uint16_t carry_bits = 0, n_carry_bits = 0, n_bits = 0, ent_bits = 0;
    auto indexes = std::vector<uint16_t>(mnemonic_size);
    auto words = std::vector<std::string_view>();
    for (auto i = 0u; i < mnemonic_size; i++) {
        indexes[i] = carry_bits << (WORD_SIZE_BITS - n_carry_bits);
        n_bits = n_carry_bits;

        while (n_bits < WORD_SIZE_BITS) {
            ent_bits = entropy_byte_vector[ent_idx++];
            if (WORD_SIZE_BITS - n_bits >= 8)
                ent_bits <<= WORD_SIZE_BITS - n_bits - 8;
            else
                ent_bits >>= 8 - (WORD_SIZE_BITS - n_bits);
            indexes[i] |= ent_bits;
            n_bits += 8;
        }

        n_carry_bits = n_bits - 11;
        carry_bits = entropy_byte_vector[ent_idx - 1];
        carry_bits &= 255 >> (8 - n_carry_bits);
        indexes[i] &= WORD_INDEX_MASK; // clear any carry bits that were added

        words.push_back(d[indexes[i]]);
    }

    return Mnemonic(words, indexes);
} // Mnemonic::generate

auto Mnemonic::toEntropy() const -> std::tuple<std::vector<uint8_t>, uint8_t>
{
    const auto mnemonic_size = this->word_indexes_.size();
    if (!is_valid_mnemonic_size(mnemonic_size))
        throw std::invalid_argument("Not a valid mnemonic size");
    const auto checksum_size_bits = mnemonic_size/3;
    const auto entropy_size_bytes = checksum_size_bits*4;

    // Iterate through the seed phrase word indexes (11 bit words) packing the
    // entropy bits into a byte (8 bit) vector. The entropy checksum will then
    // be recalculated and verified with the current checksum.
    auto ent_idx = 0UL;
    uint8_t carry_bits = 0, n_carry_bits = 0, n_bits_remain, n_bits_packed;
    auto entropy_byte_vector = std::vector<uint8_t>(entropy_size_bytes);
    for (const auto widx : this->word_indexes_) {
        auto word_index = widx & WORD_INDEX_MASK; // Use the mask to be safe

        // Fist add any bits from the last index that were not packed into a
        // byte. These are the most significant bits.
        entropy_byte_vector[ent_idx] = carry_bits << (8 - n_carry_bits);

        // Finish filling the entropy byte with bits from the current mnemonic
        // word index. This byte will always be full at this point so increment
        // the entropy vector index.
        entropy_byte_vector[ent_idx++] |= widx >> (3 + n_carry_bits);

        // If there are 8-bits remaining in the 11-bit word, pack them into the
        // next entropy byte. Unless the entropy byte vector is full, in that
        // case the remaining bits are the checksum.
        n_bits_packed = 8 - n_carry_bits;
        n_bits_remain = 11 - n_bits_packed;
        if ((ent_idx < entropy_size_bytes) && (n_bits_remain >= 8)) {
            entropy_byte_vector[ent_idx] = 0;
            entropy_byte_vector[ent_idx] |= word_index >> (n_bits_remain - 8);
            n_bits_remain -= 8;
            ent_idx++;
        }

        // Any remaining bits are carried over to start packing the next
        // entropy byte. If the entropy byte vector is full, the carry bits are
        // the checksum.
        n_carry_bits = n_bits_remain;
        carry_bits = word_index & (65535 >> (16 - n_bits_remain));
    }

    return std::make_tuple(entropy_byte_vector, (uint8_t)carry_bits);
} // Mnemonic::toEntropy

auto Mnemonic::checksum() const -> uint8_t
{
    auto [ entropy_byte_vector, cs ] = this->toEntropy();
    return cs;
} // Mnemonic::checksum

auto Mnemonic::verify_checksum() const -> bool
{
    const auto mnemonic_size = this->word_indexes_.size();
    if (!is_valid_mnemonic_size(mnemonic_size))
        throw std::invalid_argument("Not a valid mnemonic size");
    const auto checksum_size_bits = mnemonic_size/3;
    const auto entropy_size_bytes = checksum_size_bits*4;

    // Convert the mnemonic word indexes back to the entropy.
    auto [ entropy_byte_vector, old_checksum ] = this->toEntropy();

    // The checksum is the first few bits of the SHA-256 hash.
    auto sha256 = Botan::HashFunction::create("SHA-256");
    sha256->update(entropy_byte_vector.data(), entropy_byte_vector.size());
    auto hashed_entropy = sha256->final(); // <- std::vector
    auto nshift = 8 - checksum_size_bits;
    auto new_checksum = (hashed_entropy[0] & (255 << nshift)) >> nshift;

    return new_checksum == old_checksum;
} // Mnemonic::verify_checksum

auto Mnemonic::toSeed() const -> std::vector<uint8_t>
{
    auto [ entropy_byte_vector, cs ] = this->toEntropy();
    return entropy_byte_vector;
} // Mnemonic::getEntropy