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

#ifndef _CARDANO_MNEMONIC_HPP_
#define _CARDANO_MNEMONIC_HPP_

// Standard Library Headers
#include <span>
#include <string_view>
#include <tuple>
#include <vector>

// Public Cardano++ Headers
#include <cardano/bip39_dictionary.hpp>

namespace cardano
{

class Mnemonic
{
  private:
    std::vector<std::string> word_list_;
    std::vector<uint16_t> word_indexes_;
    
    Mnemonic() = default;

  public:

    /// Constructors
    Mnemonic(std::string_view seed_phrase, BIP39Language lang);
    Mnemonic(std::span<std::string_view> seed_phrase, BIP39Language lang);
    Mnemonic(std::span<std::string> seed_phrase, BIP39Language lang);
    Mnemonic(std::span<std::string_view> seed_phrase, 
             std::span<const uint16_t> word_indexes);
    Mnemonic(std::span<std::string> seed_phrase, 
             std::span<const uint16_t> word_indexes);

    /// Factory methods
    static auto generate(size_t mnemonic_size = 24, 
                         BIP39Language lang = BIP39Language::English)
        -> Mnemonic;

    const std::vector<uint16_t>& i() const { return this->word_indexes_; }
    const std::vector<std::string>& w() const { return this->word_list_; }

    /// Utility methods
    auto size() const -> size_t { return word_list_.size(); }
    auto isize() const -> size_t { return word_indexes_.size(); }
    auto checksum() const -> uint8_t;
    auto verify_checksum() const -> bool;
    auto toSeed() const -> std::vector<uint8_t>;
    auto toEntropy() const -> std::tuple<std::vector<uint8_t>, uint8_t>;

}; // Mnemonic

} // namespace cardano

#endif // _CARDANO_MNEMONIC_HPP_