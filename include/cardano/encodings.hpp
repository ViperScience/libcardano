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

#ifndef _CARDANO_ENCODINGS_HPP_
#define _CARDANO_ENCODINGS_HPP_

#include <span>
#include <string_view>
#include <tuple>
#include <vector>

namespace cardano {

class BASE16
{
  private:
    BASE16() = default;
  public:
    static std::string encode(std::span<const uint8_t> bytes);
    static std::vector<uint8_t> decode(std::string_view str);
}; // BASE16

class BECH32
{
  private:
    BECH32() = default;
  public:
    static std::string encode(std::string_view hrp, std::span<const uint8_t> values);
    static std::string encode_hex(std::string_view hrp, std::string_view hex_values);
    static std::tuple<std::string, std::vector<uint8_t>> decode(std::string_view str);
    static std::tuple<std::string, std::string> decode_hex(std::string_view str);
}; // BECH32

class BASE58
{
  private:
    BASE58() = default;
  public:
    static std::string encode(std::span<const uint8_t> values);
    static std::string encode_hex(std::string_view hex_values);
    static std::vector<uint8_t> decode(std::string_view str);
    static std::string decode_hex(std::string_view str);
}; // BASE58

class CBOR
{
  private:
    CBOR() = default;
  public:
    static auto encodeBytes(std::span<const uint8_t> bytes) -> std::string;
}; // CBOR

} // namespace cardano

#endif // _CARDANO_ENCODINGS_HPP_