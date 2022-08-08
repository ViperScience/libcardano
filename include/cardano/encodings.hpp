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
    
    // This is a generic pointer that can be used to point to the data object 
    // used by the underlying CBOR implementation. It is intentionally kept 
    // general in order to completely separate the interface (header file) from
    // the implementation. This way, in the event that a different CBOR backend
    // it used, nothing else but that source code will need recompilation.
    void* _cbor_context;

  public:
    CBOR() : CBOR(256) {};
    CBOR(const size_t buff_size);
    ~CBOR();

    // Static factory methods
    static auto newArray() -> CBOR;
    static auto newIndefiniteArray() -> CBOR;
    static auto newMap() -> CBOR;
    static auto newIndefiniteMap() -> CBOR;

    // Encoding //

    auto startArray() -> void;
    auto endArray() -> void;

    auto startIndefiniteArray() -> void;
    auto endIndefiniteArray() -> void;

    auto startMap() -> void;
    auto endMap() -> void;

    /// Add an item to the CBOR data structure.
    auto add(int64_t v) -> void;
    auto add(uint64_t v) -> void;
    auto add(std::span<const uint8_t> v) -> void;

    auto addEncoded(std::span<const uint8_t> v) -> void;

    auto addTagged(uint64_t t, std::span<const uint8_t> v) -> void;

    /// Add an item to a CBOR map (key-value pair)
    auto addToMap(std::string_view k, int64_t v) -> void;
    auto addToMap(std::string_view k, uint64_t v) -> void;
    auto addToMap(std::string_view key, std::span<const uint8_t> v) -> void;
    auto addToMap(int64_t k, int64_t v) -> void;
    auto addToMap(int64_t k, uint64_t v) -> void;
    auto addToMap(int64_t k, std::span<const uint8_t> v) -> void;

    auto serializeToBytes() -> std::vector<uint8_t>;
    auto serializeToString() -> std::string;

    /// Static method to CBOR encode a byte string.
    static auto encode(std::span<const uint8_t> b) -> std::vector<uint8_t>;
    static auto encode(uint64_t v) -> std::vector<uint8_t>;

    // Decoding //

    
}; // CBOR

} // namespace cardano

#endif // _CARDANO_ENCODINGS_HPP_