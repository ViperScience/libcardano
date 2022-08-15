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

#include <memory>
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
    constexpr CBOR() = default;
    inline ~CBOR() = default;

  public:

    /// API for CBOR encoding complex data structures. All working buffers are
    /// allocated on the heap.
    class Encoder
    {
      public:
        /// Prefered constructor. Sets the size of the working buffer.
        Encoder(const size_t buff_size);

        /// Default constructor. Working buffer defaults to 256 bytes.
        Encoder() : Encoder(256) {};

        /// Destructor
        inline ~Encoder() = default;

        /// Factory method: returns a new CBOR::Encoder with an opened array.
        static auto newArray(const size_t buff_size = 256) -> Encoder;

        /// Factory method: returns a new CBOR::Encoder with an opened array of
        /// indefinite length.
        static auto newIndefArray(const size_t buff_size = 256) -> Encoder;

        /// Factory method: returns a new CBOR::Encoder with an opened map.
        static auto newMap(const size_t buff_size = 256) -> Encoder;

        /// Factory method: returns a new CBOR::Encoder with an opened array of
        /// indefinite length.
        static auto newIndefMap(const size_t buff_size = 256) -> Encoder;

        /// Start a finite array. Must be eventually followed by endArray.
        auto startArray() -> void;

        /// Close an open array. Signals the end of adding data to the array.
        auto endArray() -> void;

        /// Open a indefinite array. Must be eventually followed by 
        /// endIndefiniteArray.
        auto startIndefArray() -> void;

        /// Close an open indefinite array. Signals the end of adding data to
        /// the array.
        auto endIndefArray() -> void;

        /// Start a finite map. Must be eventually followed by endMap.
        auto startMap() -> void;

        /// Close an open map. Signals the end of adding data to the map.
        auto endMap() -> void;

        /// Start an indefinite map. Must be eventually followed by endIndefMap.
        auto startIndefMap() -> void;

        /// Close an open indefinite map. Signals the end of adding data to the
        /// indefinite map.
        auto endIndefMap() -> void;

        /// NOTE: Method overloading is used extensively by this API. 
        /// Overloading is prefered by the C++ runtime to template 
        /// specialization. Furthermore, having few distinct method names 
        /// results in an API that simpler for the end user.

        /// Add an integer item to the CBOR data structure.
        auto add(int64_t v) -> void;

        /// Add a byte string item to the CBOR data structure.
        auto add(std::span<const uint8_t> v) -> void;

        /// Add previously encoded CBOR bytes to the structure.
        auto addEncoded(std::span<const uint8_t> v) -> void;

        /// Add tagged bytes to the CBOR structure.
        auto addTagged(int64_t t, std::span<const uint8_t> v) -> void;

        /// Add an integer value to a CBOR map with a string key.
        auto addToMap(std::string_view k, int64_t v) -> void;

        /// Add a byte string value to a CBOR map with a string key.
        auto addToMap(std::string_view k, std::span<const uint8_t> v) -> void;

        /// Add an integer value to a CBOR map with an integer key.
        auto addToMap(int64_t k, int64_t v) -> void;

        /// Add a byte string value to a CBOR map with an integer key.
        auto addToMap(int64_t k, std::span<const uint8_t> v) -> void;

        /// Serialize the CBOR object to bytes allocated on the heap. Return a 
        /// smart pointer to the heap allocated vector.
        auto serialize() -> std::vector<uint8_t>;

      private:
        // Smart pointers to a generic data type (void) are used to 
        // intentionally separate the interface (header file) from the 
        // implementation. This way, in the event that a different CBOR backend
        // is used, only the implementation source code will need recompilation.
        std::shared_ptr<void> _cbor_ctx;
        std::shared_ptr<void> _cbor_buf;
    }; // Encoder

    /// API for CBOR decoding complex data structures. All working buffers are
    /// allocated on the heap.
    class Decoder
    {
      public:
        /// Prefered constructor. Provide the data to decode as bytes.
        Decoder(std::span<const uint8_t> data);
        inline ~Decoder() = default;

        static auto fromArrayData(std::span<const uint8_t> data) -> Decoder;

        static auto fromMapData(std::span<const uint8_t> data) -> Decoder;

        auto enterArray() -> void;
        auto exitArray() -> void;
        auto enterMap() -> void;
        auto exitMap() -> void;

        auto getSkip() -> void;
        auto getInt() -> int64_t;
        auto getTaggedCborBytes() -> std::vector<uint8_t>;

      private:
        // Smart pointers to a generic data type (void) are used to 
        // intentionally separate the interface (header file) from the 
        // implementation. This way, in the event that a different CBOR backend
        // is used, only the implementation source code will need recompilation.
        std::shared_ptr<void> _cbor_ctx;
        std::shared_ptr<void> _cbor_itm;
    }; // Decoder

    /// Static methods for encoding and decoding objects.
    /// These methods use stack memory.

    /// Static method to CBOR encode a byte string.
    static auto encode(std::span<const uint8_t> b) -> std::vector<uint8_t>;

    /// Static method to CBOR encode an unsigned integer.
    static auto encode(uint64_t v) -> std::vector<uint8_t>;
    
}; // CBOR

} // namespace cardano

#endif // _CARDANO_ENCODINGS_HPP_