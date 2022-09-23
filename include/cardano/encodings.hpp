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
#include <utility>
#include <vector>

namespace cardano {

class BASE16
{
  private:
    /// The constructor should remain private since this is a static class.
    BASE16() = default;
  public:
    // what endianess?
    static auto encode(std::span<const uint8_t> bytes) -> std::string;
    static auto decode(std::string_view str) -> std::vector<uint8_t>;
}; // BASE16

class BECH32
{
  private:
    /// The constructor should remain private since this is a static class.
    BECH32() = default;
  public:
    /// Bech32 encode raw bytes and hrp to a string.
    static auto encode(std::string_view hrp, std::span<const uint8_t> values) 
        -> std::string;
    
    /// Bech32 encode raw bytes (as hex string) and hrp to a string.
    static auto encode_hex(std::string_view hrp, std::string_view hex_values)
        -> std::string;
    
    /// Decode a bech32 encoded string to its raw bytes and hrp.
    static auto decode(std::string_view str)
        -> std::pair<std::string, std::vector<uint8_t>>;
    
    /// Decode a bech32 encoded string to its raw bytes (as hex string) and hrp.
    static auto decode_hex(std::string_view str)
        -> std::pair<std::string, std::string>;
}; // BECH32

class BASE58
{
  private:
    /// The constructor should remain private since this is a static class.
    BASE58() = default;
  public:
    /// Static method to encode a raw byte string into a base58 hex string.
    static auto encode(std::span<const uint8_t> values) -> std::string;

    /// Static method to encode a raw hex string into a base58 hex string.
    static auto encode_hex(std::string_view hex_values) -> std::string;

    /// Static method to decode a base58 hex string to a raw byte string.
    static auto decode(std::string_view str) -> std::vector<uint8_t>;

    /// Static method to decode a base58 hex string to a raw hex string.
    static auto decode_hex(std::string_view str) -> std::string;
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

        /// Prefered constructor. Provide the data to decode as bytes. The data
        /// is copied to an internal buffer for preservation during decoding.
        Decoder(std::span<const uint8_t> data);

        /// Destructor
        inline ~Decoder() = default;

        /// Factory method: returns a new CBOR::Decoder with an opened array.
        static auto fromArrayData(std::span<const uint8_t> data) -> Decoder;

        /// Factory method: returns a new CBOR::Decoder with an opened map.
        static auto fromMapData(std::span<const uint8_t> data) -> Decoder;

        /// Decode the next item in a CBOR data structure as the start of an
        /// array. The next decode calls will operate on items in the array.
        /// This must be eventually followed by exitArray.
        /// @throws A std::invalid_argument exception if the next CBOR item is
        ///         not an array object.
        auto enterArray() -> void;

        /// Access the array item stored in the current map object for the
        /// supplied integer-type key. Must have "entered" a map object. This
        /// must be eventually followed by exitArray.
        /// @throws A std::invalid_argument exception if the key does not exist
        ///         or the CBOR item is not an array object.
        auto enterArrayFromMap(int64_t k) -> void;

        /// Leave the array being decoded, i.e., go back up one nesting level. 
        /// Subsequent decoding calls will consume the items after the array.
        auto exitArray() -> void;

        /// Decode the next item in a CBOR data structure as the start of a
        /// map. The next decode calls will operate on items in the map.
        /// This must be eventually followed by exitMap.
        /// @throws A std::invalid_argument exception if the next CBOR item is
        ///         not a map object.
        auto enterMap() -> void;

        /// Access the map item stored in the current map object for the
        /// supplied integer-type key. Must have "entered" a map object. This
        /// must be eventually followed by exitMap.
        /// @throws A std::invalid_argument exception if the key does not exist
        ///         or the CBOR item is not a map object.
        auto enterMapFromMap(int64_t k) -> void;

        /// Leave the map being decoded, i.e., go back up one nesting level. 
        /// Subsequent decoding calls will consume the items after the map.
        auto exitMap() -> void;

        /// Consume the next item in the CBOR data structure.
        /// @throws A std::invalid_argument exception if the get item call is
        ///         not successful. Do not use to find the end of an object.
        auto getSkip() -> void;

        /// Decode the next item in the CBOR structure as an 8-bit integer.
        auto getInt8() -> int8_t;

        /// Decode the next item in the CBOR structure as an 16-bit integer.
        auto getInt16() -> int16_t;

        /// Decode the next item in the CBOR structure as an 32-bit integer.
        auto getInt32() -> int32_t;

        /// Decode the next item in the CBOR structure as an 64-bit integer.
        auto getInt64() -> int64_t;

        /// Decode the next item in the CBOR structure as an unsigned 8-bit 
        /// integer.
        auto getUint8() -> uint8_t;

        /// Decode the next item in the CBOR structure as an unsigned 16-bit 
        /// integer.
        auto getUint16() -> uint16_t;

        /// Decode the next item in the CBOR structure as an unsigned 32-bit 
        /// integer.
        auto getUint32() -> uint32_t;

        /// Decode the next item in the CBOR structure as an unsigned 64-bit 
        /// integer.
        auto getUint64() -> uint64_t;

        /// Decode the next item in the CBOR structure as tagged CBOR, i.e., a
        /// byte string which is itself encoded CBOR and therefore has the tag
        /// 24.
        auto getTaggedCborBytes() -> std::vector<uint8_t>;

        // Decode the next item in the CBOR structure as a rational number,
        // i.e., Tag = 30.
        auto getRational() -> std::pair<uint64_t, uint64_t>;

        /// Decode the next item in the CBOR structure as a byte string.
        auto getBytes() -> std::vector<uint8_t>;

        /// Decode the next item in the CBOR structure as a character string.
        auto getString() -> std::string;
        
        /// Decode the next item in the CBOR structure as a NULL. Return true if
        /// the item is a simple NULL type.
        auto getNULL() -> bool;

        /// Get the number of elements in the current array. This does not 
        /// count nested arrays, only the current nesting level. Must have 
        /// "entered" an array object.
        auto getArraySize() -> size_t;

        /// Get the number of key-value pairs in the current map. This does not 
        /// count nested maps, only the current nesting level. Must have 
        /// "entered" a map object.
        auto getMapSize() -> size_t;

        /// Return true if the current map (must have entered a map object)
        /// contains the provided integer-type key.
        auto keyInMap(int64_t k) -> bool;

        /// Return true if the current map (must have entered a map object)
        /// contains the provided string-type key.
        auto keyInMap(std::string_view k) -> bool;

        /// Access the bytes stored in the map object for the supplied 
        /// integer-type key. Must have "entered" a map object. Throws an 
        /// exception if the key does not exist in the map.
        auto getBytesFromMap(int64_t k) -> std::vector<uint8_t>;

        /// Access the bytes stored in the map object for the supplied 
        /// string-type key. Must have "entered" a map object. Throws an 
        /// exception if the key does not exist in the map.
        auto getBytesFromMap(std::string_view k) -> std::vector<uint8_t>;
        
        /// Decode the item in the CBOR map structure for the given integer-type
        /// key as an unsigned 8-bit integer.
        auto getUint8FromMap(int64_t k) -> uint8_t;

        /// Decode the item in the CBOR map structure for the given integer-type
        /// key as an unsigned 16-bit integer.
        auto getUint16FromMap(int64_t k) -> uint16_t;

        /// Decode the item in the CBOR map structure for the given integer-type
        /// key as an unsigned 32-bit integer.
        auto getUint32FromMap(int64_t k) -> uint32_t;

        /// Decode the item in the CBOR map structure for the given integer-type
        /// key as an unsigned 64-bit integer.
        auto getUint64FromMap(int64_t k) -> uint64_t;

        /// Decode the item in the CBOR map structure for the given integer-type
        /// key as an 8-bit integer.
        auto getInt8FromMap(int64_t k) -> int8_t;

        /// Decode the item in the CBOR map structure for the given integer-type
        /// key as an 16-bit integer.
        auto getInt16FromMap(int64_t k) -> int16_t;

        /// Decode the item in the CBOR map structure for the given integer-type
        /// key as an 32-bit integer.
        auto getInt32FromMap(int64_t k) -> int32_t;

        /// Decode the item in the CBOR map structure for the given integer-type
        /// key as an 64-bit integer.
        auto getInt64FromMap(int64_t k) -> int64_t;

      private:
        /// Store an internal copy of the CBOR data byte string. This is 
        /// required to prevent modification or deletion of the data during the
        /// decoding process.
        std::vector<uint8_t> _cbor_bytes;

        // Smart pointers to a generic data type (void) are used to 
        // intentionally separate the interface (header file) from the 
        // implementation. This way, in the event that a different CBOR backend
        // is used, only the implementation source code will need recompilation.
        std::shared_ptr<void> _cbor_ctx;
        std::shared_ptr<void> _cbor_itm;
    }; // Decoder

    /// Static methods for encoding and decoding objects. These methods 
    /// primarily use stack memory.

    /// Static method to CBOR encode a byte string.
    static auto encode(std::span<const uint8_t> b) -> std::vector<uint8_t>;

    /// Static method to CBOR encode an unsigned integer.
    static auto encode(uint64_t v) -> std::vector<uint8_t>;

    /// Static method to decode a CBOR encoded UInt32.
    static auto decodeUint32(std::span<const uint8_t> b) -> uint32_t;

    /// Static method to decode a CBOR encoded byte string.
    static auto decodeBytes(std::span<const uint8_t> b) -> std::vector<uint8_t>;
    
}; // CBOR

} // namespace cardano

#endif // _CARDANO_ENCODINGS_HPP_