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

namespace cardano
{

/// @brief A static class to encode and decode bytes to and from hex strings.
class BASE16
{
  private:
    // The constructor should remain private since this is a static class.
    BASE16() = default;

  public:
    // What endianess? Should this be configurable?

    /// @brief Encode a byte array to a hex string.
    /// @param bytes The byte array to encode.
    /// @return The encoded hex string.
    static auto encode(std::span<const uint8_t> bytes) -> std::string;

    /// @brief Decode a hex string to a byte array.
    /// @param str The hex string to decode.
    /// @return The decoded byte array.
    static auto decode(std::string_view str) -> std::vector<uint8_t>;
};  // BASE16

/// @brief A static class to encode and decode bytes to and from Bech32 format.
class BECH32
{
  private:
    // The constructor should remain private since this is a static class.
    BECH32() = default;

  public:
    /// @brief Bech32 encode raw bytes and hrp to a string.
    /// @param hrp The human readable part of the bech32 string.
    /// @param values The raw bytes to encode.
    /// @return The encoded bech32 string.
    static auto encode(std::string_view hrp, std::span<const uint8_t> values)
        -> std::string;

    /// @brief Bech32 encode raw bytes (as hex string) and hrp to a string.
    /// @param hrp The human readable part of the bech32 string.
    /// @param hex_values The raw bytes to encode (as hex string).
    /// @return The encoded bech32 string.
    static auto encode_hex(std::string_view hrp, std::string_view hex_values)
        -> std::string;

    /// @brief Decode a bech32 encoded string to its raw bytes and hrp.
    /// @param str The bech32 encoded string to decode.
    /// @return The decoded raw bytes and hrp.
    static auto decode(std::string_view str)
        -> std::pair<std::string, std::vector<uint8_t>>;

    /// @brief Decode a bech32 encoded string to its raw bytes (as hex string) and hrp.
    /// @param str The bech32 encoded string to decode.
    /// @return The decoded raw bytes (as hex string) and hrp.
    static auto decode_hex(std::string_view str)
        -> std::pair<std::string, std::string>;
};  // BECH32

/// @brief A static class to encode and decode bytes to and from base58.
class BASE58
{
  private:
    // The constructor should remain private since this is a static class.
    BASE58() = default;

  public:
    /// @brief Static method to encode a raw byte string into a base58 hex string.
    /// @param values The raw byte string to encode.
    /// @return The encoded base58 hex string.
    static auto encode(std::span<const uint8_t> values) -> std::string;

    /// @brief Static method to encode a raw hex string into a base58 hex string.
    /// @param hex_values The raw hex string to encode.
    /// @return The encoded base58 hex string.
    static auto encode_hex(std::string_view hex_values) -> std::string;

    /// @brief Static method to decode a base58 hex string to a raw byte string.
    /// @param str The base58 hex string to decode.
    /// @return The decoded raw byte string.
    static auto decode(std::string_view str) -> std::vector<uint8_t>;

    /// @brief Static method to decode a base58 hex string to a raw hex string.
    /// @param str The base58 hex string to decode.
    /// @return The decoded raw hex string.
    static auto decode_hex(std::string_view str) -> std::string;
};  // BASE58

}  // namespace cardano

#endif  // _CARDANO_ENCODINGS_HPP_