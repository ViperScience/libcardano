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

#ifndef _CARDANO_UTIL_HPP_
#define _CARDANO_UTIL_HPP_

// Standard Library Headers
#include <algorithm>
#include <concepts>
#include <cstdint>
#include <ranges>
#include <span>
#include <type_traits>
#include <vector>

namespace cardano
{

/// @brief Utility namespace
namespace util
{

/// @brief Concatenate two byte ranges.
/// @return A vector containing the elements of both ranges.
template <class SizedRange1, class SizedRange2>
auto concatBytes(SizedRange1 const &r1, SizedRange2 const &r2)
{
    std::vector<typename SizedRange1::value_type> ret;
    ret.reserve(r1.size() + r2.size());
    ret.insert(ret.end(), std::begin(r1), std::end(r1));
    ret.insert(ret.end(), std::begin(r2), std::end(r2));
    return ret;
}  // concat_bytes

/// @brief Convert a span of bytes into a fixed size array.
/// @return An array containing the elements from the input.
template <std::size_t N>
constexpr auto makeByteArray(std::span<const uint8_t> vec)
    -> std::array<uint8_t, N>
{
    std::array<uint8_t, N> arr;
    std::ranges::copy(vec | std::views::take(N), arr.begin());
    return arr;
}  // makeByteArray

enum class Endianness
{
    BigEndian,
    LittleEndian
};

/// @brief Object for packing and unpacking bytes as integers.
/// @tparam IntType The integer type to pack to or unpack from.
template <typename IntType>
    requires std::is_integral_v<IntType>
struct BytePacker
{
    /// @brief Pack an integer into an array of bytes.
    /// @param value The IntType value to pack.
    /// @param endianness Specify big or little endianess (default: big).
    /// @return A fixed size byte array of length sizeof(IntType).
    static auto pack(
        IntType value,
        Endianness endianness = Endianness::BigEndian
    ) -> std::array<uint8_t, sizeof(IntType)>
    {
        auto bytes = std::array<uint8_t, sizeof(IntType)>();
        if (endianness == Endianness::BigEndian)
        {
            for (size_t i = 0; i < sizeof(IntType); ++i)
            {
                bytes[i] = static_cast<uint8_t>(
                    (value >> (8 * (sizeof(IntType) - 1 - i))) & 0xFF
                );
            }
        }
        else  // little endian
        {
            for (size_t i = 0; i < sizeof(IntType); ++i)
            {
                bytes[i] = static_cast<uint8_t>((value >> (8 * i)) & 0xFF);
            }
        }
        return bytes;
    }

    /// @brief Unpack a span of bytes as an integer.
    /// @param bytes Bytes to unpack, must be fixed length of sizeof(IntType).
    /// @param endianness Specify big or little endianess (default: big).
    /// @return The unpacked integer of IntType.
    static auto unpack(
        std::span<const uint8_t, sizeof(IntType)> bytes,
        Endianness endianness = Endianness::BigEndian
    ) -> IntType
    {
        IntType value = 0;
        if (endianness == Endianness::BigEndian)
        {
            for (size_t i = 0; i < sizeof(IntType); ++i)
            {
                value |= static_cast<IntType>(bytes[i])
                         << (8 * (sizeof(IntType) - 1 - i));
            }
        }
        else
        {
            for (size_t i = 0; i < sizeof(IntType); ++i)
            {
                value |= static_cast<IntType>(bytes[i]) << (8 * i);
            }
        }
        return value;
    }
};

}  // namespace util
}  // namespace cardano

#endif  // _CARDANO_UTIL_HPP_