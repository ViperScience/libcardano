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

// #include <algorithm>
// #include <array>
// #include <cmath>
// #include <ranges>
// #include <span>
// #include <string>
// #include <vector>

#ifndef _CARDANO_UTIL_HPP_
#define _CARDANO_UTIL_HPP_

// Standard Library Headers
#include <concepts>
#include <cstdint>
#include <ranges>
#include <span>
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

template <typename IntType>
    requires std::integral<IntType>
struct BytePacker
{
    // need to specify endianess
    static auto pack(IntType value) -> std::vector<uint8_t>
    {
        constexpr auto nb = sizeof(IntType);
        auto bytes = std::vector<uint8_t>(nb);
        for (int i = 0; i < nb; ++i)
        {
            bytes[i] = static_cast<uint8_t>(value >> (8 * (nb - 1 - i)));
        }
        return bytes;
    }

    static auto unpack(std::span<const uint8_t> bytes) -> IntType
    {
        IntType value = 0;
        for (int i = 0; i < sizeof(IntType); ++i)
        {
            value |= static_cast<IntType>(
                bytes[i] << (8 * (sizeof(IntType) - 1 - i))
            );
        }
        return value;
    }
};

}  // namespace util
}  // namespace cardano

#endif  // _CARDANO_UTIL_HPP_