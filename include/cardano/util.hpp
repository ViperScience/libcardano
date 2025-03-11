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
#include <cmath>
#include <cstdint>
#include <span>
#include <vector>

// Third-party library headers
#include <botan/auto_rng.h>
#include <botan/rng.h>
#include <botan/system_rng.h>

/// @brief Utility namespace
namespace cardano::util
{

/// @brief Convert Lovelaces to ADA.
/// @param lovelaces The value in lovelaces (integer).
/// @return The equivalent value in ADA (double).
constexpr auto love2ada(int64_t lovelaces) -> double
{
    return static_cast<double>(lovelaces) / 1000000.0;
}

/// @brief Convert ADA Lovelaces.
/// @param ada The value in ADA (double).
/// @return The value in lovelaces (integer).
constexpr auto ada2love(double ada) -> int64_t
{
    return static_cast<int64_t>(trunc(1000000 * ada));
}

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
constexpr auto makeByteArray(std::span<const uint8_t> vec
) -> std::array<uint8_t, N>
{
    std::array<uint8_t, N> arr;
    std::ranges::copy(vec | std::views::take(N), arr.begin());
    return arr;
}  // makeByteArray

/// @brief Generate a fixed size array filled with random bytes.
/// @return An array of uint8_t containing random values.
template <std::size_t N>
auto makeRandomByteArray() -> std::array<uint8_t, N> {
    std::unique_ptr<Botan::RandomNumberGenerator> rng;
#if defined(BOTAN_HAS_SYSTEM_RNG)
    rng.reset(new Botan::System_RNG);
#else
    rng.reset(new Botan::AutoSeeded_RNG);
#endif
    auto ent = std::array<uint8_t, N>();
    rng->randomize(ent.data(), N);
    return ent;
}  // makeRandomByteArray

/// @brief Enum class to represent byte order.
enum class Endianness
{
    BigEndian,
    LittleEndian
};  // Endianness

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
};  // BytePacker

/// @brief Write CBOR date to file in the envelope format used by cardano node.
/// @param file_path Path to the generated key file.
/// @param type A string key type specifier.
/// @param description Description of the key (maybe empty).
/// @param cbor_hex The CBOR key data in hex string format.
auto writeEnvelopeTextFile(
    const std::string_view file_path,
    const std::string_view type,
    const std::string_view description,
    const std::string_view cbor_hex
) -> void;

/// @brief Approximate a floating point number as a rational number.
/// @param f The floating point number to convert.
/// @param md The maximum denominator.
/// @return The numerator and denominator as a pair of integers.
/// @note Note that machine floating point number has a finite resolution
/// (10e-16 ish for 64 bit double), so specifying a "best match with minimal
/// error" is often wrong, because one can always just retrieve the significand
/// and return that divided by 2**52, which is in a sense accurate, but
/// generally not very useful: 1.0/7.0 would be
/// "2573485501354569/18014398509481984", for example.
auto rationalApprox(double f, int64_t md) -> std::pair<int64_t, int64_t>;

}  // namespace cardano::util

#endif  // _CARDANO_UTIL_HPP_