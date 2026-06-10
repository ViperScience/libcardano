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

#ifndef _CARDANO_TEST_UTILS_HPP_
#define _CARDANO_TEST_UTILS_HPP_

// Standard Library Headers
#include <cstdint>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <span>
#include <vector>

// Third-party library headers
#include <boost/multiprecision/cpp_int.hpp>

// Public libcardano headers
#include <cardano/curve25519.hpp>

namespace mp = boost::multiprecision;
using namespace std::literals;

namespace cardano_test
{

/// @brief Print binary data to the console for debugging.
/// @param data The bytes tp print.
/// @param line_width The number of bytes to print before new line.
static void PrintBytes(std::span<const uint8_t> data, size_t line_width = 16)
{
    size_t counter = 0;
    for (auto v : data)
    {
        std::cout << "0x" << std::hex << std::setfill('0') << std::setw(2)
                  << (int)v << " ";
        counter++;
        if (counter > line_width - 1)
        {
            std::cout << std::endl;
            counter = 0;
        }
    }
    std::cout << std::endl;
}  // PrintBytes

/// @brief Load binary data from a file into a std::vector.
/// @param file_path The path to the file to load.
/// @return The binary data in a std::vector.
static auto LoadBytes(std::string_view file_path) -> std::vector<uint8_t>
{
    auto stream =
        std::ifstream(file_path.data(), std::ios::in | std::ios::binary);
    if (!stream)
    {
        throw std::runtime_error(
            "Failed to open file: " + std::string(file_path)
        );
    }
    return {
        (std::istreambuf_iterator<char>(stream)),
        std::istreambuf_iterator<char>()
    };
}  // LoadBytes

inline auto CppIntToBytes(mp::cpp_int big_int) -> std::array<uint8_t, 32>
{
    auto big_int_bytes = std::array<uint8_t, 32>();
    for (size_t n = 0; n < big_int_bytes.size(); ++n)
    {
        big_int_bytes[n] =
            static_cast<uint8_t>((big_int >> n * 8) & 0b11111111);
    }
    return big_int_bytes;
}  // CppIntToBytes

inline auto BytesToCppInt(std::span<uint8_t, 32> big_int_bytes) -> mp::cpp_int
{
    auto big_int = mp::cpp_int(0);
    for (size_t n = 0; n < big_int_bytes.size(); ++n)
    {
        big_int += (mp::cpp_int(big_int_bytes[n]) << (n * 8));
    }
    return big_int;
}  // BytesToCppInt

inline auto Curve25519GroupOrder() -> mp::cpp_int
{
    // 2^252+27742317777372353535851937790883648493
    return mp::pow(mp::cpp_int(2), 252) +
           mp::cpp_int("27742317777372353535851937790883648493"sv);
}  // Curve25519GroupOrder

inline auto FromMpUint256(mp::uint256_t v) -> cardano::tss::ed25519::Scalar
{
    auto U64TO8_LE = [](std::span<uint8_t> out, const uint64_t v) -> void
    {
        if (out.size() < 8)
        {
            throw std::invalid_argument("Input must be at least 8 bytes");
        }
        out[0] = (uint8_t)v;
        out[1] = (uint8_t)(v >> 8);
        out[2] = (uint8_t)(v >> 16);
        out[3] = (uint8_t)(v >> 24);
        out[4] = (uint8_t)(v >> 32);
        out[5] = (uint8_t)(v >> 40);
        out[6] = (uint8_t)(v >> 48);
        out[7] = (uint8_t)(v >> 56);
    };
    auto res = std::array<uint8_t, 32>();
    for (size_t n = 0; n < 4; ++n)
    {
        U64TO8_LE({res.data() + 8 * n, 8}, static_cast<uint64_t>(v >> 64 * n));
    }
    return cardano::tss::ed25519::Scalar::reduce(res);
}  // FromMpUint256

}  // namespace cardano_test

#endif  // _CARDANO_TEST_UTILS_HPP_
