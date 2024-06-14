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

#include <algorithm>
#include <array>
#include <cmath>
#include <ranges>
#include <span>
#include <string>
#include <vector>

#ifndef _CARDANO_UTILS_HPP_
#define _CARDANO_UTILS_HPP_

namespace cardano
{

/// @brief Namespace for utility functions.
namespace utils
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

template <std::size_t N>
constexpr auto makeByteArray(std::span<const uint8_t> vec)
    -> std::array<uint8_t, N>
{
    std::array<uint8_t, N> arr;
    std::ranges::copy(vec | std::views::take(N), arr.begin());
    return arr;
}  // makeByteArray

/// @brief Case insensitive string compare.
/// @return True if the strings are equal when ignoring case.
constexpr auto strcmpi(std::string_view h1, std::string_view h2) -> bool
{
    if (h1.size() != h2.size()) return false;
    for (size_t i = 0; i < h1.size(); ++i)
        if (std::tolower((char)h1[i]) != std::tolower((char)h2[i]))
            return false;
    return true;
}  // strcmpi

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
constexpr auto rationalApprox(double f, int64_t md)
    -> std::pair<int64_t, int64_t>
{
    /* f : number to convert.
     * num, denom: returned parts of the rational.
     * md: max denominator value.  Note that machine floating point number
     *     has a finite resolution (10e-16 ish for 64 bit double), so specifying
     *     a "best match with minimal error" is often wrong, because one can
     *     always just retrieve the significand and return that divided by
     *     2**52, which is in a sense accurate, but generally not very useful:
     *     1.0/7.0 would be "2573485501354569/18014398509481984", for example.
     */

    int64_t num, denom;

    // a: continued fraction coefficients.
    int64_t a, h[3] = {0, 1, 0}, k[3] = {1, 0, 0};
    int64_t x, d, n = 1;
    int i, neg = 0;

    if (md <= 1)
    {
        denom = 1;
        num = (int64_t)f;
        return {num, denom};
    }

    if (f < 0)
    {
        neg = 1;
        f = -f;
    }

    while (f != ::floor(f))
    {
        n <<= 1;
        f *= 2;
    }
    d = static_cast<int64_t>(f);

    // continued fraction and check denominator each step
    for (i = 0; i < 64; i++)
    {
        a = n ? d / n : 0;
        if (i && !a) break;

        x = d;
        d = n;
        n = x % n;

        x = a;
        if (k[1] * a + k[0] >= md)
        {
            x = (md - k[0]) / k[1];
            if (x * 2 >= a || k[1] >= md)
                i = 65;
            else
                break;
        }

        h[2] = x * h[1] + h[0];
        h[0] = h[1];
        h[1] = h[2];
        k[2] = x * k[1] + k[0];
        k[0] = k[1];
        k[1] = k[2];
    }
    denom = k[1];
    num = neg ? -h[1] : h[1];
    return {num, denom};
}  // rationalApprox

}  // namespace utils
}  // namespace cardano

#endif  // _CARDANO_UTILS_HPP_
