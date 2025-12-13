// Copyright (c) 2024 Viper Science LLC
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

// Standard Library Headers
#include <cmath>
#include <fstream>

// Public libcardano Headers
#include <cardano/util.hpp>

auto cardano::util::writeEnvelopeTextFile(
    const std::string_view file_path,
    const std::string_view type,
    const std::string_view description,
    const std::string_view cbor_hex
) -> void
{
    auto out = std::ofstream(std::string(file_path).c_str());
    if (!out)
    {
        throw std::runtime_error(
            "Failed to open file for writing: " + std::string(file_path)
        );
    }

    out.exceptions(std::ofstream::failbit | std::ofstream::badbit);

    try
    {
        out << "{\n";
        out << R"(    "type": ")" << type << "\",\n";
        out << R"(    "description": ")" << description << "\",\n";
        out << R"(    "cborHex": ")" << cbor_hex << "\"\n";
        out << "}";
        // Destructor will close and flush
    }
    catch (const std::ofstream::failure& e)
    {
        throw std::runtime_error(
            "Failed to write to file " + std::string(file_path) +
            ": " + e.what()
        );
    }
}  // writeEnvelopeTextFile

auto cardano::util::rationalApprox(double f, int64_t md)
    -> std::pair<int64_t, int64_t>
{
    int64_t num, denom;

    // a: continued fraction coefficients.
    auto h = std::array<int64_t, 3>{0, 1, 0};
    auto k = std::array<int64_t, 3>{1, 0, 0};
    int64_t a, x, d, n = 1;
    // int i, neg = 0;

    if (md <= 1)
    {
        denom = 1;
        num = (int64_t)f;
        return {num, denom};
    }

    const bool is_neg = (f < 0);
    if (is_neg)
    {
        f = -f;
    }

    while (f != ::floor(f))
    {
        n <<= 1;
        f *= 2;
    }
    d = static_cast<int64_t>(f);

    // continued fraction and check denominator each step
    for (int i = 0; i < 64; i++)
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
    num = is_neg ? -h[1] : h[1];
    return {num, denom};
}  // rationalApprox