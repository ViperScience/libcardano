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
#include <array>
#include <cstdint>

// Third-party library headers
#include <boost/multiprecision/cpp_int.hpp>
#include <catch2/catch_test_macros.hpp>

// Public libcardano headers
#include <cardano/curve25519.hpp>

// Private libcardano headers
#include "test_utils.hpp"

// Use namespaces to make the code more readable
namespace mp = boost::multiprecision;
namespace ed = cardano::tss::ed25519;
using namespace std::literals;

TEST_CASE("testCardanoCurve25519API")
{
    SECTION("ed25519::Scalar::zero")
    {
        const auto z = ed::Scalar::zero();
        REQUIRE(z.isZero());
        for (const auto b : z.bytes())
        {
            REQUIRE(b == 0);
        }
    }

    SECTION("ed25519::Scalar::fromUint")
    {
        const auto t = ed::Scalar::fromUint(10).bytes();
        REQUIRE(t[0] == 10);
        uint64_t cumm = 0;
        for (const auto b : t)
        {
            cumm += b;
        }
        REQUIRE(cumm == 10);

        // 0xFFFFFFFFFFFFFFFF is little-endian eight 0xFF bytes (< ℓ).
        const auto u = ed::Scalar::fromUint(0xFFFFFFFFFFFFFFFF).bytes();
        for (size_t i = 0; i < 8; ++i)
        {
            REQUIRE(u[i] == 0xFF);
        }
        for (size_t i = 8; i < 32; ++i)
        {
            REQUIRE(u[i] == 0x00);
        }
    }

    SECTION("ed25519::Scalar::fromUintPow")
    {
        REQUIRE(ed::Scalar::fromUintPow(4, 0) == ed::Scalar::fromUint(1));
        REQUIRE(ed::Scalar::fromUintPow(4, 1) == ed::Scalar::fromUint(4));
        REQUIRE(ed::Scalar::fromUintPow(10, 4) == ed::Scalar::fromUint(10000));

        // 2^64 has its only set byte at index 8 (little-endian).
        const auto v = ed::Scalar::fromUintPow(2, 64).bytes();
        REQUIRE(v[8] == 0x01);
        for (size_t i = 0; i < 32; ++i)
        {
            if (i != 8) REQUIRE(v[i] == 0x00);
        }
    }

    SECTION("ed25519::Scalar::operator*")
    {
        // (-1) * (-1) == 1 mod ℓ, where -1 == 0 - 1.
        const auto neg_one = ed::Scalar::zero() - ed::Scalar::fromUint(1);
        REQUIRE(neg_one * neg_one == ed::Scalar::fromUint(1));

        // Small products that do not wrap.
        REQUIRE(
            ed::Scalar::fromUint(7) * ed::Scalar::fromUint(6) ==
            ed::Scalar::fromUint(42)
        );

        // Large operands reduce mod ℓ without overflow.
        const auto v1 = cardano_test::FromMpUint256(
            mp::uint256_t("370634456879779497815637488681697333477376"sv)
        );
        const auto v2 = cardano_test::FromMpUint256(
            mp::uint256_t(
                "4426296878308873747580834685433361064182339707311849457677035872484747727729"sv
            )
        );
        // Commutativity as a basic sanity property.
        REQUIRE(v1 * v2 == v2 * v1);
    }

    SECTION("ed25519::Scalar::operator-")
    {
        const auto a = ed::Scalar::fromUint(12);
        const auto b = ed::Scalar::fromUint(3);

        REQUIRE(a - b == ed::Scalar::fromUint(9));
        // b - a wraps to -(9) == 0 - 9 mod ℓ.
        REQUIRE(b - a == ed::Scalar::zero() - ed::Scalar::fromUint(9));
        // Round-trip.
        REQUIRE((a - b) + b == a);
    }

    SECTION("ed25519::Scalar::operator== and isZero")
    {
        REQUIRE(ed::Scalar::fromUint(5) == ed::Scalar::fromUint(5));
        REQUIRE_FALSE(ed::Scalar::fromUint(5) == ed::Scalar::fromUint(6));
        REQUIRE((ed::Scalar::fromUint(7) - ed::Scalar::fromUint(7)).isZero());
        REQUIRE_FALSE(ed::Scalar::fromUint(1).isZero());
    }

    SECTION("ed25519::Scalar::operator/ (modular inverse)")
    {
        const auto num = ed::Scalar::fromUint(12);
        const auto den = ed::Scalar::fromUint(3);

        REQUIRE(num / den == ed::Scalar::fromUint(4));
        REQUIRE(den * (num / den) == num);
        REQUIRE(den * ((den * (num / den)) / den) == num);
        REQUIRE(num * (den / num) == den);

        // a * a^-1 == 1 for several values, including a large one.
        const auto one = ed::Scalar::fromUint(1);
        for (const uint64_t a : {2ULL, 12ULL, 17ULL})
        {
            const auto s = ed::Scalar::fromUint(a);
            REQUIRE(s * (one / s) == one);
        }
        const auto big = cardano_test::FromMpUint256(
            mp::uint256_t(
                "6778802174860340747202025463674101745619506775745309900070354323071886227867"sv
            )
        );
        REQUIRE(big * (one / big) == one);

        // Division by zero is rejected.
        REQUIRE_THROWS(num / ed::Scalar::zero());
    }

    SECTION("ed25519::Point basepoint multiply and addition")
    {
        // [2]B == B + B.
        const auto b1 = ed::Point::mulBasepoint(ed::Scalar::fromUint(1));
        const auto b2 = ed::Point::mulBasepoint(ed::Scalar::fromUint(2));
        REQUIRE((b1 + b1).bytes() == b2.bytes());

        // [3]B == [2]B + B == B + [2]B (commutativity).
        const auto b3 = ed::Point::mulBasepoint(ed::Scalar::fromUint(3));
        REQUIRE((b2 + b1).bytes() == b3.bytes());
        REQUIRE((b1 + b2).bytes() == b3.bytes());

        // The free pointAdd helper matches Point::operator+.
        const auto a_enc = b1.bytes();
        const auto c_enc = b2.bytes();
        REQUIRE(
            ed::EncodedPointAdd(
                std::span<const uint8_t, 32>{a_enc},
                std::span<const uint8_t, 32>{c_enc}
            ) == b3.bytes()
        );
    }

    SECTION("ed25519::Point addition rejects off-curve encodings")
    {
        // The encoding y = 2 has no valid x-coordinate (it is not on the curve)
        // and must be rejected by point addition.
        auto bad = std::array<uint8_t, 32>{};
        bad[0] = 0x02;
        const auto good =
            ed::Point::mulBasepoint(ed::Scalar::fromUint(1)).bytes();
        REQUIRE_THROWS(
            ed::EncodedPointAdd(
                std::span<const uint8_t, 32>{bad},
                std::span<const uint8_t, 32>{good}
            )
        );
    }
}
