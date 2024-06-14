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

// Third-party library headers
#include <catch2/catch_test_macros.hpp>

// Public libcardano headers
#include <cardano/kes.hpp>
#include <cardano/secmem.hpp>

using namespace cardano;

TEST_CASE("testCardanoKESAPI")
{
    SECTION("SumKesKey_Depth0")
    {
        auto [skey, pkey] = SumKesPrivateKey<0>::generate();

        REQUIRE(skey.period() == 0);
        REQUIRE_THROWS(skey.update());

        constexpr auto dummy_message = "tilin";
        auto sigma = skey.sign(dummy_message);

        REQUIRE(sigma.verify(0, pkey, dummy_message));
    }

    SECTION("CompactSumKesKey_Depth0")
    {
        // auto key = ed25519::Sum0CompactKesPrivateKey::generate();
        // CHECK(key.period() == 0);
        // CHECK_THROWS(key.update());
    }

    SECTION("SumKesKey_Depth1")
    {
        auto [skey, pkey] = SumKesPrivateKey<1>::generate();

        constexpr auto dummy_message = "tilin";
        auto sigma = skey.sign(dummy_message);
        REQUIRE(sigma.verify(0, pkey, dummy_message));

        // Key can be updated 2^1 - 1 times
        REQUIRE(skey.period() == 0);
        REQUIRE_NOTHROW(skey.update());
        REQUIRE(skey.period() == 1);
        REQUIRE_THROWS(skey.update());

        // Verify the key is zeroed by the drop operation.
        skey.drop();
        auto z = std::array<uint8_t, SumKesPrivateKey<1>::size + 4>{};
        REQUIRE(skey.bytes() == z);
    }

    SECTION("CompactSumKesKey_Depth1") {}

    SECTION("SumKesKey_Depth4")
    {
        auto [skey, pkey] = SumKesPrivateKey<4>::generate();

        constexpr auto dummy_message = "tilin";
        auto sigma = skey.sign(dummy_message);
        REQUIRE(sigma.verify(0, pkey, dummy_message));

        // Key can be updated 2^4 - 1 times
        for (int i = 0; i < 15; i++)
        {
            REQUIRE_NOTHROW(skey.update());
        }
        REQUIRE(skey.period() == 15);

        REQUIRE(skey.sign(dummy_message).verify(15, pkey, dummy_message));
    }

    SECTION("CompactSumKesKey_Depth4") {}

    SECTION("KesKey_to_PublicKey")
    {
        auto [skey, pkey] = SumKesPrivateKey<4>::generate();
        REQUIRE(pkey.bytes() == skey.publicKey().bytes());
    }
}