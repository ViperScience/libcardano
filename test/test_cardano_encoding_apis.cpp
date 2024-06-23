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

// Standard library headers
#include <string_view>

// Third-party library headers
#include <catch2/catch_test_macros.hpp>

// Public libcardano headers
#include <cardano/encodings.hpp>

using namespace cardano;
using namespace std::literals;

TEST_CASE("testCardanoEncodingAPIs")
{
    SECTION("testBech32Basic")
    {
        constexpr auto addr_bech32 = "addr1qyghraqad85ue38enxtdkmfsmxktds58msuxhqwyq87yjd2pefk9uwxnjt63hj85l8srdgfh50y7repx0ymaspz5s3msgdc7y8"sv;
        constexpr auto addr_hex = "011171f41d69e9ccc4f99996db6d30d9acb6c287dc386b81c401fc493541ca6c5e38d392f51bc8f4f9e036a137a3c9e1e4267937d804548477"sv;

        auto [hrp, data] = cardano::BECH32::decode_hex(addr_bech32);
        REQUIRE(hrp == "addr");
        REQUIRE(data == addr_hex);

        auto data_bech32 = cardano::BECH32::encode_hex("addr", data);
        REQUIRE(data_bech32 == addr_bech32);
    }

    SECTION("testBech32Advanced")
    {
        constexpr auto pool_id_hex = "d69b6b16c6a135c4157365ded9b0d772d44c7628a05b49741d3ae25c"sv;
        constexpr auto pool_id_bech32 = "pool166dkk9kx5y6ug9tnvh0dnvxhwt2yca3g5pd5jaqa8t39cgyqqlr"sv;
        constexpr auto stake_hex = "e130188f574458076f6746c4d0b7904247dd477db7d0be91fc919eedfe"sv; // e1 -> header byte
        constexpr auto stake_bech32 = "stake1uycp3r6hg3vqwmm8gmzdpdusgfra63maklgtay0ujx0wmlstrah3d"sv;

        auto [hrp1, data1] = cardano::BECH32::decode_hex(pool_id_bech32);
        REQUIRE(hrp1 == "pool");
        REQUIRE(data1 == pool_id_hex);

        auto data1_bech32 = cardano::BECH32::encode_hex("pool", pool_id_hex);
        REQUIRE(data1_bech32 == pool_id_bech32);

        auto [hrp2, data2] = cardano::BECH32::decode_hex(stake_bech32);
        REQUIRE(hrp2 == "stake");
        REQUIRE(data2 == stake_hex);

        auto data2_bech32 = cardano::BECH32::encode_hex("stake", stake_hex);
        REQUIRE(data2_bech32 == stake_bech32);
    }

    SECTION("testBase58")
    {
        const auto v1 = std::vector<uint8_t>{0x00, 0x00, 0x28, 0x7f, 0xb4, 0xcd};
        constexpr auto v1_b58 = "11233QC4";
        constexpr auto addr_hex = "82d818584283581c34c964f2ba4bc1ad09e131f110ff5bb835110069967ca0f62e0c39f1a101581e581ce07c1b3a70256505b286ba878318800b1b980a83fd5a1ec63f247b13001a6dfc0e16";
        constexpr auto addr_b58 = "DdzFFzCqrhskgmnxD51DjjQajd4Q7mhNaHjSXMi6Cg77VbwWgdCgT8X2zYtTfszqKB2XKR7dhgSBfsgJfzmmAYGtKcHKYqKhWy7o9fwb";
        
        auto v1_encoding = cardano::BASE58::encode(v1);
        REQUIRE(v1_encoding == v1_b58);

        auto addr_encoding = cardano::BASE58::encode_hex(addr_hex);
        REQUIRE(addr_encoding == addr_b58);

        auto v1_decode = cardano::BASE58::decode(v1_b58);
        REQUIRE(v1_decode == v1);

        auto addr_decode = cardano::BASE58::decode_hex(addr_b58);
        REQUIRE(addr_decode == addr_hex);
    }
}
