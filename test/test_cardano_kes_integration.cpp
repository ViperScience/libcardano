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
#include <cardano/encodings.hpp>
#include <cardano/kes.hpp>

// Local test headers
#include "test_utils.hpp"

TEST_CASE("Test KES API Integration with Cardano-Node Haskell code.")
{
    auto seed = std::array<uint8_t, 32>{
        116, 101, 115, 116, 32,  115, 116, 114, 105, 110, 103,
        32,  111, 102, 32,  51,  50,  32,  98,  121, 116, 101,
        32,  111, 102, 32,  108, 101, 110, 103, 104, 116,
    };

    SECTION("haskel_depth_1")
    {
        // haskell generated key
        auto h_key = cardano_test::load_bytes("data/kes/key1.bin");
        const auto parsed_h_key = cardano::SumKesPrivateKey<1>(h_key);

        auto key_buffer =
            std::array<uint8_t, cardano::SumKesPrivateKey<1>::size + 4>{};
        auto [skey, vkey] =
            cardano::SumKesPrivateKey<1>::keygen(key_buffer, seed);

        // Compare hex strings for easier debugging if needed
        REQUIRE(
            cardano::BASE16::encode(skey.bytes()) ==
            cardano::BASE16::encode(parsed_h_key.bytes())
        );
    }

    SECTION("haskel_depth_6")
    {
        // haskell generated key
        auto h_key = cardano_test::load_bytes("data/kes/key6.bin");
        const auto parsed_h_key = cardano::SumKesPrivateKey<6>(h_key);

        auto key_buffer =
            std::array<uint8_t, cardano::SumKesPrivateKey<6>::size + 4>{};
        auto [skey, vkey] =
            cardano::SumKesPrivateKey<6>::keygen(key_buffer, seed);

        // Compare hex strings for easier debugging if needed
        REQUIRE(
            cardano::BASE16::encode(skey.bytes()) ==
            cardano::BASE16::encode(parsed_h_key.bytes())
        );
    }

    SECTION("haskell_signature_6")
    {
        const auto h_signature =
            cardano_test::load_bytes("data/kes/key6Sig.bin");

        auto key_buffer =
            std::array<uint8_t, cardano::SumKesPrivateKey<6>::size + 4>{};
        auto [skey, vkey] =
            cardano::SumKesPrivateKey<6>::keygen(key_buffer, seed);

        constexpr auto message = "test message";
        auto signature = skey.sign(message);

        // Compare hex strings for easier debugging if needed
        REQUIRE(
            cardano::BASE16::encode(signature.bytes()) ==
            cardano::BASE16::encode(h_signature)
        );
    }

    SECTION("haskell_signature_6_update_5")
    {
        const auto h_signature =
            cardano_test::load_bytes("data/kes/key6Sig5.bin");

        auto key_buffer =
            std::array<uint8_t, cardano::SumKesPrivateKey<6>::size + 4>{};
        auto [skey, vkey] =
            cardano::SumKesPrivateKey<6>::keygen(key_buffer, seed);
        skey.update();
        skey.update();
        skey.update();
        skey.update();
        skey.update();

        constexpr auto message = "test message";
        auto signature = skey.sign(message);

        // Compare hex strings for easier debugging if needed
        REQUIRE(
            cardano::BASE16::encode(signature.bytes()) ==
            cardano::BASE16::encode(h_signature)
        );
    }

    SECTION("haskel_compact_depth_1")
    {
        // haskell generated key
        auto h_key = cardano_test::load_bytes("data/kes/compactkey1.bin");
        const auto parsed_h_key = cardano::SumKesPrivateKey<1>(h_key);

        auto key_buffer =
            std::array<uint8_t, cardano::SumKesPrivateKey<1>::size + 4>{};
        auto [skey, vkey] =
            cardano::SumKesPrivateKey<1>::keygen(key_buffer, seed);

        // Compare hex strings for easier debugging if needed
        REQUIRE(
            cardano::BASE16::encode(skey.bytes()) ==
            cardano::BASE16::encode(parsed_h_key.bytes())
        );
    }

    SECTION("haskell_compact_depth_6")
    {
        // haskell generated key
        auto h_key = cardano_test::load_bytes("data/kes/compactkey6.bin");
        const auto parsed_h_key = cardano::SumKesPrivateKey<6>(h_key);

        auto key_buffer =
            std::array<uint8_t, cardano::SumKesPrivateKey<6>::size + 4>{};
        auto [skey, vkey] =
            cardano::SumKesPrivateKey<6>::keygen(key_buffer, seed);

        REQUIRE(
            cardano::BASE16::encode(skey.bytes()) ==
            cardano::BASE16::encode(parsed_h_key.bytes())
        );
    }

    SECTION("haskell_compact_signature_6")
    {
        const auto h_signature =
            cardano_test::load_bytes("data/kes/compactkey6Sig.bin");

        auto key_buffer =
            std::array<uint8_t, cardano::SumKesPrivateKey<6>::size + 4>{};
        auto [skey, vkey] =
            cardano::SumKesPrivateKey<6>::keygen(key_buffer, seed);

        constexpr auto message = "test message";
        auto signature = skey.signCompact(message);

        // Compare hex strings for easier debugging if needed
        REQUIRE(
            cardano::BASE16::encode(signature.bytes()) ==
            cardano::BASE16::encode(h_signature)
        );
    }

    SECTION("haskell_compact_signature_6_update_5")
    {
        const auto h_signature =
            cardano_test::load_bytes("data/kes/compactkey6Sig5.bin");

        auto key_buffer =
            std::array<uint8_t, cardano::SumKesPrivateKey<6>::size + 4>{};
        auto [skey, vkey] =
            cardano::SumKesPrivateKey<6>::keygen(key_buffer, seed);
        skey.update();
        skey.update();
        skey.update();
        skey.update();
        skey.update();

        constexpr auto message = "test message";
        auto signature = skey.signCompact(message);

        // Compare hex strings for easier debugging if needed
        REQUIRE(
            cardano::BASE16::encode(signature.bytes()) ==
            cardano::BASE16::encode(h_signature)
        );
    }
}
