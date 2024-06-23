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
#include <cardano/bip32_ed25519.hpp>
#include <cardano/encodings.hpp>
#include <cardano/util.hpp>

using namespace cardano;
using namespace std::literals;

TEST_CASE("testCardanoEd25519API")
{
    constexpr auto root_xsk_bech32 = "root_xsk1hqzfzrgskgnpwskxxrv5khs7ess82ecy8za9l5ef7e0afd2849p3zryje8chk39nxtva0sww5me3pzkej4rvd5cae3q3v8eu7556n6pdrp4fdu8nsglynpmcppxxvfdyzdz5gfq3fefjepxhvqspmuyvmvqg8983"sv;
    constexpr auto root_xsk_base16 = "b804910d10b2261742c630d94b5e1ecc2075670438ba5fd329f65fd4b547a943110c92c9f17b44b332d9d7c1cea6f3108ad99546c6d31dcc41161f3cf529a9e82d186a96f0f3823e498778084c6625a413454424114e532c84d760201df08cdb"sv;
    constexpr auto addr_xvk_bech32 = "addr_xvk1grvg8qzmkmw2n0dm4pd0h3j4dv6yglyammyp733eyj629dc3z28v6wk22nfmru6xz0vl2s3y5xndyd57fu70hrt84c6zkvlwx6fdl7ct9j7yc"sv;
    constexpr auto stake_xvk_bech32 = "stake_xvk1658atzttunamzn80204khrg0qfdk5nvmrutlmmpg7xlsyaggwa7h9z4smmeqsvs67qhyqmc2lqa0vy36rf2la74ym8a5p93zp4qtpuq6ky3ve"sv;
    constexpr auto stake_xvk_base16 = "d50fd5896be4fbb14cef53eb6b8d0f025b6a4d9b1f17fdec28f1bf027508777d728ab0def208321af02e406f0af83af6123a1a55fefaa4d9fb4096220d40b0f0"sv;
    constexpr auto zeros_base16 = "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"sv;
    constexpr auto password = "password";

    SECTION("testBasicKeyDerivation")
    {
        const auto [hrp1, data] = BECH32::decode(root_xsk_bech32);
        auto root_xsk = bip32_ed25519::PrivateKey(util::makeByteArray<96>(data));
        auto acct_xsk = root_xsk.deriveChild(bip32_ed25519::HardenIndex(1852))
                                .deriveChild(bip32_ed25519::HardenIndex(1815))
                                .deriveChild(bip32_ed25519::HardenIndex(0));
        auto acct_xvk = acct_xsk.publicKey();
        auto addr_xvk = acct_xvk.deriveChild(0).deriveChild(0);
        auto stake_xvk = acct_xvk.deriveChild(2).deriveChild(0);

        REQUIRE(BECH32::encode("root_xsk", root_xsk.xbytes()) == root_xsk_bech32);
        REQUIRE(BECH32::encode("addr_xvk", addr_xvk.xbytes()) == addr_xvk_bech32);
        REQUIRE(BECH32::encode("stake_xvk", stake_xvk.xbytes()) == stake_xvk_bech32);
    }

    SECTION("testAdvancedKeyDerivation")
    {
        const auto [hrp1, xkey_bytes] = BECH32::decode(root_xsk_bech32);
        const auto root_xsk = bip32_ed25519::PrivateKey(util::makeByteArray<96>(xkey_bytes));
        REQUIRE(BECH32::encode("root_xsk", root_xsk.xbytes()) == root_xsk_bech32);

        auto root_xsk_enc = root_xsk.encrypt(password);
        auto acct_xsk = root_xsk_enc.decrypt(password)
                                    .deriveChild(bip32_ed25519::HardenIndex(1852))
                                    .deriveChild(bip32_ed25519::HardenIndex(1815))
                                    .deriveChild(bip32_ed25519::HardenIndex(0));
        
        auto acct_xvk = acct_xsk.publicKey();
        auto addr_xvk = acct_xvk.deriveChild(0).deriveChild(0);
        auto stake_xvk = acct_xvk.deriveChild(2).deriveChild(0);

        REQUIRE(BECH32::encode("addr_xvk", addr_xvk.xbytes()) == addr_xvk_bech32);
        REQUIRE(BECH32::encode("stake_xvk", stake_xvk.xbytes()) == stake_xvk_bech32);

        REQUIRE(BASE16::encode(stake_xvk.xbytes()) == stake_xvk_base16);
        REQUIRE(BASE16::encode(root_xsk_enc.decrypt(password).xbytes()) == root_xsk_base16);
    }

    SECTION("testBasicSignature")
    {
        constexpr auto prv_key_bytes = ByteArray<32>{
            0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60, 0xba, 0x84, 0x4a,
            0xf4, 0x92, 0xec, 0x2c, 0xc4, 0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32,
            0x69, 0x19, 0x70, 0x3b, 0xac, 0x03, 0x1c, 0xae, 0x7f, 0x60
        };

        constexpr auto pub_key_bytes = ByteArray<32>{
            0xd7, 0x5a, 0x98, 0x01, 0x82, 0xb1, 0x0a, 0xb7, 0xd5, 0x4b, 0xfe,
            0xd3, 0xc9, 0x64, 0x07, 0x3a, 0x0e, 0xe1, 0x72, 0xf3, 0xda, 0xa6,
            0x23, 0x25, 0xaf, 0x02, 0x1a, 0x68, 0xf7, 0x07, 0x51, 0x1a
        };

        constexpr auto sig_bytes = ByteArray<64>{
            0xe5, 0x56, 0x43, 0x00, 0xc3, 0x60, 0xac, 0x72, 0x90, 0x86, 0xe2,
            0xcc, 0x80, 0x6e, 0x82, 0x8a, 0x84, 0x87, 0x7f, 0x1e, 0xb8, 0xe5,
            0xd9, 0x74, 0xd8, 0x73, 0xe0, 0x65, 0x22, 0x49, 0x01, 0x55, 0x5f,
            0xb8, 0x82, 0x15, 0x90, 0xa3, 0x3b, 0xac, 0xc6, 0x1e, 0x39, 0x70,
            0x1c, 0xf9, 0xb4, 0x6b, 0xd2, 0x5b, 0xf5, 0xf0, 0x59, 0x5b, 0xbe,
            0x24, 0x65, 0x51, 0x41, 0x43, 0x8e, 0x7a, 0x10, 0x0b
        };

        const auto xsk = bip32_ed25519::PrivateKey::fromSeed(prv_key_bytes);

        // Test signing an empty message
        auto msg = std::vector<uint8_t>{};
        const auto sig = xsk.sign(msg);
        REQUIRE(sig == sig_bytes);

        // Verify the signature
        const auto pub_key = xsk.publicKey();
        REQUIRE(pub_key.bytes() == pub_key_bytes);
        REQUIRE(pub_key.verifySignature(msg, sig));
    }

    SECTION("testAdvancedSignature")
    {
        constexpr auto prv_key_bytes = ByteArray<32>{
            0x72, 0xd4, 0xa5, 0x64, 0xca, 0x15, 0x49, 0x9b, 0x5e, 0x4e, 0x75,
            0xd8, 0xac, 0x0f, 0x28, 0x21, 0x7d, 0x32, 0x11, 0x4a, 0x0c, 0x64,
            0x9a, 0x7c, 0x8e, 0xaa, 0xdd, 0x0c, 0xc7, 0x8c, 0x52, 0x0b
        };
        
        constexpr auto pub_key_bytes = ByteArray<32>{
            0xc7, 0x66, 0xbd, 0x73, 0x83, 0x7c, 0x4f, 0xaa, 0x52, 0x15, 0x50,
            0x2f, 0x1e, 0xfc, 0x90, 0xc0, 0x03, 0xf7, 0x11, 0xbb, 0xef, 0x55,
            0x17, 0x00, 0x91, 0x02, 0x8a, 0x34, 0x49, 0x34, 0x08, 0xa9
        };

        constexpr auto sig_bytes = ByteArray<64>{
            0x8f, 0xc4, 0xf1, 0x79, 0x33, 0x0b, 0x64, 0x2d, 0xd8, 0x6c, 0xa9,
            0x36, 0x26, 0x51, 0xb8, 0x3b, 0x00, 0x6d, 0x83, 0x75, 0xcc, 0xef,
            0x81, 0x1d, 0x3c, 0x67, 0x06, 0xf9, 0x15, 0x94, 0x65, 0x1d, 0xf2,
            0x76, 0x99, 0x53, 0x72, 0x30, 0x46, 0xcc, 0xb9, 0xbf, 0xe6, 0x6a,
            0x66, 0x7e, 0x0d, 0x11, 0xfc, 0x3e, 0xa2, 0xd8, 0x22, 0x62, 0x34,
            0xfd, 0xd5, 0x16, 0x47, 0x65, 0x26, 0x0f, 0x7b, 0x05
        };

        const auto xsk = bip32_ed25519::PrivateKey::fromSeed(prv_key_bytes);

        // Test signing the message
        constexpr auto msg_str = std::string_view{
            "\x6c\x7e\x7b\x62\xeb\x24\x4a\x45\xd7\x84\x36\xe2\x97\x0d\xcd\x6c\x0f"
            "\x7d\xb8\x22\x97\xa8\x61\x40\xea\x58\xdd\x22\xc2\x19\x5a\xdb\xc9\x56"
            "\xd4\xc4\xec\x05\x35\x4b\x21\xef\xe2\x4c\xfc\xfe\x10\xe1\x76\x22\x36"
            "\x88\x48\x18\x0d\x2c\x46\x80\xcc\x21\x5e\x8c\xee\xa6\xcc\xe2\x22\x16"
            "\x1f\x1e\x09\x22\x39\x25\x3b\x97\x46\xf7\x88\x7d\xf2\x42\x5a\xb5\xa8"
            "\x80\xbd\xba\x98\x15\x3b\xe7\x86\xdc\x83\x8c\xbe\xca\x01\x6b\x1d\x06"
            "\x52\x4b\xd6\xbf\xba\x80\x9a\x8b\xb3\x7a\xda\xb1\x5d\x42\x41\x5f\x86"
            "\xec\x03\x58\x36\x5e\xa8\x7b\x81\x50\xb0\x54\x41\xd9\xd4\x98\x46\x87"
            "\x14\x85\xca\xae\x6d\xe3\x59\x73\x6c\x27\x18\x97\x36\xd8\xf1\x76\x5f"
            "\x3e\x5c\x5f\x6b\x92\x16\x83\x96\x39\x0b\xee\x94\xcf\xbd"
        };
        auto sig = xsk.sign(
            {reinterpret_cast<const uint8_t*>(msg_str.data()), msg_str.size()}
        );
        REQUIRE(sig == sig_bytes);

        // Verify the signature
        const auto pub_key = xsk.publicKey();
        REQUIRE(pub_key.bytes() == pub_key_bytes);
        REQUIRE(pub_key.verifySignature(
            {reinterpret_cast<const uint8_t*>(msg_str.data()), msg_str.size()},
            sig
        ));
    }
}