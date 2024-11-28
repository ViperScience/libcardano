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
// #include <string_view>

// Third-party library headers
#include <catch2/catch_test_macros.hpp>

// Public libcardano headers
#include <cardano/address.hpp>
#include <cardano/bip32_ed25519.hpp>
#include <cardano/encodings.hpp>
#include <cardano/mnemonic.hpp>

using namespace cardano;
// using namespace std::literals;

TEST_CASE("testCardanoEd25519API")
{
    SECTION("testBasicMnemonicGeneration")
    {
        for (const size_t sz : {9, 12, 15, 18, 21, 24})
        {
            for (size_t n = 0; n < 1000; ++n)
            {
                auto mn = cardano::Mnemonic::generate(sz);
                REQUIRE(mn.size() == sz);
                REQUIRE(mn.verify_checksum());
            }
        }
    }

    SECTION("testMnemonicGeneration")
    {
        // This is an English recovery phrase, ordered left-to-right, then top-to-bottom.
        //
        // write       maid        rib
        // female      drama       awake
        // release     inhale      weapon
        // crush       mule        jump
        // sound       erupt       stereo
        //
        // It is 15 words long, so 15*11=165 bits of information, which is split into a 160 bit seed and 5 bit checksum.
        //
        // Using the dictionary, these words resolve to:
        //
        // 2036        1072        1479
        // 679         529         129
        // 1449        925         1986
        // 424         1162        967
        // 1662        615         1708
        //
        // Which is:
        //
        // Seed:
        // 11111110100 10000110000 10111000111
        // 01010100111 01000010001 00010000001
        // 10110101001 01110011101 11111000010
        // 00110101000 10010001010 01111000111
        // 11001111110 01001100111 110101
        // Checksum:                     01100
        //
        // Seed (base16):     fe90c2e3aa7422206d4b9df846a2453c7cfc99f5
        // Checksum (base16): 0c
        constexpr std::string_view seed_phrase = "write maid rib female drama awake release inhale weapon crush mule jump sound erupt stereo";
        constexpr std::array<uint16_t, 15> dictionary_indexes = {
            2036, 1072, 1479, 679, 529, 129, 1449, 925, 1986, 424, 1162, 967, 1662,
            615, 1708
        };
        constexpr std::array<uint8_t, 20> seed = {
            0b11111110, 0b10010000, 0b11000010, 0b11100011, 0b10101010,
            0b01110100, 0b00100010, 0b00100000, 0b01101101, 0b01001011,
            0b10011101, 0b11111000, 0b01000110, 0b10100010, 0b01000101,
            0b00111100, 0b01111100, 0b11111100, 0b10011001, 0b11110101
        };
        auto mn = cardano::Mnemonic(seed_phrase, cardano::BIP39Language::English);
        auto mn_idxs = mn.i();
        for (auto i = 0ul; i < dictionary_indexes.size(); i++)
            REQUIRE(dictionary_indexes[i] == mn_idxs[i]);

        REQUIRE(mn.checksum() == 0x0c);
        REQUIRE(mn.verify_checksum());
        auto mn_seed = mn.toSeed();
        for (auto i = 0ul; i < seed.size(); i++)
            REQUIRE(seed[i] == mn_seed[i]);
    }

    SECTION("testMnemonicToAddress")
    {
        constexpr std::string_view seed_phrase = "exercise club noble adult miracle awkward problem olympic puppy private goddess piano fatal fashion vacuum";    
        constexpr std::string_view root_xsk_bech32 = "root_xsk1hqzfzrgskgnpwskxxrv5khs7ess82ecy8za9l5ef7e0afd2849p3zryje8chk39nxtva0sww5me3pzkej4rvd5cae3q3v8eu7556n6pdrp4fdu8nsglynpmcppxxvfdyzdz5gfq3fefjepxhvqspmuyvmvqg8983";
        constexpr std::string_view addr_xvk_bech32 = "addr_xvk1grvg8qzmkmw2n0dm4pd0h3j4dv6yglyammyp733eyj629dc3z28v6wk22nfmru6xz0vl2s3y5xndyd57fu70hrt84c6zkvlwx6fdl7ct9j7yc";
        constexpr std::string_view base_addr_bech32 = "addr_test1qp2fg770ddmqxxduasjsas39l5wwvwa04nj8ud95fde7f70k6tew7wrnx0s4465nx05ajz890g44z0kx6a3gsnms4c4qq8ve0n";
        constexpr std::string_view payment_addr_bech32 = "addr_test1vp2fg770ddmqxxduasjsas39l5wwvwa04nj8ud95fde7f7guscp6v";

        auto    mn = cardano::Mnemonic(seed_phrase, cardano::BIP39Language::English);

        // Test the Shelley root key derivation.
        auto root_xsk = bip32_ed25519::PrivateKey::fromMnemonic(mn);
        REQUIRE(BECH32::encode("root_xsk", root_xsk.xbytes()) == root_xsk_bech32);

        // Derive the stake key from the root
        auto acct_xsk = root_xsk.deriveChild(bip32_ed25519::HardenIndex(1852))
                                .deriveChild(bip32_ed25519::HardenIndex(1815))
                                .deriveChild(bip32_ed25519::HardenIndex(0));
        auto acct_xvk = acct_xsk.publicKey();
        auto addr_xvk = acct_xvk.deriveChild(0).deriveChild(0);
        auto stake_xvk = acct_xvk.deriveChild(2).deriveChild(0);
        REQUIRE(BECH32::encode("addr_xvk", addr_xvk.xbytes()) == addr_xvk_bech32);

        // Derive the enterprise address
        auto pmt_addr = cardano::EnterpriseAddress::fromKey(cardano::NetworkID::testnet, addr_xvk);
        REQUIRE(pmt_addr.toBech32() == payment_addr_bech32);

        // Derive the base address
        auto addr = cardano::BaseAddress::fromKeys(cardano::NetworkID::testnet, addr_xvk, stake_xvk);
        REQUIRE(addr.toBech32() == base_addr_bech32);
    }

    SECTION("testMnemonicToStakeAddress")
    {
        constexpr std::string_view seed_phrase = "exercise club noble adult miracle awkward problem olympic puppy private goddess piano fatal fashion vacuum";    
        constexpr std::string_view root_xsk_bech32 = "root_xsk1hqzfzrgskgnpwskxxrv5khs7ess82ecy8za9l5ef7e0afd2849p3zryje8chk39nxtva0sww5me3pzkej4rvd5cae3q3v8eu7556n6pdrp4fdu8nsglynpmcppxxvfdyzdz5gfq3fefjepxhvqspmuyvmvqg8983";
        constexpr std::string_view stake_xvk_bech32 = "stake_xvk1658atzttunamzn80204khrg0qfdk5nvmrutlmmpg7xlsyaggwa7h9z4smmeqsvs67qhyqmc2lqa0vy36rf2la74ym8a5p93zp4qtpuq6ky3ve";
        constexpr std::string_view stake_addr_bech32 = "stake_test1urmd9uh08pen8c26a2fn86weprjh52638mrdwc5gfac2u2s25zpat";

        auto mn = cardano::Mnemonic(seed_phrase, cardano::BIP39Language::English);

        // Test the Shelley root key derivation.
        auto root_xsk = bip32_ed25519::PrivateKey::fromMnemonic(mn);
        REQUIRE(BECH32::encode("root_xsk", root_xsk.xbytes()) == root_xsk_bech32);

        // Derive the stake key from the root
        auto acct_xsk = root_xsk.deriveChild(bip32_ed25519::HardenIndex(1852))
                                .deriveChild(bip32_ed25519::HardenIndex(1815))
                                .deriveChild(bip32_ed25519::HardenIndex(0));
        auto acct_xvk = acct_xsk.publicKey();
        auto stake_xvk = acct_xvk.deriveChild(2).deriveChild(0);
        REQUIRE(BECH32::encode("stake_xvk", stake_xvk.xbytes()) == stake_xvk_bech32);

        // Derive the stake address
        auto stake_addr = cardano::RewardsAddress::fromKey(cardano::NetworkID::testnet, stake_xvk);
        REQUIRE(stake_addr.toBech32() == stake_addr_bech32);
    }
}