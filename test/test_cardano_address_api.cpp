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
#include <cardano/address.hpp>
#include <cardano/bip32_ed25519.hpp>
#include <cardano/encodings.hpp>
#include <cardano/util.hpp>

using namespace cardano;
using namespace std::literals;

TEST_CASE("testCardanoEd25519API")
{
    constexpr auto root_xsk_bech32 = "root_xsk1hqzfzrgskgnpwskxxrv5khs7ess82ecy8za9l5ef7e0afd2849p3zryje8chk39nxtva0sww5me3pzkej4rvd5cae3q3v8eu7556n6pdrp4fdu8nsglynpmcppxxvfdyzdz5gfq3fefjepxhvqspmuyvmvqg8983"sv;
    constexpr auto base_addr_bech32 = "addr_test1qp2fg770ddmqxxduasjsas39l5wwvwa04nj8ud95fde7f70k6tew7wrnx0s4465nx05ajz890g44z0kx6a3gsnms4c4qq8ve0n"sv;
    constexpr auto stake_addr_bech32 = "stake_test1urmd9uh08pen8c26a2fn86weprjh52638mrdwc5gfac2u2s25zpat"sv;
    constexpr auto payment_addr_bech32 = "addr_test1vp2fg770ddmqxxduasjsas39l5wwvwa04nj8ud95fde7f7guscp6v"sv;

    SECTION("testAddressGenerationFromKeys")
    {
        const auto [hrp1, data] = BECH32::decode(root_xsk_bech32);
        auto root_xsk = bip32_ed25519::PrivateKey(util::makeByteArray<96>(data));
        auto acct_xsk = root_xsk.deriveChild(bip32_ed25519::HardenIndex(1852))
                                .deriveChild(bip32_ed25519::HardenIndex(1815))
                                .deriveChild(bip32_ed25519::HardenIndex(0));
        auto acct_xvk = acct_xsk.publicKey();
        auto addr_xvk = acct_xvk.deriveChild(0).deriveChild(0);
        auto stake_xvk = acct_xvk.deriveChild(2).deriveChild(0);

        auto addr = cardano::BaseAddress::fromKeys(cardano::NetworkID::testnet, addr_xvk, stake_xvk);
        REQUIRE(addr.toBech32("addr_test") == base_addr_bech32);
        REQUIRE(cardano::BaseAddress::fromBech32(base_addr_bech32).toBech32("addr_test") == base_addr_bech32);
    
        auto pmt_addr = cardano::EnterpriseAddress::fromKey(cardano::NetworkID::testnet, addr_xvk);
        REQUIRE(pmt_addr.toBech32("addr_test") == payment_addr_bech32);
        REQUIRE(cardano::EnterpriseAddress::fromBech32(payment_addr_bech32).toBech32("addr_test") == payment_addr_bech32);

        auto stake_addr = cardano::RewardsAddress::fromKey(cardano::NetworkID::testnet, stake_xvk);
        REQUIRE(stake_addr.toBech32("stake_test") == stake_addr_bech32 );
        REQUIRE(cardano::RewardsAddress::fromBech32(stake_addr_bech32).toBech32("stake_test") == stake_addr_bech32);

        REQUIRE(stake_addr.toBase16() == std::string("f6d2f2ef387333e15aea9333e9d908e57a2b513ec6d762884f70ae2a"));
        REQUIRE(stake_addr.toBase16(true) == std::string("e0f6d2f2ef387333e15aea9333e9d908e57a2b513ec6d762884f70ae2a"));
        REQUIRE(pmt_addr.toBase16() == std::string("54947bcf6b760319bcec250ec225fd1ce63baface47e34b44b73e4f9"));
        REQUIRE(pmt_addr.toBase16(true) == std::string("6054947bcf6b760319bcec250ec225fd1ce63baface47e34b44b73e4f9"));
        REQUIRE(addr.toBase16() == std::string("54947bcf6b760319bcec250ec225fd1ce63baface47e34b44b73e4f9f6d2f2ef387333e15aea9333e9d908e57a2b513ec6d762884f70ae2a"));
        REQUIRE(addr.toBase16(true) == std::string("0054947bcf6b760319bcec250ec225fd1ce63baface47e34b44b73e4f9f6d2f2ef387333e15aea9333e9d908e57a2b513ec6d762884f70ae2a"));
    }
}
