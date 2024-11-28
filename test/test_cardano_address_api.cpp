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
        REQUIRE(addr.toBech32() == base_addr_bech32);
        REQUIRE(cardano::BaseAddress::fromBech32(base_addr_bech32).toBech32() == base_addr_bech32);
    
        auto pmt_addr = cardano::EnterpriseAddress::fromKey(cardano::NetworkID::testnet, addr_xvk);
        REQUIRE(pmt_addr.toBech32() == payment_addr_bech32);
        REQUIRE(cardano::EnterpriseAddress::fromBech32(payment_addr_bech32).toBech32() == payment_addr_bech32);

        auto stake_addr = cardano::RewardsAddress::fromKey(cardano::NetworkID::testnet, stake_xvk);
        REQUIRE(stake_addr.toBech32() == stake_addr_bech32 );
        REQUIRE(cardano::RewardsAddress::fromBech32(stake_addr_bech32).toBech32() == stake_addr_bech32);

        REQUIRE(stake_addr.toBase16() == std::string("f6d2f2ef387333e15aea9333e9d908e57a2b513ec6d762884f70ae2a"));
        REQUIRE(stake_addr.toBase16(true) == std::string("e0f6d2f2ef387333e15aea9333e9d908e57a2b513ec6d762884f70ae2a"));
        REQUIRE(pmt_addr.toBase16() == std::string("54947bcf6b760319bcec250ec225fd1ce63baface47e34b44b73e4f9"));
        REQUIRE(pmt_addr.toBase16(true) == std::string("6054947bcf6b760319bcec250ec225fd1ce63baface47e34b44b73e4f9"));
        REQUIRE(addr.toBase16() == std::string("54947bcf6b760319bcec250ec225fd1ce63baface47e34b44b73e4f9f6d2f2ef387333e15aea9333e9d908e57a2b513ec6d762884f70ae2a"));
        REQUIRE(addr.toBase16(true) == std::string("0054947bcf6b760319bcec250ec225fd1ce63baface47e34b44b73e4f9f6d2f2ef387333e15aea9333e9d908e57a2b513ec6d762884f70ae2a"));
    }

    SECTION("testBasicByronAddresses")
    {
        // The tests setup here verify the data supplied in the Cardano documentation at:
        // https://input-output-hk.github.io/cardano-wallet/concepts/byron-address-format

        std::string yoroi_base58 = "Ae2tdPwUPEZFRbyhz3cpfC2CumGzNkFBN2L42rcUc2yjQpEkxDbkPodpMAi";
        std::vector<uint8_t> yoroi_cbor = {
            0x82, 0xD8, 0x18, 0x58, 0x21, 0x83, 0x58, 0x1C, 0xBA, 0x97, 0x0A, 0xD3, 0x66, 0x54, 0xD8,
            0xDD, 0x8F, 0x74, 0x27, 0x4B, 0x73, 0x34, 0x52, 0xDD, 0xEA, 0xB9, 0xA6, 0x2A, 0x39, 0x77,
            0x46, 0xBE, 0x3C, 0x42, 0xCC, 0xDD, 0xA0, 0x00, 0x1A, 0x90, 0x26, 0xDA, 0x5B
        };
        auto yoroi_addr_from_str = cardano::ByronAddress::fromBase58(yoroi_base58);
        auto yoroi_addr_from_cbor = cardano::ByronAddress::fromCBOR(yoroi_cbor);
        REQUIRE(yoroi_addr_from_str.toBase58() == yoroi_base58);
        REQUIRE(yoroi_addr_from_cbor.toBase58() == yoroi_base58);

        std::string addr_base58 = "37btjrVyb4KEB2STADSsj3MYSAdj52X5FrFWpw2r7Wmj2GDzXjFRsHWuZqrw7zSkwopv8Ci3VWeg6bisU9dgJxW5hb2MZYeduNKbQJrqz3zVBsu9nT";
        std::vector<uint8_t> addr_cbor = {
            0x82, 0xD8, 0x18, 0x58, 0x49, 0x83, 0x58, 0x1C, 0x9C, 0x70, 0x85, 0x38, 0xA7, 0x63, 0xFF,
            0x27, 0x16, 0x99, 0x87, 0xA4, 0x89, 0xE3, 0x50, 0x57, 0xEF, 0x3C, 0xD3, 0x77, 0x8C, 0x05,
            0xE9, 0x6F, 0x7B, 0xA9, 0x45, 0x0E, 0xA2, 0x01, 0x58, 0x1E, 0x58, 0x1C, 0x9C, 0x17, 0x22,
            0xF7, 0xE4, 0x46, 0x68, 0x92, 0x56, 0xE1, 0xA3, 0x02, 0x60, 0xF3, 0x51, 0x0D, 0x55, 0x8D,
            0x99, 0xD0, 0xC3, 0x91, 0xF2, 0xBA, 0x89, 0xCB, 0x69, 0x77, 0x02, 0x45, 0x1A, 0x41, 0x70,
            0xCB, 0x17, 0x00, 0x1A, 0x69, 0x79, 0x12, 0x6C
        };
        auto addr_from_str = cardano::ByronAddress::fromBase58(addr_base58);
        auto addr_from_cbor = cardano::ByronAddress::fromCBOR(addr_cbor);
        REQUIRE(addr_from_str.toBase58() == addr_base58);
        REQUIRE(addr_from_cbor.toBase58() == addr_base58);
    }

    SECTION("testByronAddressGenerationFromKeys")
    {
        std::string root_prv_base16 = "5079457179b48efd3be6bfe351959c490df067defba703b5e8264ad7fc4b304c175f5a248c8762de70feae23b647b33f63ea478c16803eb7137afd194166eabf";
        std::string root_pub_base16 = "e34ccf1393dc758f0042d9e9c0a7f7151e0f046e3ca1c6b0764475e1d03e0372";
        std::string root_cc_base16 = "da644915ce8c9b7333b43a05d029064f570b2ff1d865165968e06f10cb4894d8";
        std::string addr_0H0H_base58 = "DdzFFzCqrht4nJCMRgF8xpNMbHFj3xjZn6f4ngpnUujcNXpm5KQFYgU7jwj42ZyjNyjnUqq5ngfEH5YS6hpykqvE78BHTMvgauTBQdsb";
        std::string addr_0H869280224H_base58 = "DdzFFzCqrhsw7KpiDuCQfhf6szHmZqqZRUrPEkj8ij7yx2ahM3jh1LAFYjTmqCGuTp6BVqPbAfddHGwAinLNtyPmojLe1jx3UU6vzqKc";
        std::string addr_0H2071358278H_base58 = "DdzFFzCqrhsemgxPDQLmn6auZnUbzaxeEj6FLZuwAP5pK6WrCandFPhcGGrc5h5LR8zz67YHfiCnKsLFFgSbDtfN93guwXxYTrS5XEYd";
        std::string addr_0H2075417326H_base58 = "DdzFFzCqrhsjUUQkiBpCSYkWLtJPmrPKjg2RPK6hRTgyejsraJh2HKQcHwdDdBHpNCvNLj2PxBrUGMxyvuQtULKv7yLzfmfEo5S5vx8z";
        std::string addr_0H492230898H_base58 = "DdzFFzCqrht7XNfGYnNyan5fKfLQWs8KVUZ9Jab65r87cvs2vyJ4n9gaCPUGdHMzSA8qKo8x6E76Di4xQQukcVdtaSmwpVkv5ZiUmJa3";

        const auto root_prv_bytes = util::makeByteArray<64>(BASE16::decode(root_prv_base16));
        const auto root_cc_bytes = util::makeByteArray<32>(BASE16::decode(root_cc_base16));

        auto root_xprv_enc = bip32_ed25519::EncryptedPrivateKey(root_prv_bytes, root_cc_bytes);
        auto root_xprv = root_xprv_enc.decrypt(R"(B1CD6Vv9$%@W5Vo%iR5$pv01)");
        REQUIRE(BASE16::encode(root_xprv.publicKey().xbytes()) == root_pub_base16 + root_cc_base16);

        auto addr_0H0H_from_str = cardano::ByronAddress::fromBase58(addr_0H0H_base58);
        auto addr_0H869280224H_from_str = cardano::ByronAddress::fromBase58(addr_0H869280224H_base58);
        auto addr_0H2071358278H_from_str = cardano::ByronAddress::fromBase58(addr_0H2071358278H_base58);
        auto addr_0H2075417326H_from_str = cardano::ByronAddress::fromBase58(addr_0H2075417326H_base58);
        auto addr_0H492230898H_from_str = cardano::ByronAddress::fromBase58(addr_0H492230898H_base58);

        REQUIRE(addr_0H0H_from_str.toBase58() == addr_0H0H_base58);
        REQUIRE(addr_0H869280224H_from_str.toBase58() == addr_0H869280224H_base58);
        REQUIRE(addr_0H2071358278H_from_str.toBase58() == addr_0H2071358278H_base58);
        REQUIRE(addr_0H2075417326H_from_str.toBase58() == addr_0H2075417326H_base58);
        REQUIRE(addr_0H492230898H_from_str.toBase58() == addr_0H492230898H_base58);

        auto derivation_path_0H0H = std::vector<uint32_t>{bip32_ed25519::HardenIndex(0), bip32_ed25519::HardenIndex(0)};
        auto derivation_path_0H869280224H = std::vector<uint32_t>{bip32_ed25519::HardenIndex(0), bip32_ed25519::HardenIndex(869280224)};
        auto derivation_path_0H2071358278H = std::vector<uint32_t>{bip32_ed25519::HardenIndex(0), bip32_ed25519::HardenIndex(2071358278)};
        auto derivation_path_0H2075417326H = std::vector<uint32_t>{bip32_ed25519::HardenIndex(0), bip32_ed25519::HardenIndex(2075417326)};
        auto derivation_path_0H492230898H = std::vector<uint32_t>{bip32_ed25519::HardenIndex(0), bip32_ed25519::HardenIndex(492230898)};

        auto addr_0H0H_from_key = cardano::ByronAddress::fromRootKey(root_xprv, derivation_path_0H0H);
        auto addr_0H869280224H_from_key = cardano::ByronAddress::fromRootKey(root_xprv, derivation_path_0H869280224H);
        auto addr_0H2071358278H_from_key = cardano::ByronAddress::fromRootKey(root_xprv, derivation_path_0H2071358278H);
        auto addr_0H2075417326H_from_key = cardano::ByronAddress::fromRootKey(root_xprv, derivation_path_0H2075417326H);
        auto addr_0H492230898H_from_key = cardano::ByronAddress::fromRootKey(root_xprv, derivation_path_0H492230898H);

        REQUIRE(addr_0H0H_from_key.toBase58() == addr_0H0H_base58);
        REQUIRE(addr_0H869280224H_from_key.toBase58() == addr_0H869280224H_base58);
        REQUIRE(addr_0H2071358278H_from_key.toBase58() == addr_0H2071358278H_base58);
        REQUIRE(addr_0H2075417326H_from_key.toBase58() == addr_0H2075417326H_base58);
        REQUIRE(addr_0H492230898H_from_key.toBase58() == addr_0H492230898H_base58);
    }
}
