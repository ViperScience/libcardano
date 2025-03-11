// MIT License
//
// Copyright (c) 2021-2024 Viper Staking
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
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

#include <catch2/catch_test_macros.hpp>

// Libcardano Headers
#include <cardano/address.hpp>
#include <cardano/bip32_ed25519.hpp>
#include <cardano/encodings.hpp>
#include <cardano/ledger.hpp>
#include <cardano/stake_pool.hpp>
#include <cardano/transaction.hpp>
#include <cardano/util.hpp>

TEST_CASE("testCardanoShelleyTransactionBuilder")
{
    constexpr auto seed_phrase =
        "exercise club noble adult miracle awkward problem olympic puppy "
        "private goddess piano fatal fashion vacuum";
    const auto mn =
        cardano::Mnemonic(seed_phrase, cardano::BIP39Language::English);
    const auto root_xsk = cardano::bip32_ed25519::PrivateKey::fromMnemonic(mn);

    using cardano::bip32_ed25519::HardenIndex;
    const auto payment_xsk = root_xsk.deriveChild(HardenIndex(1852))
                                 .deriveChild(HardenIndex(1815))
                                 .deriveChild(HardenIndex(0))
                                 .deriveChild(0)
                                 .deriveChild(0);

    const auto rewards_xsk = root_xsk.deriveChild(HardenIndex(1852))
                                 .deriveChild(HardenIndex(1815))
                                 .deriveChild(HardenIndex(0))
                                 .deriveChild(2)
                                 .deriveChild(0);

    constexpr auto utxo_id =
        std::array<uint8_t, 32>{0xe3, 0x03, 0x65, 0xe4, 0x30, 0x0d, 0xb8, 0xe8,
                                0xf9, 0x83, 0x44, 0x03, 0xe4, 0xad, 0xb1, 0xc3,
                                0xaa, 0x59, 0x43, 0xbc, 0x03, 0xd9, 0x9f, 0xf5,
                                0x32, 0x04, 0xd7, 0x63, 0xa6, 0x80, 0x09, 0x52};

    auto change_addr = cardano::BaseAddress::fromBech32(
        "addr1q90npzsed8jgy868pxk7l6j9yt586rt7967vtpynuemtgaw2hc28qjn559ea96hy6gwzmm6c0rc6cf3unvw29wadw98slryedc"
    );

    auto to_addr = cardano::BaseAddress::fromBech32(
        "addr1qxkfg5kgh43t29l5ev6hvqdnfx3d4lf09qn298ua66nvdaxgj0v7sm7gyn0l3huhuwn6ktgvrny9wyqx4px3l3ldu4uq7czuxe"
    );

    auto rewards_addr = cardano::RewardsAddress::fromBech32(
        "stake1u89tu9rsff62zu7jatjdy8pdaav83udvyc7fk89zhwkhzncapqzhe"
    );

    SECTION("testSimpleTransaction")
    {
        const auto tx_id =
            "6d190456920e396c39583f1f668b53e551b19adc251144be9c810ca6368a59fb";

        auto tx_builder = cardano::TransactionBuilder();

        tx_builder.addInput(utxo_id, 0UL)
            .addOutput(change_addr, 9969478417UL)
            .addOutput(to_addr, 10000000UL)
            .setFee(173861UL)
            .setTtl(13044029UL)
            .sign(payment_xsk)
            .sign(payment_xsk);  // ensure duplicates are removed

        const auto tx = tx_builder.getTransaction();
        REQUIRE(tx.transaction_witness_set.vkeywitnesses.size() == 1);
        REQUIRE(cardano::BASE16::encode(tx_builder.getID()) == tx_id);
    }

    SECTION("testWithdrawalTransaction")
    {
        auto tx_raw_cbor =
            "83a50082825820e30365e4300db8e8f9834403e4adb1c3aa5943bc03d99ff53204"
            "d763a680095204825820e30365e4300db8e8f9834403e4adb1c3aa5943bc03d99f"
            "f53204d763a680095205018282583901ac9452c8bd62b517f4cb357601b349a2da"
            "fd2f2826a29f9dd6a6c6f4c893d9e86fc824dff8df97e3a7ab2d0c1cc8571006a8"
            "4d1fc7ede5781a05f5e100825839015f308a1969e4821f4709adefea4522e87d0d"
            "7e2ebcc58493e676b475cabe14704a74a173d2eae4d21c2def5878f1ac263c9b1c"
            "a2bbad714f1a0683ed67021a0002aeb5031a00c7093d05a1581de1cabe14704a74"
            "a173d2eae4d21c2def5878f1ac263c9b1ca2bbad714f1a00989680a0f6";

        auto tx_builder = cardano::shelley::TransactionBuilder();
        tx_builder.setTtl(13044029UL)
            .addInput({utxo_id, 5UL, 165898624})
            .addInput({utxo_id, 4UL, 33586460})
            .addOutput(to_addr, 100000000UL)
            .setChangeAddress(change_addr)
            .addWithdrawal(rewards_addr, 10000000UL)
            .balance(2);

        REQUIRE(cardano::BASE16::encode(tx_builder.serialize()) == tx_raw_cbor);
    }

    SECTION("testTransactionBalancing")
    {
        auto tx_builder1 = cardano::shelley::TransactionBuilder();
        tx_builder1.setTtl(13044029UL)
            .addInput({utxo_id, 5UL, 165898624})
            .addInput({utxo_id, 4UL, 33586460})
            .addWithdrawal(rewards_addr, 10000000UL)
            .addOutput(to_addr, 100000000UL)
            .setChangeAddress(change_addr)
            .balance(2);

        auto tx_builder2 = cardano::shelley::TransactionBuilder();
        tx_builder2.setTtl(13044029UL)
            .addInput({utxo_id, 5UL, 165898624UL})
            .addInput({utxo_id, 4UL, 33586460UL})
            .addWithdrawal(rewards_addr, 10000000UL)
            .addOutput(to_addr, 100000000UL)
            .addOutput(
                change_addr,
                165898624UL + 33586460UL + 10000000UL - 100000000UL - 175797UL
            )
            .setFee(175797UL);

        REQUIRE(
            cardano::BASE16::encode(tx_builder1.serialize()) ==
            cardano::BASE16::encode(tx_builder2.serialize())
        );
    }

    SECTION("testTransactionSerialization")
    {
        // Add a certificate to the transaction to make things more interesting...
        auto cert_mgr = cardano::stake_pool::DeregistrationCertificateManager(
            cardano::stake_pool::ColdVerificationKey(std::array<uint8_t, 32>{
                0xd7, 0x5a, 0x98, 0x01, 0x82, 0xb1, 0x0a, 0xb7,
                0xd5, 0x4b, 0xfe, 0xd3, 0xc9, 0x64, 0x07, 0x3a,
                0x0e, 0xe1, 0x72, 0xf3, 0xda, 0xa6, 0x23, 0x25,
                0xaf, 0x02, 0x1a, 0x68, 0xf7, 0x07, 0x51, 0x1a
            }),
            459
        );

        auto tx_builder1 = cardano::shelley::TransactionBuilder();
        tx_builder1.setTtl(13044029UL)
            .addInput({utxo_id, 5UL, 165898624})
            .addInput({utxo_id, 4UL, 33586460})
            .addWithdrawal(rewards_addr, 10000000UL)
            .addPoolRetirementCertificate(cert_mgr.certificate())
            .addOutput(to_addr, 100000000UL)
            .setChangeAddress(change_addr)
            .balance(2)
            .sign(payment_xsk)
            .sign(rewards_xsk);

        const auto tx_cbor = tx_builder1.serialize();

        auto tx_builder2 =
            cardano::shelley::TransactionBuilder::fromCBOR(tx_cbor);

        REQUIRE(
            cardano::BASE16::encode(tx_builder1.serialize()) ==
            cardano::BASE16::encode(tx_builder2.serialize())
        );

        REQUIRE(tx_builder1.getID() == tx_builder2.getID());
    }
}