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
#include <span>
#include <string_view>
#include <vector>

// Third-party library headers
#include <boost/multiprecision/cpp_int.hpp>
#include <cardano/bip32_ed25519.hpp>
#include <cardano/encodings.hpp>
#include <catch2/catch_test_macros.hpp>

// Public libcardano headers
#include <cardano/tss.hpp>

// Private libcardano headers
#include "test_utils.hpp"

// Use namespaces to make the code more readable
namespace mp = boost::multiprecision;
using namespace std::literals;
using namespace cardano::tss;

TEST_CASE("testCardanoTssDirectKeySplitting")
{
    const auto msg = "This is a test"sv;
    const auto msg_bytes =
        std::span<const uint8_t>((const uint8_t*)msg.data(), msg.size());

    SECTION("Single key, no aggregation")
    {
        const auto key = PrivateKey::generate();

        // Test the static (stateless) API
        const auto [commitment, nonce] =
            Signer::commitmentShareAndNonce(msg_bytes, {1, key});
        const auto ssig = Signer::signatureShare(
            msg_bytes, nonce, commitment, key.publicKey(), {1, key}
        );
        REQUIRE(Signer::verifySignature(msg_bytes, ssig, key.publicKey()));

        // Test the stateful API
        auto tss = StatefulSigner(msg_bytes, key.publicKey(), {1, key});
        const auto agg_com = tss.commitmentShare();
        const auto sig = tss.signatureShare(agg_com);
        REQUIRE(tss.verifySignature(sig));
    }

    SECTION("Single key, with aggregation")
    {
        const auto key = PrivateKey::generate();
        const auto dealer = Dealer(1);
        const auto [commitment, nonce] =
            Signer::commitmentShareAndNonce(msg_bytes, {1, key});
        const auto agg_commitment =
            dealer.aggregateCommitmentShares({commitment});
        const auto signature = Signer::signatureShare(
            msg_bytes, nonce, agg_commitment, key.publicKey(), {1, key}
        );
        const auto agg_signature = dealer.aggregateSignatureShares({signature});
        REQUIRE(
            dealer.verifySignature(msg_bytes, agg_signature, key.publicKey())
        );
    }

    SECTION("Double keys - fixed keys")
    {
        const auto dealer = Dealer(2);

        constexpr auto prv_key_bytes1 = std::array<uint8_t, 32>{
            0x72, 0xd4, 0xa5, 0x64, 0xca, 0x15, 0x49, 0x9b, 0x5e, 0x4e, 0x75,
            0xd8, 0xac, 0x0f, 0x28, 0x21, 0x7d, 0x32, 0x11, 0x4a, 0x0c, 0x64,
            0x9a, 0x7c, 0x8e, 0xaa, 0xdd, 0x0c, 0xc7, 0x8c, 0x52, 0x0b
        };
        constexpr auto prv_key_bytes2 = std::array<uint8_t, 32>{
            0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60, 0xba, 0x84, 0x4a,
            0xf4, 0x92, 0xec, 0x2c, 0xc4, 0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32,
            0x69, 0x19, 0x70, 0x3b, 0xac, 0x03, 0x1c, 0xae, 0x7f, 0x60
        };

        // Create two random private keys.
        const auto key1 = KeyShare{1, PrivateKey::fromSeed(prv_key_bytes1)};
        const auto key2 = KeyShare{2, PrivateKey::fromSeed(prv_key_bytes2)};

        // Create a base public key from the two keys.
        const auto base_vk = dealer.compositeKey({{key1, key2}});

        // Create a random nonce and commitment for each key to sign the
        // message.
        const auto [commitment1, nonce1] =
            Signer::commitmentShareAndNonce(msg_bytes, key1);
        const auto [commitment2, nonce2] =
            Signer::commitmentShareAndNonce(msg_bytes, key2);

        // Aggregate each commitment share into a single commitment.
        const auto agg_commitment =
            dealer.aggregateCommitmentShares({commitment1, commitment2});

        // Create the signature shares with the aggregate commitment and base
        // public key.
        const auto signature1 = Signer::signatureShare(
            msg_bytes, nonce1, agg_commitment, base_vk, key1
        );
        const auto signature2 = Signer::signatureShare(
            msg_bytes, nonce2, agg_commitment, base_vk, key2
        );

        // Aggregate the signature shares into the final signature.
        const auto agg_signature =
            dealer.aggregateSignatureShares({signature1, signature2});

        // Verify the aggregate signature is a valid signature with the base
        // public key.
        REQUIRE(base_vk.verifySignature(msg_bytes, agg_signature));
    }

    SECTION("Double keys - random keys")
    {
        const auto dealer = Dealer(2);

        // Create two random private keys.
        const auto key1 = KeyShare{1, PrivateKey::generate()};
        const auto key2 = KeyShare{2, PrivateKey::generate()};

        // Create a base public key from the two keys.
        const auto base_vk = dealer.compositeKey({{key1, key2}});

        // Create a random nonce and commitment for each key to sign the
        // message.
        const auto [commitment1, nonce1] =
            Signer::commitmentShareAndNonce(msg_bytes, key1);
        const auto [commitment2, nonce2] =
            Signer::commitmentShareAndNonce(msg_bytes, key2);

        // Aggregate each commitment share into a single commitment.
        const auto agg_commitment =
            dealer.aggregateCommitmentShares({commitment1, commitment2});

        // Create the signature shares with the aggregate commitment and base
        // public key.
        const auto signature1 = Signer::signatureShare(
            msg_bytes, nonce1, agg_commitment, base_vk, key1
        );
        const auto signature2 = Signer::signatureShare(
            msg_bytes, nonce2, agg_commitment, base_vk, key2
        );

        // Aggregate the signature shares into the final signature.
        const auto agg_signature =
            dealer.aggregateSignatureShares({signature1, signature2});

        // Verify the aggregate signature is a valid signature with the base
        // public key.
        REQUIRE(base_vk.verifySignature(msg_bytes, agg_signature));
    }

    SECTION("Multiple random keys")
    {
        // Use direct key splitting by setting t == n.
        constexpr auto num_key_shares = 4;
        const auto dealer = Dealer(num_key_shares);
        REQUIRE(dealer.thresholdSize() == num_key_shares);

        // Generate a set of key shares
        auto [base_vk, key_shares] = dealer.generate();
        REQUIRE(key_shares.size() == num_key_shares);

        // Verify we can recompute the base public key from the key shares.
        REQUIRE(
            cardano::BASE16::encode(dealer.compositeKey(key_shares).bytes()) ==
            cardano::BASE16::encode(base_vk.bytes())
        );

        // Verify we can recompute the base public key from the public key
        // shares.
        auto pub_key_shares = std::vector<PublicKey>();
        for (auto& k : key_shares)
        {
            pub_key_shares.push_back(k.publicKey());
        }
        REQUIRE(
            cardano::BASE16::encode(dealer.compositeKey(key_shares).bytes()) ==
            cardano::BASE16::encode(dealer.compositeKey(pub_key_shares).bytes())
        );

        auto nonce_shares = std::vector<std::array<uint8_t, 32>>();
        auto commitment_shares = std::vector<std::array<uint8_t, 32>>();
        for (auto const& sk : key_shares)
        {
            auto [c, n] = Signer::commitmentShareAndNonce(msg_bytes, sk);
            commitment_shares.push_back(c);
            nonce_shares.push_back(n);
        }
        auto agg_commitment =
            dealer.aggregateCommitmentShares(commitment_shares);

        auto signature_shares = std::vector<std::array<uint8_t, 64>>();
        for (int i = 0; i < key_shares.size(); ++i)
        {
            const auto sig_share = Signer::signatureShare(
                msg_bytes,
                nonce_shares[i],
                agg_commitment,
                base_vk,
                key_shares[i]
            );
            REQUIRE(!dealer.verifySignature(msg_bytes, sig_share, base_vk));
            signature_shares.push_back(sig_share);
        }

        // Aggregate the signature shares into the final signature.
        const auto agg_signature =
            dealer.aggregateSignatureShares(signature_shares);
        REQUIRE(dealer.verifySignature(msg_bytes, agg_signature, base_vk));

        // Re-create the base key and verify it can also produce a valid
        // signature.
        const auto base_sk = dealer.compositeSigningKey(key_shares);
        REQUIRE(base_sk.publicKey().bytes() == base_vk.bytes());
        REQUIRE(base_vk.verifySignature(msg_bytes, base_sk.sign(msg_bytes)));
    }

    SECTION("Integration")
    {
        // Test vectors from:
        // https://datatracker.ietf.org/doc/html/draft-hallambaker-threshold-sigs-06

        const auto dealer = Dealer(2);

        auto alice_seed_bytes = std::array<uint8_t, 32>{
            0x10, 0xAE, 0xC0, 0xC2, 0x16, 0x65, 0x9B, 0x4F, 0x7C, 0x9D, 0xDE,
            0x82, 0x3E, 0x49, 0x7F, 0xD4, 0x9B, 0x14, 0xBB, 0xF8, 0x2D, 0x9F,
            0x0C, 0x11, 0x24, 0xD7, 0x15, 0xE3, 0x43, 0x79, 0x57, 0x20
        };
        auto alice_skey = PrivateKey::fromSeed(alice_seed_bytes);

        auto alice_vkey_bytes = std::array<uint8_t, 32>{
            0x45, 0x16, 0x53, 0x7C, 0x26, 0x50, 0xCF, 0xDA, 0xF1, 0xA4, 0xDF,
            0x4C, 0x45, 0xDC, 0x3D, 0x95, 0x4E, 0xB6, 0x8E, 0xEB, 0xA6, 0x5A,
            0x27, 0xD6, 0xCD, 0x5B, 0x43, 0xC5, 0xF4, 0x06, 0x53, 0xED
        };
        REQUIRE(
            cardano::BASE16::encode(alice_skey.publicKey().bytes()) ==
            cardano::BASE16::encode(alice_vkey_bytes)
        );

        auto bob_seed_bytes = std::array<uint8_t, 32>{
            0xE5, 0xCD, 0x34, 0x01, 0xFD, 0x8C, 0x0E, 0x27, 0x81, 0x4B, 0x11,
            0xDD, 0x12, 0x68, 0x50, 0xA1, 0x4B, 0x5A, 0xD5, 0xE1, 0xE1, 0x41,
            0xD7, 0x68, 0x5F, 0x51, 0xED, 0xB4, 0x3A, 0x84, 0x58, 0x5C
        };
        auto bob_skey = PrivateKey::fromSeed(bob_seed_bytes);

        auto bob_vkey_bytes = std::array<uint8_t, 32>{
            0xF1, 0x5F, 0xC0, 0x78, 0xF8, 0x32, 0x49, 0x2C, 0xD9, 0x64, 0xCC,
            0x2B, 0xCF, 0x90, 0x5C, 0x4F, 0x23, 0xEA, 0xBB, 0xF8, 0x38, 0x99,
            0xC5, 0xFE, 0xF3, 0xAA, 0x67, 0xBE, 0xAB, 0xEC, 0xD2, 0x5E
        };
        REQUIRE(
            cardano::BASE16::encode(bob_skey.publicKey().bytes()) ==
            cardano::BASE16::encode(bob_vkey_bytes)
        );

        auto base_vkey_bytes = std::array<uint8_t, 32>{
            0x48, 0x1A, 0x27, 0x66, 0x06, 0xAF, 0x4E, 0x3C, 0x20, 0xA4, 0x02,
            0xCD, 0x8A, 0x13, 0x46, 0x99, 0x02, 0xB7, 0x75, 0xF8, 0xAC, 0xD4,
            0x7E, 0x89, 0x68, 0xFB, 0x68, 0xEB, 0xD8, 0xEF, 0x4A, 0xC7
        };

        auto key_shares = std::vector<KeyShare>{{1, alice_skey}, {2, bob_skey}};
        auto pub_key_shares = std::vector<PublicKey>{
            alice_skey.publicKey(), bob_skey.publicKey()
        };
        auto base_vkey = dealer.compositeKey(key_shares);

        REQUIRE(
            cardano::BASE16::encode(base_vkey.bytes()) ==
            cardano::BASE16::encode(base_vkey_bytes)
        );

        REQUIRE(
            cardano::BASE16::encode(
                dealer.compositeKey(pub_key_shares).bytes()
            ) == cardano::BASE16::encode(base_vkey_bytes)
        );

        auto alice_R = std::array<uint8_t, 32>{
            0xDF, 0xA3, 0xD5, 0xCC, 0x9F, 0x94, 0x63, 0x67, 0xBB, 0x3E, 0xC3,
            0xF7, 0x88, 0x4A, 0x0D, 0x52, 0x00, 0x20, 0xA2, 0x90, 0x13, 0x27,
            0x4E, 0x47, 0x03, 0x19, 0xDA, 0xEC, 0xBF, 0x74, 0xCB, 0x14
        };
        auto alice_nonce = cardano_test::CppIntToBytes(
            mp::cpp_int(
                "5052107346214975953932707847456141751131916641574177425600105798482114377785"sv
            )
        );

        auto [alice_Rb, alice_ri] =
            Signer::commitmentShareFromNonce(alice_nonce);
        REQUIRE(
            cardano::BASE16::encode(alice_Rb) ==
            cardano::BASE16::encode(alice_R)
        );

        auto bob_R = std::array<uint8_t, 32>{
            0xDD, 0xC8, 0x79, 0x2A, 0xBB, 0xD8, 0x72, 0xD5, 0x9D, 0xF5, 0x13,
            0x22, 0xC2, 0xF1, 0x58, 0x62, 0x47, 0xDC, 0x19, 0x39, 0xC5, 0xCE,
            0x02, 0xFB, 0x24, 0x0B, 0xFA, 0x64, 0xD1, 0x55, 0xBC, 0x3E
        };
        auto bob_nonce = cardano_test::CppIntToBytes(
            mp::cpp_int(
                "6778802174860340747202025463674101745619506775745309900070354323071886227867"sv
            )
        );

        auto [bob_Rb, bob_ri] = Signer::commitmentShareFromNonce(bob_nonce);
        REQUIRE(
            cardano::BASE16::encode(bob_Rb) == cardano::BASE16::encode(bob_R)
        );

        auto composite_R = std::array<uint8_t, 32>{
            0x5A, 0xD0, 0x1C, 0x17, 0x95, 0xED, 0x9B, 0x99, 0xB8, 0xCD, 0xCE,
            0x7B, 0xEE, 0x47, 0x6E, 0xA5, 0x0E, 0xA6, 0xCF, 0x51, 0xDE, 0xDA,
            0x89, 0xCB, 0xB5, 0xF4, 0x4C, 0xE2, 0xD5, 0x0D, 0x58, 0xFA
        };

        REQUIRE(
            cardano::BASE16::encode(
                dealer.aggregateCommitmentShares({alice_Rb, bob_Rb})
            ) == cardano::BASE16::encode(composite_R)
        );

        // Create an aggregate signature using the key shares and verify it
        // works.
        const auto alice_sig = Signer::signatureShare(
            msg_bytes, alice_ri, composite_R, base_vkey, {1, alice_skey}
        );
        const auto bob_sig = Signer::signatureShare(
            msg_bytes, bob_ri, composite_R, base_vkey, {2, bob_skey}
        );
        const auto composite_sig =
            dealer.aggregateSignatureShares({alice_sig, bob_sig});
        REQUIRE(Signer::verifySignature(msg_bytes, composite_sig, base_vkey));
    }
}
