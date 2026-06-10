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
#include <cardano/encodings.hpp>
#include <cardano/tss.hpp>

// Use namespaces to make the code more readable
using namespace std::literals;
using namespace cardano::tss;
using cardano::BASE16;

TEST_CASE("testCardanoTssShamirSecretSharing")
{
    const auto msg = "This is a test"sv;
    const auto msg_bytes =
        std::span<const uint8_t>((const uint8_t*)msg.data(), msg.size());

    SECTION("Multiple random keys")
    {
        // Use Shamir Secret Sharing by setting t < n.
        constexpr auto num_key_shares = 4;
        constexpr auto num_threshold_shares = 3;
        const auto dealer = Dealer(num_key_shares, num_threshold_shares);
        REQUIRE(dealer.keySharesSize() == num_key_shares);
        REQUIRE(dealer.thresholdSize() == num_threshold_shares);

        // Generate a set of key shares
        auto [base_vk, key_shares] = dealer.generate();
        REQUIRE(key_shares.size() == num_key_shares);

        // Verify we can recompute the base public key from the key shares.
        // This also verifies we can re-construct the base private key.
        REQUIRE(
            BASE16::encode(dealer.compositeKey(key_shares).bytes()) ==
            BASE16::encode(base_vk.bytes())
        );

        // Take a non-consecutive subset of t keys to test creating a signature.
        auto key_shares_subset = std::vector<KeyShare>{};
        key_shares_subset.push_back(key_shares[0]);
        key_shares_subset.push_back(key_shares[1]);
        key_shares_subset.push_back(key_shares[3]);

        REQUIRE(key_shares_subset.size() == num_threshold_shares);

        // Calculate the Lagrange interpolation coefficients
        auto key_shares_subset_ids = std::vector<uint64_t>();
        for (const auto& k : key_shares_subset)
            key_shares_subset_ids.push_back(k.id);
        auto lagrange_coefficients =
            dealer.computeLagrangeCoefficients(key_shares_subset_ids);

        // Compute individual nonces for each key share and combine for the
        // shared signature nonce.
        auto nonce_shares = std::vector<std::array<uint8_t, 32>>();
        auto commitment_shares = std::vector<std::array<uint8_t, 32>>();
        for (const auto& k : key_shares_subset)
        {
            auto [c, n] = Signer::commitmentShareAndNonce(msg_bytes, k);
            commitment_shares.push_back(c);
            nonce_shares.push_back(n);
        }
        auto agg_commitment =
            dealer.aggregateCommitmentShares(commitment_shares);

        // Create signature shares for each key in the subset.
        auto signature_shares = std::vector<std::array<uint8_t, 64>>();
        for (int i = 0; i < key_shares_subset.size(); ++i)
        {
            const auto sig_share = Signer::signatureShare(
                msg_bytes,
                nonce_shares[i],
                agg_commitment,
                lagrange_coefficients[i],
                base_vk,
                key_shares_subset[i]
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
        const auto base_sk = dealer.compositeSigningKey(key_shares_subset);
        REQUIRE(base_vk.verifySignature(msg_bytes, base_sk.sign(msg_bytes)));
    }

    SECTION("More random keys with the stateful signer")
    {
        // Use Shamir Secret Sharing by setting t < n.
        constexpr auto num_key_shares = 150;
        constexpr auto num_threshold_shares = 130;
        const auto dealer = Dealer(num_key_shares, num_threshold_shares);
        REQUIRE(dealer.keySharesSize() == num_key_shares);
        REQUIRE(dealer.thresholdSize() == num_threshold_shares);

        // Generate a set of key shares
        auto [base_vk, key_shares] = dealer.generate();
        REQUIRE(key_shares.size() == num_key_shares);

        // Verify we can recompute the base public key from the key shares.
        // This also verifies we can re-construct the base private key.
        REQUIRE(
            BASE16::encode(dealer.compositeKey(key_shares).bytes()) ==
            BASE16::encode(base_vk.bytes())
        );

        // Take a subset of t keys to test creating a signature.
        auto key_shares_subset = std::vector<KeyShare>(
            key_shares.begin(), key_shares.begin() + num_threshold_shares
        );
        REQUIRE(key_shares_subset.size() == num_threshold_shares);

        // Calculate the Lagrange interpolation coefficients
        auto key_shares_subset_ids = std::vector<uint64_t>();
        for (const auto& k : key_shares_subset)
            key_shares_subset_ids.push_back(k.id);
        auto lagrange_coefficients =
            dealer.computeLagrangeCoefficients(key_shares_subset_ids);

        // Create a set of stateful signers
        auto signers = std::vector<StatefulSigner>();
        for (auto i = 0; i < key_shares_subset.size(); ++i)
        {
            signers.emplace_back(
                msg_bytes,
                base_vk,
                key_shares_subset[i],
                lagrange_coefficients[i]
            );
        }

        // Compute individual nonces for each key share and combine for the
        // shared signature nonce.
        auto commitment_shares = std::vector<std::array<uint8_t, 32>>();
        for (auto i = 0; i < key_shares_subset.size(); ++i)
        {
            commitment_shares.push_back(signers[i].commitmentShare());
        }
        auto agg_commitment =
            dealer.aggregateCommitmentShares(commitment_shares);

        // Create signature shares for each key in the subset.
        auto signature_shares = std::vector<std::array<uint8_t, 64>>();
        for (int i = 0; i < key_shares_subset.size(); ++i)
        {
            const auto sig_share = signers[i].signatureShare(agg_commitment);
            REQUIRE(!dealer.verifySignature(msg_bytes, sig_share, base_vk));
            signature_shares.push_back(sig_share);
        }

        // Aggregate the signature shares into the final signature.
        const auto agg_signature =
            dealer.aggregateSignatureShares(signature_shares);
        REQUIRE(dealer.verifySignature(msg_bytes, agg_signature, base_vk));

        // Re-create the base key and verify it can also produce a valid
        // signature.
        const auto base_sk = dealer.compositeSigningKey(key_shares_subset);
        REQUIRE(base_vk.verifySignature(msg_bytes, base_sk.sign(msg_bytes)));
    }
}
