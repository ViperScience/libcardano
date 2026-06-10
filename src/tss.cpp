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

// System Headers
#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <stdexcept>

// Third-Party Library Headers
#include <botan/auto_rng.h>
#include <botan/hash.h>
#include <botan/rng.h>
#include <botan/system_rng.h>
#include <sodium.h>

// Public libcardano Headers
#include <cardano/bip32_ed25519.hpp>
#include <cardano/curve25519.hpp>
#include <cardano/ed25519.hpp>
#include <cardano/tss.hpp>
#include <cardano/util.hpp>

using namespace cardano;

using tss::Dealer;
using tss::KeyShare;
using tss::Signer;
using tss::StatefulSigner;

// libsodium-backed Ed25519 scalar / point primitives (see tss_ed25519.hpp).
using cardano::tss::ed25519::EncodedPointAdd;
using cardano::tss::ed25519::Point;
using cardano::tss::ed25519::Scalar;

namespace
{  // unnamed namespace

template <size_t Size>
auto GenerateEntropy() -> std::array<uint8_t, Size>
{
    std::unique_ptr<Botan::RandomNumberGenerator> rng;
#if defined(BOTAN_HAS_SYSTEM_RNG)
    rng = std::make_unique<Botan::System_RNG>();
#else
    rng = std::make_unique<Botan::AutoSeeded_RNG>();
#endif
    auto ent = std::array<uint8_t, Size>();
    rng->randomize(ent.data(), Size);
    return ent;
}  // GenerateEntropy

auto MakeCompositeChainCode(std::span<const KeyShare> key_shares)
    -> std::array<uint8_t, 32>
{
    auto cc = std::array<uint8_t, 32>();
    const auto sha256 = Botan::HashFunction::create("SHA-256");
    for (auto& sk : key_shares)
    {
        sha256->update(sk.key.publicKey().bytes());
    }
    sha256->final(cc);
    return cc;
}  // MakeCompositeChainCode

auto MakeCompositeChainCode(std::span<const PublicKey> key_shares)
    -> std::array<uint8_t, 32>
{
    auto cc = std::array<uint8_t, 32>();
    const auto sha256 = Botan::HashFunction::create("SHA-256");
    for (auto& vk : key_shares)
    {
        sha256->update(vk.bytes());
    }
    sha256->final(cc);
    return cc;
}  // MakeCompositeChainCode

auto PrivateKeyToScalar(const PrivateKey& sk) -> Scalar
{
    const auto kl = std::span<const uint8_t, 32>{sk.bytes().data(), 32};
    return Scalar::reduce(kl);
}  // PrivateKeyToScalar

auto Ed25519ScalarToExtendedKey(Scalar scalar) -> PrivateKey
{
    // The scalar already represents the key secret value. Use a SHA-512 hash
    // of the packed 32-byte scalar (kL) to fill the upper 32 bytes (kR) of the
    // 64-byte key and the 32-byte chain code (CC).
    auto key_bytes = std::array<uint8_t, 96>{};
    auto scalar_bytes = scalar.bytes();
    std::copy_n(scalar_bytes.begin(), 32, key_bytes.begin());
    const auto sha512 = Botan::HashFunction::create("SHA-512");
    sha512->update("cardano-tss-key-extension-v1");
    sha512->update({key_bytes.data(), 32});
    sha512->final(key_bytes.data() + 32);
    return PrivateKey(key_bytes);
}  // Ed25519ScalarToExtendedKey

auto Ed25519DirectKeySplit(const PrivateKey& root, uint32_t n)
    -> std::pair<PublicKey, std::vector<KeyShare>>
{
    auto keys = std::vector<KeyShare>();
    keys.reserve(n);

    auto ss = PrivateKeyToScalar(root);
    // Placeholder, overwritten on the first loop iteration; [1]B == basepoint,
    // preserving the legacy basepoint() initializer for the degenerate n == 1.
    auto ab = Point::mulBasepoint(Scalar::fromUint(1));
    for (size_t i = 0; i < (n - 1); ++i)
    {
        const auto ki = PrivateKey::generate();
        const auto ai = PrivateKeyToScalar(ki);
        ss = ss - ai;
        if (i == 0)
        {
            ab = Point::mulBasepoint(ai);
        }
        else
        {
            ab = ab + Point::mulBasepoint(ai);
        }
        keys.push_back({.id = (i + 1), .key = ki});
    }

    // Save the last private key share
    keys.push_back({.id = n, .key = Ed25519ScalarToExtendedKey(ss)});

    // Finalize the composite public key
    ab = ab + Point::mulBasepoint(ss);
    auto pub = PublicKey(ab.bytes(), MakeCompositeChainCode(keys));

    return std::make_pair(pub, keys);
}  // Ed25519DirectKeySplit

auto Ed25519ShamirKeySplit(
    const PrivateKey& root,
    uint32_t n,
    uint32_t t,
    std::span<const Scalar> coefs
) -> std::pair<PublicKey, std::vector<KeyShare>>
{
    const auto s = PrivateKeyToScalar(root);

    // Ensure s > 0
    if (s.isZero())
    {
        throw std::invalid_argument("Root key must be non-zero.");
    }

    // Ensure coefficients are non-zero. (Scalars are canonical by construction,
    // so the legacy "< group order" check is no longer needed.)
    for (const auto& c : coefs)
    {
        if (c.isZero())
        {
            throw std::invalid_argument(
                "Polynomial coefficients must be non-zero."
            );
        }
    }

    // Generate the key shares
    auto keys = std::vector<KeyShare>();
    keys.reserve(n);
    for (size_t xi = 1; xi < (n + 1); ++xi)
    {
        auto ai = s;
        for (size_t j = 1; j < t; ++j)
        {
            ai = ai + coefs[j - 1] * Scalar::fromUintPow(xi, j);
        }
        keys.push_back({.id = xi, .key = Ed25519ScalarToExtendedKey(ai)});
    }

    return std::make_pair(root.publicKey(), keys);
}  // Ed25519ShamirKeySplit

auto Ed25519ShamirKeySplit(const PrivateKey& root, uint32_t n, uint32_t t)
    -> std::pair<PublicKey, std::vector<KeyShare>>
{
    // Generate the set of random coefficients a_1...a_(t-1).
    auto a = std::vector<Scalar>();
    for (size_t j = 1; j < t; ++j)
    {
        a.push_back(Scalar::random());
    }

    return Ed25519ShamirKeySplit(root, n, t, a);
}  // Ed25519ShamirKeySplit

auto Ed25519ShamirKeyLagrangeCoefficients(std::span<const KeyShare> key_shares)
    -> std::vector<Scalar>
{
    auto coefficients = std::vector<Scalar>();
    for (size_t i = 0; i < key_shares.size(); ++i)
    {
        const auto xi = Scalar::fromUint(key_shares[i].id);
        auto ci_num = Scalar::fromUint(1);
        auto ci_den = Scalar::fromUint(1);
        for (size_t j = 0; j < key_shares.size(); ++j)
        {
            if (j != i)
            {
                auto xj = Scalar::fromUint(key_shares[j].id);
                ci_num = ci_num * xj;
                ci_den = (ci_den * xj) - (ci_den * xi);
                // The above order of operations reduces overflows.
            }
        }
        coefficients.push_back(ci_num / ci_den);
    }
    return coefficients;
}  // Ed25519ShamirKeyReconstruction

auto Ed25519ShamirFilterKeyShares(std::span<const KeyShare> key_shares)
    -> std::vector<KeyShare>
{
    // Ensure all the points are unique.
    auto filtered_key_shares = std::vector<KeyShare>();
    for (const auto& k : key_shares)
    {
        if (k.id == 0)
        {
            continue;
        }  // x = 0 is invalid
        auto is_unique = true;
        for (const auto& f : filtered_key_shares)
        {
            if ((f.id == k.id) && (k.key.bytes() == f.key.bytes()))
            {
                is_unique = false;
            }
        }
        if (is_unique)
        {
            filtered_key_shares.push_back(k);
        }
    }
    return filtered_key_shares;
}  // Ed25519ShamirFilterKeyShares

auto Ed25519ShamirKeyReconstruction(
    std::span<const KeyShare> key_shares,
    uint32_t t
) -> PrivateKey
{
    // Filter the key shares to remove duplicate or invalid shares
    const auto valid_key_shares = Ed25519ShamirFilterKeyShares(key_shares);

    // Ensure we have enough key shares for the re-construction
    if (valid_key_shares.size() < t)
    {
        throw std::invalid_argument("Require at least t key shares.");
    }

    auto s = Scalar::zero();
    auto coeffs = Ed25519ShamirKeyLagrangeCoefficients(valid_key_shares);
    for (size_t i = 0; i < valid_key_shares.size(); ++i)
    {
        const auto yi = PrivateKeyToScalar(valid_key_shares[i].key);
        const auto ci = coeffs[i];
        s += ci * yi;
    }

    return Ed25519ScalarToExtendedKey(s);
}  // Ed25519ShamirKeyReconstruction

}  // namespace

auto Dealer::generate() const -> std::pair<PublicKey, std::vector<KeyShare>>
{
    const auto root_key = PrivateKey::generate();
    return this->splitRootKey(root_key);
}  // Dealer::generate

auto Dealer::splitSeed(std::span<const uint8_t, SEED_SIZE> seed) const
    -> std::pair<PublicKey, std::vector<KeyShare>>
{
    const auto root_key = PrivateKey::fromSeed(seed);
    return this->splitRootKey(root_key);
}  // Dealer::splitSeed

auto Dealer::splitRootKey(const PrivateKey& root) const
    -> std::pair<PublicKey, std::vector<KeyShare>>
{
    if (this->algorithm_ == KeySharingAlgorithm::Direct)
    {
        return Ed25519DirectKeySplit(root, this->num_keys_);
    }  // KeySharingAlgorithm::Direct

    // KeySharingAlgorithm::ShamirSecretSharing
    return Ed25519ShamirKeySplit(root, this->num_keys_, this->sig_threshold_);
}  // Dealer::splitRootKey

auto Dealer::compositeKey(std::span<const KeyShare> key_shares) const
    -> PublicKey
{
    if (key_shares.size() < this->sig_threshold_)
    {
        throw std::invalid_argument("Invalid number of key shares provided.");
    }

    if (this->algorithm_ == KeySharingAlgorithm::Direct)
    {
        auto pk_bytes = std::array<uint8_t, 32>();
        std::copy_n(
            key_shares[0].key.publicKey().bytes().begin(), 32, pk_bytes.begin()
        );
        for (size_t i = 1; i < key_shares.size(); ++i)
        {
            pk_bytes = EncodedPointAdd(
                pk_bytes, key_shares[i].key.publicKey().bytes()
            );
        }
        return {pk_bytes, MakeCompositeChainCode(key_shares)};
    }

    return this->compositeSigningKey(key_shares).publicKey();
}  // Dealer::compositeKey

auto Dealer::compositeKey(std::span<const PublicKey> key_shares) const
    -> PublicKey
{
    if (key_shares.size() < this->sig_threshold_)
    {
        throw std::invalid_argument("Invalid number of key shares provided.");
    }

    if (this->algorithm_ == KeySharingAlgorithm::Direct)
    {
        auto pk_bytes = std::array<uint8_t, 32>();
        std::copy_n(key_shares[0].bytes().begin(), 32, pk_bytes.begin());
        for (size_t i = 1; i < key_shares.size(); ++i)
        {
            pk_bytes = EncodedPointAdd(pk_bytes, key_shares[i].bytes());
        }
        return {pk_bytes, MakeCompositeChainCode(key_shares)};
    }

    throw std::invalid_argument("Not implemented for SSS.");
}  // Dealer::compositeKey

auto Dealer::compositeSigningKey(std::span<const KeyShare> key_shares) const
    -> PrivateKey
{
    if (key_shares.size() < this->sig_threshold_)
    {
        throw std::invalid_argument("Invalid number of key shares provided.");
    }

    if (this->algorithm_ == KeySharingAlgorithm::Direct)
    {
        auto sk_bytes = SecureByteArray<64>{};

        // Combine the secret key shares to fill the lower 32-bytes (kL) of the
        // composite secret key.
        auto ss = PrivateKeyToScalar(key_shares[0].key);
        for (size_t i = 1; i < key_shares.size(); ++i)
        {
            ss = ss + PrivateKeyToScalar(key_shares[i].key);
        }
        auto kl_bytes = ss.bytes();
        std::copy_n(kl_bytes.begin(), 32, sk_bytes.begin());

        // Make the upper 32-bytes (kR) deterministic by hashing the lower
        // bytes.
        const auto hasher = Botan::HashFunction::create("SHA-256");
        hasher->update("cardano-tss-key-extension-v1");
        hasher->update({kl_bytes.data(), 32});
        hasher->final(sk_bytes.data() + 32);

        return {sk_bytes, MakeCompositeChainCode(key_shares)};
    }

    return Ed25519ShamirKeyReconstruction(key_shares, this->sig_threshold_);
}  // TssDealer::compositeSigningKey

auto Dealer::computeLagrangeCoefficients(
    std::span<const uint64_t> key_ids
) const -> std::vector<std::array<uint8_t, COEFFICIENT_SIZE>>
{
    if (key_ids.empty())
    {
        return {};
    }

    // Validate key IDs: a zero ID would evaluate the Lagrange interpolation
    // at x=0 (the secret itself), leaking it directly. Duplicate IDs would
    // produce a zero denominator, breaking the interpolation.
    auto sorted_ids = std::vector<uint64_t>(key_ids.begin(), key_ids.end());
    std::ranges::sort(sorted_ids.begin(), sorted_ids.end());
    if (sorted_ids[0] == 0)
    {
        throw std::invalid_argument("Key ID must be non-zero.");
    }
    for (size_t i = 1; i < sorted_ids.size(); ++i)
    {
        if (sorted_ids[i] == sorted_ids[i - 1])
        {
            throw std::invalid_argument("Key IDs must be unique.");
        }
    }

    auto coefficients = std::vector<std::array<uint8_t, 32>>();
    for (size_t i = 0; i < key_ids.size(); ++i)
    {
        const auto xi = Scalar::fromUint(key_ids[i]);
        auto ci_num = Scalar::fromUint(1);
        auto ci_den = Scalar::fromUint(1);
        for (size_t j = 0; j < key_ids.size(); ++j)
        {
            if (j != i)
            {
                auto xj = Scalar::fromUint(key_ids[j]);
                ci_num = ci_num * xj;
                ci_den = (ci_den * xj) - (ci_den * xi);
                // The above order of operations reduces overflows.
            }
        }
        coefficients.push_back((ci_num / ci_den).bytes());
    }
    return coefficients;
};

auto Dealer::aggregateCommitmentShares(
    const std::vector<std::array<uint8_t, COMMITMENT_SIZE>>& commitments
) const -> std::array<uint8_t, COMMITMENT_SIZE>
{
    auto pk_bytes = std::array<uint8_t, 32>();
    std::copy_n(commitments[0].begin(), 32, pk_bytes.begin());
    for (size_t i = 1; i < commitments.size(); ++i)
    {
        pk_bytes = EncodedPointAdd(pk_bytes, commitments[i]);
    }
    return pk_bytes;
}  // Dealer::aggregateCommitmentShares

auto Dealer::aggregateSignatureShares(
    const std::vector<std::array<uint8_t, SIGNATURE_SIZE>>& signatures
) const -> std::array<uint8_t, SIGNATURE_SIZE>
{
    // R should be the same for all signatures (constant-time compare).
    for (auto& sig : signatures)
    {
        if (sodium_memcmp(signatures[0].data(), sig.data(), 32) != 0)
        {
            throw std::invalid_argument("Signature commitments do not match!");
        }
    }

    // Add the signature scalars
    auto s_agg = Scalar::zero();
    for (auto& sig : signatures)
    {
        auto si = Scalar::reduce(std::span<const uint8_t>(sig).last<32>());
        s_agg += si;
    }
    auto sbytes = s_agg.bytes();

    // Return the complete signature
    auto sig = std::array<uint8_t, SIGNATURE_SIZE>{};
    std::copy_n(signatures[0].begin(), 32, sig.begin());
    std::copy_n(sbytes.begin(), 32, sig.begin() + 32);
    return sig;
}  // Dealer::aggregateSignatureShares

auto Dealer::verifySignature(
    std::span<const uint8_t> msg,
    std::span<const uint8_t, SIGNATURE_SIZE> sig,
    const PublicKey& pk
) const -> bool
{
    return pk.verifySignature(msg, sig);
}  // Dealer::verifySignature

auto Signer::commitmentShareFromNonce(std::span<const uint8_t> nonce) -> std::
    pair<std::array<uint8_t, COMMITMENT_SIZE>, std::array<uint8_t, NONCE_SIZE>>
{
    if (nonce.size() != 32 && nonce.size() != 64)
    {
        throw std::invalid_argument("Nonce must be 32 or 64 bytes.");
    }
    // R = rB
    auto r =
        (nonce.size() == 64)
            ? Scalar::reduce(std::span<const uint8_t, 64>{nonce.data(), 64})
            : Scalar::reduce(std::span<const uint8_t, 32>{nonce.data(), 32});
    auto rb = Point::mulBasepoint(r);
    return std::make_pair(rb.bytes(), r.bytes());
}  // Signer::commitmentShareFromNonce

auto Signer::commitmentShareAndNonce() -> std::
    pair<std::array<uint8_t, COMMITMENT_SIZE>, std::array<uint8_t, NONCE_SIZE>>
{
    // For TSS we need R to be random and non-deterministic. Use the Botan
    // random number generator for generating a random seed that will be used
    // to generate a random nonce.
    const auto seed = GenerateEntropy<32>();
    return Signer::commitmentShareFromNonce(seed);
}  // Signer::commitmentShareAndNonce

auto Signer::commitmentShareAndNonce(
    std::span<const uint8_t> msg,
    const KeyShare& sk
) -> std::
    pair<std::array<uint8_t, COMMITMENT_SIZE>, std::array<uint8_t, NONCE_SIZE>>
{
    // For TSS we need R to be random and non-deterministic. Use the Botan
    // random number generator for generating a random seed that will be used
    // to generate a random nonce.

    // r = H(seed, aExt[32..64], m) where seed is random byte string
    const auto seed = GenerateEntropy<32>();
    const auto sha512 = Botan::HashFunction::create("SHA-512");
    sha512->update(seed);
    sha512->update(std::span<const uint8_t>(sk.key.bytes().data() + 32, 32));
    sha512->update(msg);

    return Signer::commitmentShareFromNonce(sha512->final());
}  // Signer::commitmentShareAndNonce

auto Signer::signatureShare(
    std::span<const uint8_t> msg,
    std::span<const uint8_t, NONCE_SIZE> nonce,
    std::span<const uint8_t, COMMITMENT_SIZE> commitment,
    const PublicKey& base_pk,
    const KeyShare& sk
) -> std::array<uint8_t, SIGNATURE_SIZE>
{
    // S = H(R,A,m)..
    auto hash = std::array<uint8_t, 64>();
    const auto sha512 = Botan::HashFunction::create("SHA-512");
    sha512->update(commitment.data(), COMMITMENT_SIZE);
    sha512->update(base_pk.bytes().data(), base_pk.bytes().size());
    sha512->update(msg.data(), msg.size());
    sha512->final(hash);
    auto s = Scalar::reduce(std::span<const uint8_t, 64>{hash});

    // S = H(R,A,m)a
    auto kl = std::span<const uint8_t, 32>{sk.key.bytes().data(), 32};
    auto a = Scalar::reduce(kl);
    s = s * a;

    // S = (r + H(R,A,m)a)
    auto ri = Scalar::reduce(nonce);
    s = ri + s;

    // S = (r + H(R,A,m)a) mod L
    auto sbytes = s.bytes();

    // Return the complete signature
    auto sig = std::array<uint8_t, SIGNATURE_SIZE>{};
    std::copy_n(commitment.begin(), COMMITMENT_SIZE, sig.begin());
    std::copy_n(sbytes.begin(), 32, sig.begin() + COMMITMENT_SIZE);
    return sig;
}  // Signer::signatureShare

auto Signer::signatureShare(
    std::span<const uint8_t> msg,
    std::span<const uint8_t, NONCE_SIZE> nonce,
    std::span<const uint8_t, COMMITMENT_SIZE> commitment,
    std::span<const uint8_t, COEFFICIENT_SIZE> coefficient,
    const PublicKey& base_pk,
    const KeyShare& sk
) -> std::array<uint8_t, SIGNATURE_SIZE>
{
    auto ci = Scalar::reduce(coefficient);

    // k = H(R,A,m)..
    auto hash = std::array<uint8_t, 64>();
    const auto sha512 = Botan::HashFunction::create("SHA-512");
    sha512->update(commitment.data(), COMMITMENT_SIZE);
    sha512->update(base_pk.bytes().data(), 32);
    sha512->update(msg.data(), msg.size());
    sha512->final(hash);
    auto k = Scalar::reduce(std::span<const uint8_t, 64>{hash});

    // Si = (ri + k*ci*si) mod L
    auto kl = std::span<const uint8_t, 32>{sk.key.bytes().data(), 32};
    auto si = Scalar::reduce(kl);
    auto ri = Scalar::reduce(nonce);
    auto s = ri + k * ci * si;

    // Return the complete signature
    auto sbytes = s.bytes();
    auto sig = std::array<uint8_t, SIGNATURE_SIZE>{};
    std::copy_n(commitment.begin(), COMMITMENT_SIZE, sig.begin());
    std::copy_n(sbytes.begin(), 32, sig.begin() + COMMITMENT_SIZE);
    return sig;
}  // Signer::signatureShare

auto Signer::verifySignature(
    std::span<const uint8_t> msg,
    std::span<const uint8_t, SIGNATURE_SIZE> sig,
    const PublicKey& pk
) -> bool
{
    return pk.verifySignature(msg, sig);
}  // TssSigner::verifySignature

auto StatefulSigner::commitmentShare() -> std::array<uint8_t, 32>
{
    const auto [commitment, nonce] =
        Signer::commitmentShareAndNonce(this->msg_, this->key_share_);
    std::copy_n(nonce.begin(), NONCE_SIZE, this->nonce_.begin());
    return commitment;
}  // StatefulSigner::commitmentShare

auto StatefulSigner::signatureShare(
    std::span<const uint8_t, COMMITMENT_SIZE> agg_commitment
) const -> std::array<uint8_t, SIGNATURE_SIZE>
{
    return Signer::signatureShare(
        this->msg_,
        this->nonce_,
        agg_commitment,
        this->langrange_coeff_,
        this->agg_vkey_,
        this->key_share_
    );
}  // StatefulSigner::signatureShare

auto StatefulSigner::signatureShare(
    std::span<const uint8_t, COMMITMENT_SIZE> agg_commitment,
    std::span<const uint8_t, COEFFICIENT_SIZE> langrange_coeff
) const -> std::array<uint8_t, SIGNATURE_SIZE>
{
    return Signer::signatureShare(
        this->msg_,
        this->nonce_,
        agg_commitment,
        langrange_coeff,
        this->agg_vkey_,
        this->key_share_
    );
}  // StatefulSigner::signatureShare

auto StatefulSigner::verifySignature(
    std::span<const uint8_t, SIGNATURE_SIZE> sig
) const -> bool
{
    return this->agg_vkey_.verifySignature(this->msg_, sig);
}  // StatefulSigner::verifySignature
