@page cardano-tss-sss-api Shamir Secret Sharing

The Cardano-TSS library utilizes "Shamir Secret Sharing" (SSS) \[1\] when a threshold of signature shares is required that is less than the total number of key shares.
The algorithm may also be used when the threshold is equal to the number of shares but in that scenario, the direct key splitting implementation is more computationally efficient.

@section subsection-cardano-tss-sss-api API Description

The `Dealer` object is initialized by providing the number of key splits and the required threshold.

@cpp
const auto dealer = Dealer(4, 3);
@endcpp

A set of key shares may be created by splitting a root private key.
The root key (BIP32-Ed25519 \[3\]) may be provided directly (using libcardano key object), derived from a 32-byte seed (regular Ed25519 key), or finally the seed may be automatically generated using a cryptographically secure RNG.

@cpp
auto [base_vk, key_shares] = dealer.generate();  // uses a RNG
@endcpp

A subset of the generated key shares may be used to generate valid signatures providing the subset meets the required threshold.

@cpp
// Take a subset of t keys to test creating a signature.
const auto key_shares_subset = std::vector<KeyShare>(
    key_shares.begin(),
    key_shares.begin() + 3
);
@endcpp

The signing needs to be done in multiple steps \[2\].
First, each key share creates a random nonce and shares with the dealer to create the aggregate commitment value.

@cpp
// Compute individual nonces for each key share and combine for the 
// shared signature nonce.
auto nonce_shares = std::vector<std::array<uint8_t, 32>>();
auto commitment_shares = std::vector<std::array<uint8_t, 32>>();
for (const auto& k : key_shares_subset) {
    auto [c, n] = Signer::commitmentShareAndNonce(msg_bytes, k);
    commitment_shares.push_back(c);
    nonce_shares.push_back(n);
}
auto agg_commitment = dealer.aggregateCommitmentShares(commitment_shares);
@endcpp

Next, Lagrange coefficients are computed for each key share that will contribute to the final signature.

@cpp
// Calculate the Lagrange interpolation coefficients
auto key_shares_subset_ids = std::vector<uint64_t>();
for (const auto& k : key_shares_subset) {
    key_shares_subset_ids.push_back(k.id);
}
auto lagrange_coefficients = dealer.computeLagrangeCoefficients(key_shares_subset_ids);
@endcpp

Next, each key share computes its signature contribution.
Note that the previously generated random nonce must be saved and re-used at this point.

@cpp
// Create signature shares for each key in the subset.
auto signature_shares = std::vector<std::array<uint8_t, 64>>();
for (int i = 0; i < key_shares_subset.size(); ++i) {
    const auto sig_share = Signer::signatureShare(
        msg_bytes,
        nonce_shares[i],
        agg_commitment,
        lagrange_coefficients[i],
        base_vk,
        key_shares[i]
    );
    signature_shares.push_back(sig_share);
}
@endcpp

Finally, the dealer combines the signature shares into a single valid signature.

@cpp
// Aggregate the signature shares into the final signature.
const auto agg_signature = dealer.aggregateSignatureShares(signature_shares);
@endcpp

The signature may be verified by the base public key as is done for standard Ed25519 keys \[4\].

@cpp
// Verify the aggregate signature is a valid signature with the base public key.
auto isValid = dealer.verifySignature(msg_bytes, agg_signature, base_vk);
@endcpp

@section subsection-cardano-tss-sss-references References
\[1\] Threshold Modes in Elliptic Curves https://datatracker.ietf.org/doc/html/draft-hallambaker-threshold-09

\[2\] Threshold Signatures in Elliptic Curves https://datatracker.ietf.org/doc/html/draft-hallambaker-threshold-sigs-06

\[3\] BIP32-Ed25519 Hierarchical Deterministic Keys over a Non-linear Keyspace

\[4\] RFC 8032: Edwards-Curve Digital Signature Algorithm (EdDSA), https://www.rfc-editor.org/rfc/rfc8032
