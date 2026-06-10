@page cardano-tss-direct-key-splitting-api Direct Key Splitting

The Cardano-TSS library supports "Direct Key Splitting" \[1\] when the threshold is set to the same number as the key shares or if the threshold argument is omitted when creating a `Dealer` object. With the direct key splitting method, a signature share from every key split is required in order to produce a valid signature.

@section subsection-direct-key-splitting-api API Description

The `Dealer` object is initialized by providing the number of key splits and optionally the required threshold.
Note that supplying a threshold different from the number of key splits will use Shamir Secret Sharing instead of the direct key splitting method.

@cpp
const auto dealer = Dealer(2);
@endcpp

A set of key shares may be created by splitting a root private key.
The root key (BIP32-Ed25519 \[3\]) may be provided directly (using libcardano key object), derived from a 32-byte seed (regular Ed25519 key), or finally the seed may be automatically generated using a cryptographically secure RNG.

@cpp
auto [base_vk, key_shares] = dealer.generate();  // uses a RNG
@endcpp

Splitting a root key by any of the above methods to generate the complete set of key shares is the most secure method.
However, mathematically speaking, the key shares may also be generated completely separately and provided for combination. 
Use of this method should be restricted due to malicious key injection attacks \[2\].

@cpp
// Create two random private keys.
const auto key1 = PrivateKey::generate();
const auto key2 = PrivateKey::generate();

// Create a base public key from the two keys.
const auto base_vk = dealer.compositeKey({{key1, key2}});
@endcpp

The signing needs to be done in two steps \[2\].
First, each key share creates a random nonce and shares with the dealer to create the aggregate commitment value.

@cpp
// Create a random nonce and commitment for each key to sign the message.
const auto [commitment1, nonce1] = Signer::commitmentShareAndNonce(msg_bytes, key1);
const auto [commitment2, nonce2] = Signer::commitmentShareAndNonce(msg_bytes, key2);

// Aggregate each commitment share into a single commitment.
const auto agg_commitment = dealer.aggregateCommitmentShares({commitment1, commitment2});
@endcpp

Next, each key share computes its signature contribution.
Note that the previously generated random nonce must be saved and re-used at this point.

@cpp
// Create the signature shares with the aggregate commitment and base public key.
const auto signature1 = Signer::signatureShare(msg_bytes, nonce1, agg_commitment, base_vk, key1);
const auto signature2 = Signer::signatureShare(msg_bytes, nonce2, agg_commitment, base_vk, key2);
@endcpp

Finally, the dealer combines the signature shares into a single valid signature.

@cpp
// Aggregate the signature shares into the final signature.
const auto agg_signature = dealer.aggregateSignatureShares({signature1, signature2});
@endcpp

The signature may be verified by the base public key as is done for standard Ed25519 keys \[4\].

@cpp
// Verify the aggregate signature is a valid signature with the base public key.
auto isValid = base_vk.verifySignature(msg_bytes, agg_signature);
@endcpp

@section subsection-direct-key-splitting-references References
\[1\] Threshold Modes in Elliptic Curves https://datatracker.ietf.org/doc/html/draft-hallambaker-threshold-09

\[2\] Threshold Signatures in Elliptic Curves https://datatracker.ietf.org/doc/html/draft-hallambaker-threshold-sigs-06

\[3\] BIP32-Ed25519 Hierarchical Deterministic Keys over a Non-linear Keyspace

\[4\] RFC 8032: Edwards-Curve Digital Signature Algorithm (EdDSA), https://www.rfc-editor.org/rfc/rfc8032
