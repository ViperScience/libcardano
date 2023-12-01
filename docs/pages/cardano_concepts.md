@page cardano-concepts Cardano Concepts
@tableofcontents

In this document we walk through implementation details of the Cardano blockchain network
as required for the implementation of `libcardano`.

@section section-wallet Wallets

@subsection subsection-keys Keys

@subsection subsection-address Addresses

@subsection subsection-mnemonic Mnemonic

@section section-encodings Encodings

Libcardano supports encoding and decoding [Bech32](https://github.com/bitcoin/bips/blob/master/bip-0173.mediawiki) (Shelley-era) and [Base58](https://tools.ietf.org/id/draft-msporny-base58-01.html) (Byron-era) Cardano addresses to and from raw Base16 (hex) format. [CIP19](https://cips.cardano.org/cips/cip19/) provides a detailed explanation of Cardano encodings.

@section section-stake-pools Stake Pools

@subsection subsection-cold-keys Cold Keys

Stake pool cold keys are simply Ed25519 public/private key pairs.
Libcardano uses the Ed25519 implementation in [Viper25519](https://gitlab.com/viperscience/viper25519).
Extended Ed25519 keys are also supported and [CIP-1853](https://github.com/cardano-foundation/CIPs/tree/master/CIP-1853) defines a standard way to derive them from a root seed or Mnemonic using the derivation path `1853H/1815H/0H/0H`.

The stake pool ID is the `blake2b_224` hash of the verification (public) key bytes.
The following pseudocode describes the process of obtaining a pool ID from the verification key.

    vkey = skey->get_public
    pool_id = blake2b_224(vkey->bytes)
    // Pool ID is a 28 byte result that is usually then Hex or Bech32 encoded

Note that the pool IDs are often encoded in BECH32 format. In order to do this, "pool" is supplied as the _human readable part_ e.g., "pool166dkk9kx5y6ug9tnvh0dnvxhwt2yca3g5pd5jaqa8t39cgyqqlr".

@subsection subsection-vrf-keys VRF Keys

https://medium.com/algorand/algorand-releases-first-open-source-code-of-verifiable-random-function-93c2960abd61

@subsection subsection-kes-keys KES Keys

@subsection subsection-counters Operational Certificate Issue Counter

The Operational Certificate Issue Counter keeps track of the KES rotations (new certificates).
The CBOR data contains the cold verification key and the count.
If you don't keep track, the operational certificate generated will be invalid. 

@subsection subsection-certificates Operational Certificates

    [
        [
            [kes_vkey],
            issue_count,
            kes_period,
            signature
        ],
        [cold_vkey]
    ]

The signature field is the result of signing the first three elements of the certificate with the stake pool cold key.
The stake pool cold verification key is included as an extra object in the CBOR so that the signature may be verified.
The bytes fed to the Ed25519 signature algorithm are the concatenation of the hot verification key (KES verification key) bytes, the issue counter (integer encoded as 8 bytes in Big Endian format) and the KES period (integer encoded as 8 bytes in Big Endian format).
