@page concept-stake-pool-keys-and-certs Stake Pool Keys and Certificates

@subsection subsection-cold-keys Cold Keys

Stake pool cold keys are simply Ed25519 public/private key pairs.
Libcardano uses the Ed25519 implementation in [Viper25519](https://gitlab.com/viperscience/viper25519).
Extended Ed25519 keys are also supported and [CIP-1853](https://github.com/cardano-foundation/CIPs/tree/master/CIP-1853) defines a standard way to derive them from a root seed or Mnemonic using the derivation path `1853H/1815H/0H/0H`.

The stake pool ID is the 28-byte `blake2b` hash of the verification (public) key bytes.
The following pseudocode describes the process of obtaining a pool ID from the verification key.

    vkey = skey->get_public
    pool_id = blake2b_224(vkey->bytes)
    // Pool ID is a 28 byte result that is usually then Hex or Bech32 encoded

Note that the pool IDs are often encoded in BECH32 format. In order to do this, "pool" is supplied as the _human readable part_ e.g., `pool166dkk9kx5y6ug9tnvh0dnvxhwt2yca3g5pd5jaqa8t39cgyqqlr`.

@subsection subsection-vrf-keys VRF Keys

Stake pools use Verifiable Random Proofs (VRFs) to confirm slot leadership when forging blocks.
Thus each pool requires a set of VRF keys to prove that they were in fact elected the leader for a specific slot.
VRF keys are essentially Ed25519 keys with a VRF capability added.
The VRF key implementation in libcardano is provided by that in the [viper25519](https://gitlab.com/viperscience/viper25519) library.

@subsubsection VRF Keys and Cardano Blocks

Cardano block headers contain the VRF verification key of the stake pool that forged the block. This can then be used by all nodes that receive the block to verifiy that the pool was elected to produce a block on that slot.
The block header also contains the VRF proof that that may be verfied by the VRF verification key and the seed. The seed is computed from the epoch nonce and slot number. Both the VRF hash and proof from the seed are included in the block header.
Leadership validation is acheived using the VRF hash via the process described in chapter 16 of the Shelley ledger specification.

@subsection subsection-kes-keys KES Keys

TODO

@subsection subsection-certificates Operational Certificates

Node operational certificates are generated off-chain and essentially delegate the signing power of a cold key (stored offline) to a hot key (stored online) for signing blocks. The hot keys have a time limited validity and must be "rotated" on a regular interval defined by the chain parameters. The node operational certificates must be re-generated when a new set of hot keys (KES keys) are required for the pool.

The certificates prove the authority of the hot key (KES key) to sign a block on behalf of a cold key by recording the cold verification key and the signature of the hot key by the cold key. The issue count and KES period are also included in the structure and signing input. The structure of a node operational certificate is outlined below.

    cert = [
        [
            kes_vkey_bytes  : bstr,
            issue_count     : uint,
            kes_period      : uint,
        ],
        cold_vkey_bytes     : bstr,
    ]

The signature field is the result of signing the first three elements of the certificate with the stake pool cold key.
The stake pool cold verification key is included as an extra object in the CBOR so that the signature may be verified.
The bytes fed to the Ed25519 signature algorithm are the concatenation of the hot verification key (KES verification key) bytes, the issue counter (integer encoded as 8 bytes in Big Endian format) and the KES period (integer encoded as 8 bytes in Big Endian format). 

@subsection subsection-counters Operational Certificate Issue Counter

The Operational Certificate Issue Counter keeps track of the KES rotations or the number of new operatinal certificates.
If the count is not properly increased when a new certificate is generated with new hot keys, the operational certificate will be invalid and the pool will not be able to successfully sign blocks.
The CBOR data of a counter, in a text-envelope file, contains the cold verification key and the count.

    opcert = [
        vkey_bytes : bstr,
        count      : uint,
    ]

@subsection subsection-registration Registration Certificates

Stake pool registration certificates are stored on-chain as part of a transaction.
The certificate defines specific parameters for the pool and allows users to delegate stake to the pool. 
The stake pool registration certificate contains the following.

    reg_cert = [
        type              : unit, ; Cert type = 3 -> pool reg cert 
        pool_id           : bstr, 
        vrf_key_hash      : bstr,
        pledge            : uint, ; lovelace
        cost              : uint, ; lovelace
        #6.30([                   ; rational representing the margin
            uint,
            uint
        ]),
        reward_account    : bstr, 
        [* bstr],                 ; Array of owner stake addresses
        [* relay],                ; Array of relays
        [
            metadata_url  : tstr,
            metadata_hash : bstr,
        ],
    ]

* The `type` field is an unsigned integer representing the type of certificate. A constant value of 3 is used to indicate a stake pool registration certificate.
* The `pool_id` field is a byte string containing the `blake2b_224` hash of the cold verification key bytes. This is the same as the "Pool ID" that is referred to elsewhere.
* The `vrf_key_hash` field is a byte string containing the `blake2b_224` hash of the VRF verification key bytes.
* The `pledge` field is an unsigned integer representing the pool pledge in lovelace.
* The `cost` field is an unsigned integer representing the pool fixed cost in lovelace.
* The `margin` field represents the pool margin cost as a rational number. The CBOR rational number is a semantic tagged (major type 6) two-element array. The tag value is 30 and the array stores the numerator and the denominator. The value must be on the unit interval (0-1).
* The `reward_account` account field is the rewards address that will collect the pool fees. The address includes the key hash and header byte.
* The `pool_owner` field is an array of byte strings. Each element in the array represents the hash of verification key bytes for the stake account of each pool owner. The hash of the stake key is equivalent to the stake address. The pool pledge of each owner must be staked under the provided account key.
* The `relays` field is an array containing information on stake pool public relays. Each relay is defined as an array of data with the first element being the type since relays may be defined in multiple ways, i.e., via IP address or DNS names. See more details below.
* The `pool_metadata` field is a two element array containing the URL of the pool metadata file as a text string and the hash of the metadata file as a byte string. The hash is computed by feeding the metadata file bytes into the blake2b_256 algorithm.

**Relays**
Relays come in three different types (all of which may exist in a single certificate): single host address, single host DNS name, and multi-host DNS name.

A single IP address in either IPv4 or IPv6 with an optional port specified.

    relay = [ relay_ip // relay_host // relay_multi ]

    relay_ip = [
        type        : uint, ; 0 for single host address
        port / null : uint,
        addr / null : bstr, ; len 4
        addr / null : bstr, ; len 16
    ]

A single host specified by DNS name and port.

    relay_host = [
        type : uint, ; 1 for single host DNS name
        port : uint, 
        name : tstr,
    ]

Multiple hosts specified by DNS name only.

    relay_multi = [
        type : uint, ; 2 for multiple host DNS name
        name : tstr, 
    ]

@subsection subsection-deregistration Deregistration Certificates

Stake pool deregistration or retirement certificates are simple in nature. They represent the pool verification key and the epoch in which the pool should retire.

    dereg_cert = [
        type         : unit, ; Cert type = 4 -> pool de-reg cert 
        vrf_key_hash : bstr,
        epoch        : uint,
    ]
