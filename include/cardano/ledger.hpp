// Copyright (c) 2021 Viper Science LLCunordered_map
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

#ifndef _CARDANO_LEDGER_HPP_
#define _CARDANO_LEDGER_HPP_

#include <any>
#include <array>
#include <cstdint>
#include <map>
#include <memory>
#include <optional>
#include <set>
#include <string>
#include <tuple>
#include <unordered_map>
#include <unordered_set>
#include <vector>

// Official Spec (Babbage Era):
// https://github.com/input-output-hk/cardano-ledger/blob/master/eras/babbage/test-suite/cddl-files/babbage.cddl#L13
//
// This code takes the approach of trying to represent the CDDL spec in C++
// structures. These structures will be used by logic in other classes and
// files.

namespace cardano
{

using Byte = uint8_t;
using Bytes = std::vector<Byte>;
using Bytes4 = std::array<Byte, 4>;
using Bytes16 = std::array<Byte, 16>;
using Bytes28 = std::array<Byte, 28>;
using Bytes32 = std::array<Byte, 32>;
using Bytes64 = std::array<Byte, 64>;
using Bytes80 = std::array<Byte, 80>;
using Bytes448 = std::array<Byte, 448>;

using Address = Bytes;
using RewardAccount = Bytes;
using PlutusV1Script = Bytes;
using PlutusV2Script = Bytes;

using IPV4 = Bytes4;

using IPV6 = Bytes16;

using Vkey = Bytes32;
using VrfVkey = Bytes32;
using KesVkey = Bytes32;

using VrfCert = std::tuple<Bytes, Bytes80>;

using SignKeyKES = Bytes64;
using Signature = Bytes64;

using KesSignature = Bytes448;

using Hash28 = Bytes28;
using Hash32 = Bytes32;

using AddrKeyHash = Hash28;
using GenesisDelegateHash = Hash28;
using GenesisHash = Hash28;
using PoolKeyHash = Hash28;
using ScriptHash = Hash28;

using AuxiliaryDataHash = Hash32;
using MetadataHash = Hash32;
using PoolMetadataHash = Hash32;
using VrfKeyHash = Hash32;

using Port = uint16_t;

using Uint = uint64_t;
using Coin = Uint;
using Epoch = Uint;

using DeltaCoin = int64_t;

using DnsName = std::string;
using Url = std::string;

/// @brief Transaction index
/// transaction_index = uint .size 2
using TransactionIndex = uint16_t;

struct Rational
{
    Rational(Uint n, Uint d) : num{n}, den{d} {}
    const Uint num;
    const Uint den;
    // Serialize as 2-elem array with tag 6.30
};

// Unit interval is a rational between 0 and 1.
using UnitInterval = Rational;

/// @brief Cardano Byron blockchain CBOR schema
namespace byron
{
// u8 = uint .lt 256
using u8 = uint8_t;

// u16 = uint .lt 65536
using u16 = uint16_t;

// u32 = uint
using u32 = uint32_t;

// u64 = uint
using u64 = uint64_t;

// Basic Cardano Types

// blake2b-256 = bytes .size 32
using blake2b_256 = std::array<uint8_t, 32>;

// txid = blake2b-256
using txid = blake2b_256;

// blockid = blake2b-256
using blockid = blake2b_256;

// updid = blake2b-256
using updid = blake2b_256;

// hash = blake2b-256
using hash = blake2b_256;

// blake2b-224 = bytes .size 28
using blake2b_224 = std::array<uint8_t, 28>;

// addressid = blake2b-224
using addressid = blake2b_224;

// stakeholderid = blake2b-224
using stakeholderid = blake2b_224;

// epochid = u64
using epochid = u64;

// slotid = [ epoch: epochid, slot : u64 ]
struct slotid
{
    epochid epoch;
    u64 slot;
};

// pubkey = bytes
using pubkey = std::vector<uint8_t>;

// signature = bytes
using signature = std::vector<uint8_t>;

// Attributes - at the moment we do not bother deserialising these, since they
// don't contain anything
// attributes = {* any => any}
using attributes = std::unordered_map<std::any, std::any>;

// Addresses

// addrdistr = [1] / [0, stakeholderid]

// addrtype = &("PubKey" : 0, "Script" : 1, "Redeem" : 2) / (u64 .gt 2)

// addrattr = { ? 0 : addrdistr
//            , ? 1 : bytes}

// address = [ #6.24(bytes .cbor ([addressid, addrattr, addrtype])), u64 ]
struct address
{
    uint64_t addrtype;
};

// ; Transactions
// 
// txin = [0, #6.24(bytes .cbor ([txid, u32]))] / [u8 .ne 0, encoded-cbor]
// txout = [address, u64]
// 
// tx = [[+ txin], [+ txout], attributes]
// 
// txproof = [u32, hash, hash]
// 
// twit = [0, #6.24(bytes .cbor ([pubkey, signature]))]
//      / [1, #6.24(bytes .cbor ([[u16, bytes], [u16, bytes]]))]
//      / [2, #6.24(bytes .cbor ([pubkey, signature]))]
//      / [u8 .gt 2, encoded-cbor]
// 
// ; Shared Seed Computation
// 
// vsspubkey = bytes ; This is encoded using the 'Binary' instance
//                   ; for Scrape.PublicKey
// vsssec = bytes ; This is encoded using the 'Binary' instance
//                ; for Scrape.Secret.
// vssenc = [bytes] ; This is encoded using the 'Binary' instance
//                  ; for Scrape.EncryptedSi.
//                  ; TODO work out why this seems to be in a length 1 array
// vssdec = bytes ; This is encoded using the 'Binary' instance
//                ; for Scrape.DecryptedShare
// vssproof = [bytes, bytes, bytes, [* bytes]] ; This is encoded using the
//                                             ; 'Binary' instance for Scrape.Proof
// 
// ssccomm = [pubkey, [{vsspubkey => vssenc},vssproof], signature]
// ssccomms = #6.258([* ssccomm])
// 
// sscopens = {stakeholderid => vsssec}
// 
// sscshares = {addressid => [addressid, [* vssdec]]}
// 
// ssccert = [vsspubkey, pubkey, epochid, signature]
// ssccerts = #6.258([* ssccert])
// 
// ssc = [0, ssccomms, ssccerts]
//     / [1, sscopens, ssccerts]
//     / [2, sscshares, ssccerts]
//     / [3, ssccerts]
// 
// sscproof = [0, hash, hash]
//          / [1, hash, hash]
//          / [2, hash, hash]
//          / [3, hash]
// 
// ; Delegation
// 
// dlg = [ epoch : epochid
//       , issuer : pubkey
//       , delegate : pubkey
//       , certificate : signature
//       ]
// 
// dlgsig = [dlg, signature]
// 
// lwdlg = [ epochRange : [epochid, epochid]
//         , issuer : pubkey
//         , delegate : pubkey
//         , certificate : signature
//         ]
// 
// lwdlgsig = [lwdlg, signature]
// 
// ; Updates
// 
// bver = [u16, u16, u8]
// 
// txfeepol = [0, #6.24(bytes .cbor ([bigint, bigint]))]
//          / [u8 .gt 0, encoded-cbor]
// 
// bvermod = [ scriptVersion : [? u16]
//           , slotDuration : [? bigint]
//           , maxBlockSize : [? bigint]
//           , maxHeaderSize  : [? bigint]
//           , maxTxSize : [? bigint]
//           , maxProposalSize : [? bigint]
//           , mpcThd : [? u64]
//           , heavyDelThd : [? u64]
//           , updateVoteThd : [? u64]
//           , updateProposalThd : [? u64]
//           , updateImplicit : [? u64]
//           , softForkRule : [? [u64, u64, u64]]
//           , txFeePolicy : [? txfeepol]
//           , unlockStakeEpoch : [? epochid]
//           ]
// 
// updata = [ hash, hash, hash, hash ]
// 
// upprop = [ "blockVersion" : bver
//          , "blockVersionMod" : bvermod
//          , "softwareVersion" : [ text, u32 ]
//          , "data" : #6.258([text, updata])
//          , "attributes" : attributes
//          , "from" : pubkey
//          , "signature" : signature
//          ]
// 
// upvote = [ "voter" : pubkey
//          , "proposalId" : updid
//          , "vote" : bool
//          , "signature" : signature
//          ]
// 
// up = [ "proposal" :  [? upprop]
//      , votes : [* upvote]
//      ]
// 
// ; Blocks
// 
// difficulty = [u64]
// 
// blocksig = [0, signature]
//          / [1, lwdlgsig]
//          / [2, dlgsig]
// 
// blockcons = [slotid, pubkey, difficulty, blocksig]
// 
// blockheadex = [ "blockVersion" : bver
//               , "softwareVersion" : [ text, u32 ]
//               , "attributes" : attributes
//               , "extraProof" : hash
//               ]
// 
// blockproof = [ "txProof" : txproof
//              , "sscProof" : sscproof
//              , "dlgProof" : hash
//              , "updProof" : hash
//              ]
// 
// blockhead = [ "protocolMagic" : u32
//             , "prevBlock" : blockid
//             , "bodyProof" : blockproof
//             , "consensusData" : blockcons
//             , "extraData" : blockheadex
//             ]
// 
// blockbody = [ "txPayload" : [* [tx, [* twit]]]
//             , "sscPayload" : ssc
//             , "dlgPayload" : [* dlg]
//             , "updPayload" : up
//             ]
// 
// ; Epoch Boundary Blocks
// 
// ebbcons = [ epochid, difficulty ]
// 
// ebbhead = [ "protocolMagic" : u32
//           , "prevBlock" : blockid
//           , "bodyProof" : hash
//           , "consensusData" : ebbcons
//           , "extraData" : [attributes]
//           ]    


// block = [0, ebblock]
//       / [1, mainblock]
// 
// mainblock = [ "header" : blockhead
//             , "body" : blockbody
//             , "extra" : [attributes]
//             ]
// 
// ebblock = [ "header" : ebbhead
//           , "body" : [+ stakeholderid]
//           , extra : [attributes]
//           ]
// 

}  // namespace byron

/// @brief Shelley era ledger types
namespace shelley
{

// ; To compute a script hash, note that you must prepend
// ; a tag to the bytes of the script before hashing.
// ; The tag is determined by the language.
// ; In the Shelley era there is only one such tag,
// ; namely "\x00" for multisig scripts.
// scripthash            = $hash28
 
/// $nonce /= [ 0 // 1, bytes .size 32 ]
using Nonce = std::tuple<Byte, Bytes32>;

// transaction_metadatum =
//     { * transaction_metadatum => transaction_metadatum }
//   / [ * transaction_metadatum ]
//   / int
//   / bytes .size (0..64)
//   / text .size (0..64)
// using TransactionMetadatum = std::variant<std::map<TransactionMetadatum, TransactionMetadatum>, 
// std::vector<TransactionMetadatum>, int64_t, Bytes, std::string>;
using TransactionMetadatum = std::any;

/// transaction_metadatum_label = uint
using TransactionMetadatumLabel = uint;
 
// transaction_metadata =
//   { * transaction_metadatum_label => transaction_metadatum }
// 
using TransactionMetadata = std::unordered_map<TransactionMetadatumLabel, TransactionMetadatum>;

// bootstrap_witness =
//   [ public_key : $vkey
//   , signature  : $signature
//   , chain_code : bytes .size 32
//   , attributes : bytes
//   ]
struct BootstrapWitness
{
    Vkey public_key;
    Signature signature;
    Bytes32 chain_code;
    Bytes attributes;
};

/// multisig_script =
///   [ multisig_pubkey
///   // multisig_all
///   // multisig_any
///   // multisig_n_of_k
///   ]
struct MultisigScript
{
    enum Type
    {
        multisig_pubkey = 0,
        multisig_all = 1,
        multisig_any = 2,
        multisig_n_of_k = 3, 
    };

    const MultisigScript::Type type;

    // serialization method should be virtual
};

/// multisig_pubkey = (0, addr_keyhash)
struct MultisigPubkey : public MultisigScript
{
    MultisigPubkey() : MultisigScript{MultisigScript::Type::multisig_pubkey} {}
    std::vector<std::unique_ptr<AddrKeyHash>> addr_keyhashes;
};

/// multisig_all = (1, [ * multisig_script ])
struct MultisigAll : public MultisigScript
{
    MultisigAll() : MultisigScript{MultisigScript::Type::multisig_all} {}
    std::vector<std::unique_ptr<MultisigScript>> scripts;
};

/// multisig_any = (2, [ * multisig_script ])
struct MultisigAny : public MultisigScript
{
    MultisigAny() : MultisigScript{MultisigScript::Type::multisig_any} {}
    std::vector<std::unique_ptr<MultisigScript>> scripts;
};

/// multisig_n_of_k = (3, n: uint, [ * multisig_script ])
struct MultisigNofK : public MultisigScript
{
    MultisigNofK() : MultisigScript{MultisigScript::Type::multisig_n_of_k} {}
    Uint n;
    std::vector<std::unique_ptr<MultisigScript>> scripts;
};

/// @brief Verification key witness
/// vkeywitness = [ $vkey, $signature ]
using VkeyWitness = std::tuple<Vkey, Signature>;

/// @brief Represent the protocol version.
/// The CDDL description is:
///     next_major_protocol_version = 3
///     major_protocol_version = 1..next_major_protocol_version
///     protocol_version = (major_protocol_version, uint)
struct ProtocolVersion
{
    const Uint next_major_protocol_version = 3;
    Uint major_protocol_version;
    Uint minor_protocol_version;

    [[nodiscard]] auto isValid() -> bool
    {
        return (major_protocol_version > 0) 
            && (major_protocol_version <= next_major_protocol_version);
    }
};

// transaction_witness_set =
//   { ?0 => [* vkeywitness ]
//   , ?1 => [* multisig_script ]
//   , ?2 => [* bootstrap_witness ]
//   ; In the future, new kinds of witnesses can be added like this:
//   ; , ?3 => [* monetary_policy_script ]
//   ; , ?4 => [* plutus_script ]
//   }
struct TransactionWitnessSet
{
    std::vector<VkeyWitness> vkeywitnesses;
    std::vector<std::unique_ptr<MultisigScript>> multisig_scripts;
    std::vector<BootstrapWitness> bootstrap_witnesses;
};

// protocol_param_update =
//   { ? 0:  uint               ; minfee A
//   , ? 1:  uint               ; minfee B
//   , ? 2:  uint               ; max block body size
//   , ? 3:  uint               ; max transaction size
//   , ? 4:  uint               ; max block header size
//   , ? 5:  coin               ; key deposit
//   , ? 6:  coin               ; pool deposit
//   , ? 7: epoch               ; maximum epoch
//   , ? 8: uint                ; n_opt: desired number of stake pools
//   , ? 9: rational            ; pool pledge influence
//   , ? 10: unit_interval      ; expansion rate
//   , ? 11: unit_interval      ; treasury growth rate
//   , ? 12: unit_interval      ; d. decentralization constant
//   , ? 13: $nonce             ; extra entropy
//   , ? 14: [protocol_version] ; protocol version
//   , ? 15: coin               ; min utxo value
//   }
struct ProtocolParamUpdate
{
    std::optional<Uint> minfee_a;
    std::optional<Uint> minfee_b;
    std::optional<Uint> max_block_body_size;
    std::optional<Uint> max_transaction_size;
    std::optional<Uint> max_block_header_size;
    std::optional<Coin> key_deposit;
    std::optional<Coin> pool_deposit;
    std::optional<Epoch> maximum_epoch;
    std::optional<Uint> n_opt; // desired number of stake pools
    std::optional<Rational> pool_pledge_influence;
    std::optional<UnitInterval> expansion_rate;
    std::optional<UnitInterval> treasury_growth_rate;
    std::optional<UnitInterval> d; // decentralization constant
    std::optional<Nonce> extra_entropy;
    std::optional<ProtocolVersion> protocol_version;
    std::optional<Coin> min_utxo_value;
};

// proposed_protocol_parameter_updates =
//   { * genesishash => protocol_param_update }
using ProposedProtocolParameterUpdate = std::vector<std::tuple<GenesisHash, ProtocolParamUpdate>>;

// update = [ proposed_protocol_parameter_updates
//          , epoch
//          ]
using Update = std::tuple<ProposedProtocolParameterUpdate, Epoch>;

/// withdrawals = { * reward_account => coin }
using Withdrawals = std::vector<std::tuple<RewardAccount, Coin>>;

// CDDL: pool_metadata = [url, pool_metadata_hash]
using PoolMetadata = std::tuple<Url, PoolMetadataHash>;

// relay =
//   [  single_host_addr
//   // single_host_name
//   // multi_host_name
//   ]
struct Relay
{
    enum Type
    {
        single_host_addr = 0,
        single_host_name = 1,
        multi_host_name = 2
    };  // Type

    const Relay::Type type;
};  // Relay

// single_host_addr = ( 0
//                    , port / null
//                    , ipv4 / null
//                    , ipv6 / null
//                    )
struct SingleHostAddr : public Relay
{
    SingleHostAddr() : Relay{Relay::Type::single_host_addr} {}
    std::optional<Port> port;
    std::optional<IPV4> ipv4;
    std::optional<IPV6> ipv6;
};

// single_host_name = ( 1
//                    , port / null
//                    , dns_name ; An A or AAAA DNS record
//                    )
struct SingleHostName : public Relay
{
    SingleHostName() : Relay{Relay::Type::single_host_name} {}
    std::optional<Port> port;
    DnsName dns_name;
};

// multi_host_name = ( 2
//                    , dns_name ; A SRV DNS record
//                    )
struct MiltiHostName : public Relay
{
    MiltiHostName() : Relay{Relay::Type::multi_host_name} {}
    DnsName dns_name;
};

// pool_params = ( operator:       pool_keyhash
//               , vrf_keyhash:    vrf_keyhash
//               , pledge:         coin
//               , cost:           coin
//               , margin:         unit_interval
//               , reward_account: reward_account
//               , pool_owners:    set<addr_keyhash>
//               , relays:         [* relay]
//               , pool_metadata:  pool_metadata / null
//               )
struct PoolParams
{
    PoolKeyHash pool_operator;
    VrfKeyHash vrf_keyhash;
    Coin pledge;
    Coin cost;
    RewardAccount reward_account;
    std::set<AddrKeyHash> pool_owners;
    std::vector<std::unique_ptr<Relay>> relays;
    std::optional<PoolMetadata> pool_metadata;
};


/// @brief A stake credential.
/// stake_credential =
///   [  0, addr_keyhash
///   // 1, scripthash
///   ]
struct StakeCredential
{
    enum Type
    {
        addr_keyhash = 0,
        scripthash = 1
    };  // Type

    Type type;
    Hash28 cred;
};

/// move_instantaneous_reward = [ 0 / 1, { * stake_credential => coin } ]
/// ; The first field determines where the funds are drawn from.
/// ; 0 denotes the reserves, 1 denotes the treasury.
struct MoveInstantaneousReward
{
    MoveInstantaneousReward(Uint s) : source{s} {}
    const Uint source;
    std::vector<std::tuple<StakeCredential, Coin>> stake_credentials;
};

/// @brief A transaction certificate (base type).
/// certificate =
///   [ stake_registration
///   // stake_deregistration
///   // stake_delegation
///   // pool_registration
///   // pool_retirement
///   // genesis_key_delegation
///   // move_instantaneous_rewards_cert
///   ]
///
/// stake_registration = (0, stake_credential)
/// stake_deregistration = (1, stake_credential)
/// stake_delegation = (2, stake_credential, pool_keyhash)
/// pool_registration = (3, pool_params)
/// pool_retirement = (4, pool_keyhash, epoch)
/// genesis_key_delegation = (5, genesishash, genesis_delegate_hash, vrf_keyhash)
/// move_instantaneous_rewards_cert = (6, move_instantaneous_reward)
///
struct Certificate
{
    enum Type
    {
        stake_registration = 0,
        stake_deregistration = 1,
        stake_delegation = 2,
        pool_registration = 3,
        pool_retirement = 4,
        genesis_key_delegation = 5,
        move_instantaneous_rewards_cert = 6
    };

    const Certificate::Type type;
};

/// @brief A stake registration certificate.
/// CDDL: stake_registration = (0, stake_credential)
struct StakeRegistration : public Certificate
{
    StakeRegistration() : Certificate{Certificate::stake_registration} {}
    StakeCredential stake_credential;
};

/// @brief A stake deregistration certificate.
/// CDDL: stake_deregistration = (1, stake_credential)
struct StakeDeregistration : public Certificate
{
    StakeDeregistration() : Certificate{Certificate::stake_deregistration} {}
    StakeCredential stake_credential;
};

/// @brief A stake delegation certificate.
/// CDDL: stake_delegation = (2, stake_credential, pool_keyhash)
struct StakeDelegation : public Certificate
{
    StakeDelegation() : Certificate{Certificate::stake_delegation} {}
    StakeCredential stake_credential;
    PoolKeyHash pool_keyhash;
};

/// @brief A pool registration certificate.
/// CDDL: pool_registration = (3, pool_params)
struct PoolRegistration : public Certificate
{
    PoolRegistration() : Certificate{Certificate::pool_registration} {}
    PoolParams pool_params;
};

/// @brief A pool retirement certificate.
/// CDDL: pool_retirement = (4, pool_keyhash, epoch)
struct PoolRetirement : public Certificate
{
    PoolRetirement() : Certificate{Certificate::pool_retirement} {}
    PoolKeyHash pool_keyhash;
    Epoch epoch;
};

/// @brief A genesis key delegation certificate.
/// CDDL: 
/// genesis_key_delegation = (5, genesishash, genesis_delegate_hash, vrf_keyhash)
struct GenesisKeyDelegation : public Certificate
{
    GenesisKeyDelegation() : Certificate{Certificate::genesis_key_delegation} {}
    GenesisHash genesishash;
    GenesisDelegateHash genesis_delegate_hash;
    VrfKeyHash vrf_keyhash;
};

/// @brief A move instantaneous rewards certificate.
/// CDDL: move_instantaneous_rewards_cert = (6, move_instantaneous_reward)
struct MoveInstantaneousRewardsCert : public Certificate
{
    MoveInstantaneousRewardsCert(MoveInstantaneousReward m)
        : Certificate{Certificate::move_instantaneous_rewards_cert}, move_instantaneous_reward{m}
    {
    }
    MoveInstantaneousReward move_instantaneous_reward;
};

/// @brief A transaction output
/// transaction_output = [address, amount : coin]
struct TransactionOutput
{
    Address address;
    Coin amount;
};

/// @brief A transaction input
/// transaction_input = [ transaction_id : $hash32
///                     , index : uint
///                     ]
struct TransactionInput
{
    Hash32 transaction_id;
    Uint index;

    // This is required for using with a std::set.
    // bool operator<(const Input& rhs) const { return value < rhs.value; }
};

/// @brief The body of a transaction
/// transaction_body =
///   { 0 : set<transaction_input>
///   , 1 : [* transaction_output]
///   , 2 : coin ; fee
///   , 3 : uint ; ttl
///   , ? 4 : [* certificate]
///   , ? 5 : withdrawals
///   , ? 6 : update
///   , ? 7 : metadata_hash
///   }
struct TransactionBody
{
    std::unordered_set<TransactionInput> transaction_inputs;
    std::vector<TransactionOutput> transaction_outputs;
    Coin fee;
    Uint ttl;
    std::optional<std::vector<std::unique_ptr<Certificate>>> certificates;
    std::optional<Withdrawals> withdrawals;
    std::optional<Update> update;
    std::optional<MetadataHash> metadata_hash;
};

/// @brief A transaction
/// transaction =
///   [ transaction_body
///   , transaction_witness_set
///   , transaction_metadata / null
///   ]
struct Transaction
{
    TransactionBody transaction_body;
    TransactionWitnessSet transaction_witness_set;
    std::optional<TransactionMetadata> transaction_metadata;
};

/// @brief Stake pool operational certificate.
/// operational_cert =
///   ( hot_vkey        : $kes_vkey
///   , sequence_number : uint
///   , kes_period      : uint
///   , sigma           : $signature
///   )
struct OperationalCert
{
    KesVkey hot_vkey;
    Uint sequence_number;
    Uint kes_period;
    Signature sigma;
};

/// @brief A block header body
/// header_body =
///   [ block_number     : uint
///   , slot             : uint
///   , prev_hash        : $hash32 / null
///   , issuer_vkey      : $vkey
///   , vrf_vkey         : $vrf_vkey
///   , nonce_vrf        : $vrf_cert
///   , leader_vrf       : $vrf_cert
///   , block_body_size  : uint
///   , block_body_hash  : $hash32 ; merkle triple root
///   , operational_cert
///   , protocol_version
///   ]
struct HeaderBody
{
    Uint block_number;
    Uint slot;
    std::optional<Hash32> prev_hash;
    Vkey issuer_vkey;
    VrfVkey vrf_vkey;
    VrfCert nonce_vrf;
    VrfCert leader_vrf;
    Uint block_body_size;
    Hash32 block_body_hash;
    OperationalCert operational_cert;
    ProtocolVersion protocol_version;
};

/// @brief A block header
/// header =
///   [ header_body
///   , kes_signature : $kes_signature
///   ]
struct Header
{
    HeaderBody header_body;
    KesSignature kes_signature;
};

/// @brief A block
/// block =
///   [ header
///   , transaction_bodies         : [* transaction_body]
///   , transaction_witness_sets   : [* transaction_witness_set]
///   , transaction_metadata_set   :
///       { * transaction_index => transaction_metadata }
///   ]; Valid blocks must also satisfy the following two constraints:
///    ; 1) the length of transaction_bodies and transaction_witness_sets
///    ;    must be the same
///    ; 2) every transaction_index must be strictly smaller than the
///    ;    length of transaction_bodies
struct Block
{
    Header header;
    std::vector<TransactionBody> transaction_bodies;
    std::vector<TransactionWitnessSet> transaction_witness_sets;
    std::unordered_map<TransactionIndex, TransactionMetadata> transaction_metadata_set;
};

// ; address format:
// ; [ 8 bit header | payload ];
// ;
// ; shelley payment addresses:
// ; bit 7: 0
// ; bit 6: base/other
// ; bit 5: pointer/enterprise [for base: stake cred is keyhash/scripthash]
// ; bit 4: payment cred is keyhash/scripthash
// ; bits 3-0: network id
// ;
// ; reward addresses:
// ; bits 7-5: 111
// ; bit 4: credential is keyhash/scripthash
// ; bits 3-0: network id
// ;
// ; byron addresses:
// ; bits 7-4: 1000
// 
// ; 0000: base address: keyhash28,keyhash28
// ; 0001: base address: scripthash28,keyhash28
// ; 0010: base address: keyhash28,scripthash28
// ; 0011: base address: scripthash28,scripthash28
// ; 0100: pointer address: keyhash28, 3 variable length uint
// ; 0101: pointer address: scripthash28, 3 variable length uint
// ; 0110: enterprise address: keyhash28
// ; 0111: enterprise address: scripthash28
// ; 1000: byron address
// ; 1110: reward account: keyhash28
// ; 1111: reward account: scripthash28
// ; 1001 - 1101: future formats

}  // namespace shelley

/// @brief Allegra era ledger types
namespace allegra
{

/// @brief Represent the protocol version.
/// The CDDL description is:
///     next_major_protocol_version = 5
///     major_protocol_version = 1..next_major_protocol_version
///     protocol_version = (major_protocol_version, uint)
struct ProtocolVersion
{
    const Uint next_major_protocol_version = 5;
    Uint major_protocol_version;
    Uint minor_protocol_version;

    [[nodiscard]] auto isValid() -> bool
    {
        return (major_protocol_version > 0) 
            && (major_protocol_version <= next_major_protocol_version);
    }
};

//   native_script =
//     [ script_pubkey
//     // script_all
//     // script_any
//     // script_n_of_k
//     // invalid_before
//         ; Timelock validity intervals are half-open intervals [a, b).
//         ; This field specifies the left (included) endpoint a.
//     // invalid_hereafter
//         ; Timelock validity intervals are half-open intervals [a, b).
//         ; This field specifies the right (excluded) endpoint b.
//     ]
struct NativeScript
{
    enum Type
    {
        script_pubkey = 0,
        script_all = 1,
        script_any = 2,
        script_n_of_k = 3, 
        invalid_before = 4, 
        invalid_hereafter = 5, 
    };

    const NativeScript::Type type;

    // serialization method should be virtual
};

/// script_pubkey = (0, addr_keyhash)
struct ScriptPubkey : public NativeScript
{
    ScriptPubkey() : NativeScript{NativeScript::Type::script_pubkey} {}
    std::vector<std::unique_ptr<AddrKeyHash>> addr_keyhashes;
};

/// script_all = (1, [ * native_script ])
struct ScriptAll : public NativeScript
{
    ScriptAll() : NativeScript{NativeScript::Type::script_all} {}
    std::vector<std::unique_ptr<NativeScript>> scripts;
};

/// script_any = (2, [ * native_script ])
struct ScriptAny : public NativeScript
{
    ScriptAny() : NativeScript{NativeScript::Type::script_any} {}
    std::vector<std::unique_ptr<NativeScript>> scripts;
};

/// script_n_of_k = (3, n: uint, [ * native_script ])
struct ScriptNofK : public NativeScript
{
    ScriptNofK() : NativeScript{NativeScript::Type::script_n_of_k} {}
    Uint n;
    std::vector<std::unique_ptr<NativeScript>> scripts;
};

/// invalid_before = (4, uint)
struct InvalidBefore : public NativeScript
{
    InvalidBefore() : NativeScript{NativeScript::Type::invalid_before} {}
    Uint n;
};

/// invalid_hereafter = (5, uint)
struct InvalidHereafter : public NativeScript
{
    InvalidHereafter() : NativeScript{NativeScript::Type::invalid_hereafter} {}
    Uint n;
};

// transaction_witness_set =
//   { ? 0: [* vkeywitness ]
//   , ? 1: [* native_script ]
//   , ? 2: [* bootstrap_witness ]
//   ; In the future, new kinds of witnesses can be added like this:
//   ; , ? 4: [* foo_script ]
//   ; , ? 5: [* plutus_script ]
// }
 struct TransactionWitnessSet
{
    std::vector<shelley::VkeyWitness> vkeywitnesses;
    std::vector<std::unique_ptr<NativeScript>> multisig_scripts;
    std::vector<shelley::BootstrapWitness> bootstrap_witnesses;
};

// auxiliary_data =
//   { * transaction_metadatum_label => transaction_metadatum }
//   / [ transaction_metadata: { * transaction_metadatum_label => transaction_metadatum }
//     , auxiliary_scripts: [ * native_script ]
//     ; other types of metadata...
//     ]
using AuxilaryData = std::any;

// multiasset<a> = { * policy_id => { * asset_name => a } }
// policy_id = scripthash
// asset_name = bytes .size (0..32)
// 
// value = coin / [coin,multiasset<uint>]
// mint = multiasset<int64>
// 
// int64 = -9223372036854775808 .. 9223372036854775807


// transaction_body =
//   { 0 : set<transaction_input>
//   , 1 : [* transaction_output]
//   , 2 : coin ; fee
//   , ? 3 : uint ; ttl
//   , ? 4 : [* certificate]
//   , ? 5 : withdrawals
//   , ? 6 : update
//   , ? 7 : metadata_hash
//   , ? 8 : uint ; validity interval start
//   }
struct TransactionBody
{
    std::unordered_set<shelley::TransactionInput> transaction_inputs;
    std::vector<shelley::TransactionOutput> transaction_outputs;
    Coin fee;
    Uint ttl;
    std::optional<std::vector<std::unique_ptr<shelley::Certificate>>> certificates;
    std::optional<shelley::Withdrawals> withdrawals;
    std::optional<shelley::Update> update;
    std::optional<MetadataHash> metadata_hash;
    std::optional<Uint> validity_interval_start;
};

/// @brief A transaction
/// transaction =
///   [ transaction_body
///   , transaction_witness_set
///   , auxiliary_data / null
///   ]
struct Transaction
{
    TransactionBody transaction_body;
    TransactionWitnessSet transaction_witness_set;
    std::optional<AuxilaryData> transaction_metadata;
};

/// @brief A block
/// block =
///   [ header
///   , transaction_bodies         : [* transaction_body]
///   , transaction_witness_sets   : [* transaction_witness_set]
///   , transaction_metadata_set   :
///       { * transaction_index => transaction_metadata }
///   ]; Valid blocks must also satisfy the following two constraints:
///    ; 1) the length of transaction_bodies and transaction_witness_sets
///    ;    must be the same
///    ; 2) every transaction_index must be strictly smaller than the
///    ;    length of transaction_bodies
struct Block
{
    shelley::Header header;
    std::vector<TransactionBody> transaction_bodies;
    std::vector<TransactionWitnessSet> transaction_witness_sets;
    std::unordered_map<TransactionIndex, AuxilaryData> transaction_metadata_set;
};

}  // namespace allegra

/// @brief Mary era ledger types
namespace mary
{

}  // namespace mary

/// @brief Alonzo era ledger types
namespace alonzo
{

}  // namespace alonzo

/// @brief Babbage era ledger types
namespace babbage
{

// To compute a script hash, note that you must prepend
// a tag to the bytes of the script before hashing.
// The tag is determined by the language.
// The tags in the Babbage era are:
//   "\x00" for multisig scripts
//   "\x01" for Plutus V1 scripts
//   "\x02" for Plutus V2 scripts

// CDDL: pool_metadata = [url, pool_metadata_hash]
using pool_metadata = std::tuple<Url, PoolMetadataHash>;

// CDDL:
//
//     single_host_addr = ( 0
//                     , port / null
//                     , ipv4 / null
//                     , ipv6 / null
//                     )
//     single_host_name = ( 1
//                     , port / null
//                     , dns_name ; An A or AAAA DNS record
//                     )
//     multi_host_name = ( 2
//                     , dns_name ; A SRV DNS record
//                     )
//     ipv4 = bytes .size 4
//     ipv6 = bytes .size 16
//
struct Relay
{
    enum class Type
    {
        single_host_addr,
        single_host_name,
        multi_host_name
    };  // Type
    Relay::Type type_{};
    uint16_t port_{};
    Bytes4 ipv4_{};
    Bytes16 ipv6_{};
    std::string dns_name_{};
};  // Relay

// CDDL:
//     pool_params = ( operator:       pool_keyhash
//                 , vrf_keyhash:    vrf_keyhash
//                 , pledge:         coin
//                 , cost:           coin
//                 , margin:         unit_interval
//                 , reward_account: reward_account
//                 , pool_owners:    set<addr_keyhash>
//                 , relays:         [* relay]
//                 , pool_metadata:  pool_metadata / null
//                 )
struct PoolParams
{
    PoolKeyHash operator_{};
    VrfKeyHash vrf_keyhash_{};
    Coin pledge_;
    Coin cost_;
    RewardAccount reward_account_{};
    std::set<AddrKeyHash> pool_owners_;
    std::vector<Relay> relays{};
    std::unique_ptr<pool_metadata> pool_metadata_{nullptr};
};

// CDDL:
//     stake_credential =
//       [  0, addr_keyhash
//       // 1, scripthash
//       ]
struct StakeCredential
{
    enum class Type
    {
        addr_keyhash,
        scripthash
    };  // Type
    StakeCredential::Type type_;
    AddrKeyHash addr_keyhash_;
    ScriptHash scripthash_;
};

// delta_coin = int
using delta_coin = int64_t;

// move_instantaneous_reward = [ 0 / 1, { * stake_credential => delta_coin } /
// coin ] ; The first field determines where the funds are drawn from. ; 0
// denotes the reserves, 1 denotes the treasury. ; If the second field is a map,
// funds are moved to stake credentials, ; otherwise the funds are given to the
// other accounting pot.
struct MoveInstantaneousReward
{
    Uint source;
    Coin coin;  // Use this if map is empty
    std::map<StakeCredential, Coin> stake_credentials;
};

// certificate =
//   [ stake_registration
//   // stake_deregistration
//   // stake_delegation
//   // pool_registration
//   // pool_retirement
//   // genesis_key_delegation
//   // move_instantaneous_rewards_cert
//   ]
//
// stake_registration = (0, stake_credential)
// stake_deregistration = (1, stake_credential)
// stake_delegation = (2, stake_credential, pool_keyhash)
// pool_registration = (3, pool_params)
// pool_retirement = (4, pool_keyhash, epoch)
// genesis_key_delegation = (5, genesishash, genesis_delegate_hash, vrf_keyhash)
// move_instantaneous_rewards_cert = (6, move_instantaneous_reward)
//
struct Certificate
{
    enum Type
    {
        stake_registration = 0,
        stake_deregistration = 1,
        stake_delegation = 2,
        pool_registration = 3,
        pool_retirement = 4,
        genesis_key_delegation = 5,
        move_instantaneous_rewards_cert = 6
    };

    const Certificate::Type type;
};

// CDDL: stake_registration = (0, stake_credential)
struct StakeRegistration : public Certificate
{
    StakeRegistration() : Certificate{Certificate::stake_registration} {}
    StakeCredential stake_credential;
};

// CDDL: stake_deregistration = (1, stake_credential)
struct StakeDeregistration : public Certificate
{
    StakeDeregistration() : Certificate{Certificate::stake_deregistration} {}
    StakeCredential stake_credential;
};

// CDDL: stake_delegation = (2, stake_credential, pool_keyhash)
struct StakeDelegation : public Certificate
{
    StakeDelegation() : Certificate{Certificate::stake_delegation} {}
    StakeCredential stake_credential;
    PoolKeyHash pool_keyhash;
};

// CDDL: pool_registration = (3, pool_params)
struct PoolRegistration : public Certificate
{
    PoolRegistration() : Certificate{Certificate::pool_registration} {}
    PoolParams pool_params;
};

// CDDL: pool_retirement = (4, pool_keyhash, epoch)
struct PoolRetirement : public Certificate
{
    PoolRetirement() : Certificate{Certificate::pool_retirement} {}
    PoolKeyHash pool_keyhash;
    Epoch epoch;
};

// CDDL: genesis_key_delegation = (5, genesishash, genesis_delegate_hash,
// vrf_keyhash)
struct GenesisKeyDelegation : public Certificate
{
    GenesisKeyDelegation() : Certificate{Certificate::genesis_key_delegation} {}
    GenesisHash genesishash;
    GenesisDelegateHash genesis_delegate_hash;
    VrfKeyHash vrf_keyhash;
};

// CDDL: move_instantaneous_rewards_cert = (6, move_instantaneous_reward)
struct MoveInstantaneousRewardsCert : public Certificate
{
    MoveInstantaneousRewardsCert()
        : Certificate{Certificate::move_instantaneous_rewards_cert}
    {
    }
    MoveInstantaneousReward move_instantaneous_reward;
};

// This is a hash of data which may affect evaluation of a script.
// CDDL:
//    script_data_hash = $hash32
using script_data_hash = Hash32;

// required_signers = set<$addr_keyhash>
using required_signers = std::set<AddrKeyHash>;

// // protocol_version = (uint, uint)
// using protocol_version = std::tuple<uint, uint>;



// transaction_index = uint .size 2
using transaction_index = uint16_t;

// vkeywitness = [ $vkey, $signature ]
using vkeywitness = std::tuple<Vkey, Signature>;

// bootstrap_witness =
//   [ public_key : $vkey
//   , signature  : $signature
//   , chain_code : bytes .size 32
//   , attributes : bytes
//   ]
struct bootstrap_witness
{
    Vkey public_key_;
    Signature signature_;
    Bytes32 chain_code_;
    Bytes attributes_;
};

// withdrawals = { * reward_account => coin }
using withdrawal = std::map<RewardAccount, Coin>;

// proposed_protocol_parameter_updates =
//   { * genesishash => protocol_param_update }

// update = [ proposed_protocol_parameter_updates
//          , epoch
//          ]



// protocol_param_update =
//   { ? 0:  uint               ; minfee A
//   , ? 1:  uint               ; minfee B
//   , ? 2:  uint               ; max block body size
//   , ? 3:  uint               ; max transaction size
//   , ? 4:  uint               ; max block header size
//   , ? 5:  coin               ; key deposit
//   , ? 6:  coin               ; pool deposit
//   , ? 7: epoch               ; maximum epoch
//   , ? 8: uint                ; n_opt: desired number of stake pools
//   , ? 9: rational            ; pool pledge influence
//   , ? 10: unit_interval      ; expansion rate
//   , ? 11: unit_interval      ; treasury growth rate
//   , ? 14: [protocol_version] ; protocol version
//   , ? 16: coin               ; min pool cost
//   , ? 17: coin               ; ada per utxo byte
//   , ? 18: costmdls           ; cost models for script languages
//   , ? 19: ex_unit_prices     ; execution costs
//   , ? 20: ex_units           ; max tx ex units
//   , ? 21: ex_units           ; max block ex units
//   , ? 22: uint               ; max value size
//   , ? 23: uint               ; collateral percentage
//   , ? 24: uint               ; max collateral inputs
//   }

// transaction =
//   [ transaction_body
//   , transaction_witness_set
//   , bool
//   , auxiliary_data / null
//   ]
struct Transaction
{
    // // datum_option = [ 0, $hash32 // 1, data ]
    // // script_ref = #6.24(bytes .cbor script)

    // CDDL:
    // transaction_output = legacy_transaction_output /
    // post_alonzo_transaction_output ; New
    //
    // legacy_transaction_output =
    //   [ address
    //   , amount : value
    //   , ? datum_hash : $hash32
    //   ]
    //
    // post_alonzo_transaction_output =
    //   { 0 : address
    //   , 1 : value
    //   , ? 2 : datum_option ; New; datum option
    //   , ? 3 : script_ref   ; New; script reference
    //   }
    //
    struct Output
    {
        enum class Type
        {
            legacy_transaction_output,
            post_alonzo_transaction_output
        };

        Output::Type type;
        Bytes address;
        Coin value;
        std::shared_ptr<Hash32> datum_hash{nullptr};
        // std::shared_ptr<datum_option> datum_option_{nullptr};
        // std::shared_ptr<script_ref> script_ref_{nullptr};
    };

    // transaction_input = [ transaction_id : $hash32
    //                     , index : uint
    //                     ]
    struct Input
    {
        Hash32 transaction_id{};
        Uint index;
        Coin value;

        // This is required for using with a std::set.
        bool operator<(const Input& rhs) const { return value < rhs.value; }
    };

    // transaction_body =
    //   { 0 : set<transaction_input>    ; inputs
    //   , 1 : [* transaction_output]
    //   , 2 : coin                      ; fee
    //   , ? 3 : uint                    ; time to live
    //   , ? 4 : [* certificate]
    //   , ? 5 : withdrawals
    //   , ? 6 : update
    //   , ? 7 : auxiliary_data_hash
    //   , ? 8 : uint                    ; validity interval start
    //   , ? 9 : mint
    //   , ? 11 : script_data_hash
    //   , ? 13 : set<transaction_input> ; collateral inputs
    //   , ? 14 : required_signers
    //   , ? 15 : network_id
    //   , ? 16 : transaction_output     ; collateral return; New
    //   , ? 17 : coin                   ; total collateral; New
    //   , ? 18 : set<transaction_input> ; reference inputs; New
    //   }
    struct Body
    {
        // Required
        std::set<Transaction::Input> inputs{};
        std::vector<Transaction::Output> outputs{};
        Coin fee;

        // Optional
        Coin ttl;
        std::vector<Certificate> certs;
        withdrawal withdrawals{};
    };

    // transaction_witness_set =
    //   { ? 0: [* vkeywitness ]
    //   , ? 1: [* native_script ]
    //   , ? 2: [* bootstrap_witness ]
    //   , ? 3: [* plutus_v1_script ]
    //   , ? 4: [* plutus_data ]
    //   , ? 5: [* redeemer ]
    //   , ? 6: [* plutus_v2_script ] ; New
    //   }
    struct WitnessSet
    {
        std::vector<vkeywitness> vkeywitness_vec;
        //
        std::vector<bootstrap_witness> bootstrap_witness_vec;
        std::vector<PlutusV1Script> plutus_v1_script_vec;
        // std::vector<plutus_data> plutus_data_vec;
        // std::vector<redeemer> redeemer_vec;
        std::vector<PlutusV2Script> plutus_v2_script_vec;
    };

    struct Metadata
    {
    };

    Transaction::Body body{};
    Transaction::WitnessSet witness_set{};
    std::shared_ptr<Transaction::Metadata> auxiliary_data{nullptr};
};

// block =
//   [ header
//   , transaction_bodies         : [* transaction_body]
//   , transaction_witness_sets   : [* transaction_witness_set]
//   , auxiliary_data_set         : {* transaction_index => auxiliary_data }
//   , invalid_transactions       : [* transaction_index ]
//   ]; Valid blocks must also satisfy the following two constraints:
//    ; 1) the length of transaction_bodies and transaction_witness_sets
//    ;    must be the same
//    ; 2) every transaction_index must be strictly smaller than the
//    ;    length of transaction_bodies
struct Block
{
    // header =
    //   [ header_body
    //   , body_signature : $kes_signature
    //   ]
    struct Header
    {
        // header_body =
        //   [ block_number     : uint
        //   , slot             : uint
        //   , prev_hash        : $hash32 / null
        //   , issuer_vkey      : $vkey
        //   , vrf_vkey         : $vrf_vkey
        //   , vrf_result       : $vrf_cert ; New, replaces nonce_vrf and
        //   leader_vrf , block_body_size  : uint , block_body_hash  : $hash32 ;
        //   merkle triple root , operational_cert , protocol_version
        //   ]
        struct Body
        {
            uint64_t block_number_;
            uint64_t slot_;
            std::unique_ptr<Hash32> prev_hash{nullptr};
            Vkey issuer_vkey_;
            VrfVkey vrf_vkey_;
            //
            Uint block_body_size_;
            Hash32 block_body_hash_;
            //
            //
        };
    };

    Block::Header header;
    std::vector<Transaction::Body> transaction_bodies;
    std::vector<Transaction::WitnessSet> transaction_witness_sets;
};

}  // namespace babbage

/// @brief Conway era ledger types
namespace conway
{
}  // namespace conway

}  // namespace cardano

#endif  // _CARDANO_LEDGER_HPP_