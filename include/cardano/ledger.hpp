// Copyright (c) 2021 Viper Science LLC
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

#include <array>
#include <cstdint>
#include <map>
#include <memory>
#include <set>
#include <tuple>
#include <vector>

// Official Spec (Babbage Era):
// https://github.com/input-output-hk/cardano-ledger/blob/master/eras/babbage/test-suite/cddl-files/babbage.cddl#L13
//
// This code takes the approach of trying to represent the CDDL spec in C++
// structures. These structures will be used by logic in other classes and
// files.

namespace cardano
{

using uint = uint64_t;
using coin = uint;
using Epoch = uint;

using byte = uint8_t;
using bytes = std::vector<byte>;
using bytes4 = std::array<byte, 4>;
using bytes16 = std::array<byte, 16>;
using bytes28 = std::array<byte, 28>;
using bytes32 = std::array<byte, 32>;
using bytes64 = std::array<byte, 64>;
using bytes80 = std::array<byte, 80>;
using bytes448 = std::array<byte, 448>;

using vkey = bytes32;
using vrf_vkey = bytes32;
using vrf_cert = std::tuple<bytes, bytes80>;
using kes_vkey = bytes32;
using kes_signature = bytes448;
using signkeyKES = bytes64;
using signature = bytes64;

using hash28 = bytes28;
using hash32 = bytes32;
using addr_keyhash = hash28;
using GenesisDelegateHash = hash28;
using PoolKeyHash = hash28;
using GenesisHash = hash28;

// To compute a script hash, note that you must prepend
// a tag to the bytes of the script before hashing.
// The tag is determined by the language.
// The tags in the Babbage era are:
//   "\x00" for multisig scripts
//   "\x01" for Plutus V1 scripts
//   "\x02" for Plutus V2 scripts
using scripthash = hash28;

using VrfKeyHash = hash32;
using auxiliary_data_hash = hash32;
using pool_metadata_hash = hash32;

using address = bytes;
using reward_account = bytes;

using plutus_v1_script = bytes;
using plutus_v2_script = bytes;

using url = std::string;

/// @brief Namespace for all Babbage Era ledger objects.
namespace babbage
{

// CDDL: pool_metadata = [url, pool_metadata_hash]
using pool_metadata = std::tuple<url, pool_metadata_hash>;

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
    bytes4 ipv4_{};
    bytes16 ipv6_{};
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
    coin pledge_;
    coin cost_;
    reward_account reward_account_{};
    std::set<addr_keyhash> pool_owners_;
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
    addr_keyhash addr_keyhash_;
    scripthash scripthash_;
};

// delta_coin = int
using delta_coin = int64_t;

// move_instantaneous_reward = [ 0 / 1, { * stake_credential => delta_coin } /
// coin ] ; The first field determines where the funds are drawn from. ; 0
// denotes the reserves, 1 denotes the treasury. ; If the second field is a map,
// funds are moved to stake credentials, ; otherwise the funds are given to the
// other accounting pot.
class MoveInstantaneousReward
{
  private:
    uint source_;
    coin coin_;  // Use this if map is empty
    std::map<StakeCredential, coin> stake_credentials_;
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
using script_data_hash = hash32;

// required_signers = set<$addr_keyhash>
using required_signers = std::set<addr_keyhash>;

// protocol_version = (uint, uint)
using protocol_version = std::tuple<uint, uint>;

// CDDL:
//     operational_cert =
//       ( hot_vkey        : $kes_vkey
//       , sequence_number : uint
//       , kes_period      : uint
//       , sigma           : $signature
//       )
struct OperationalCert
{
    kes_vkey hot_vkey;
    uint sequence_number;
    uint kes_period;
    signature sigma;
};

// transaction_index = uint .size 2
using transaction_index = uint16_t;

// vkeywitness = [ $vkey, $signature ]
using vkeywitness = std::tuple<vkey, signature>;

// bootstrap_witness =
//   [ public_key : $vkey
//   , signature  : $signature
//   , chain_code : bytes .size 32
//   , attributes : bytes
//   ]
struct bootstrap_witness
{
    vkey public_key_;
    signature signature_;
    bytes32 chain_code_;
    bytes attributes_;
};

// withdrawals = { * reward_account => coin }
using withdrawal = std::map<reward_account, coin>;

// update = [ proposed_protocol_parameter_updates
//          , epoch
//          ]

// proposed_protocol_parameter_updates =
//   { * genesishash => protocol_param_update }

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
        bytes address;
        coin value;
        std::shared_ptr<hash32> datum_hash{nullptr};
        // std::shared_ptr<datum_option> datum_option_{nullptr};
        // std::shared_ptr<script_ref> script_ref_{nullptr};
    };

    // transaction_input = [ transaction_id : $hash32
    //                     , index : uint
    //                     ]
    struct Input
    {
        hash32 transaction_id{};
        uint index;
        coin value;

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
        coin fee;

        // Optional
        coin ttl;
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
        std::vector<plutus_v1_script> plutus_v1_script_vec;
        // std::vector<plutus_data> plutus_data_vec;
        // std::vector<redeemer> redeemer_vec;
        std::vector<plutus_v2_script> plutus_v2_script_vec;
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
            std::unique_ptr<hash32> prev_hash{nullptr};
            vkey issuer_vkey_;
            vrf_vkey vrf_vkey_;
            //
            uint block_body_size_;
            hash32 block_body_hash_;
            //
            //
        };
    };

    Block::Header header;
    std::vector<Transaction::Body> transaction_bodies;
    std::vector<Transaction::WitnessSet> transaction_witness_sets;
};

}  // namespace babbage
}  // namespace cardano

#endif  // _CARDANO_LEDGER_HPP_