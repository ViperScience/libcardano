// Copyright (c) 2025 Viper Science LLC
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

#ifndef _CARDANO_GENESIS_HPP_
#define _CARDANO_GENESIS_HPP_

// Standard Library Headers
#include <cstdint>
#include <string>
#include <unordered_map>

// Third-Party Library Headers
#include <nlohmann/json.hpp>

using json = nlohmann::json;

/// @brief The root namespace for all Cardano functions and types.
namespace cardano
{

/// @brief The namespace for functions and types specific to the Byron era.
namespace byron
{

/// Struct for softforkRule within blockVersionData
struct SoftforkRule
{
    std::string init_thd;
    std::string min_thd;
    std::string thd_decrement;

    friend auto to_json(json& j, const SoftforkRule& sr) -> void;
    friend auto from_json(const json& j, SoftforkRule& sr) -> void;
};

// Struct for txFeePolicy within blockVersionData
struct TxFeePolicy
{
    std::string multiplier;
    std::string summand;

    friend auto to_json(json& j, const TxFeePolicy& tfp) -> void;
    friend auto from_json(const json& j, TxFeePolicy& tfp) -> void;
};

// Struct for blockVersionData
struct BlockVersionData
{
    std::string heavy_del_thd;
    std::string max_block_size;
    std::string max_header_size;
    std::string max_proposal_size;
    std::string max_tx_size;
    std::string mpc_thd;
    uint16_t script_version;
    std::string slot_duration;
    SoftforkRule softfork_rule;
    TxFeePolicy tx_fee_policy;
    std::string unlock_stake_epoch;
    std::string update_implicit;
    std::string update_proposal_thd;
    std::string update_vote_thd;

    friend auto to_json(json& j, const BlockVersionData& bvd) -> void;
    friend auto from_json(const json& j, BlockVersionData& bvd) -> void;
};

// Struct for protocolConsts
struct ProtocolConsts
{
    uint32_t k;
    uint32_t protocol_magic;
    uint32_t vss_max_ttl;
    uint32_t vss_min_ttl;

    friend auto to_json(json& j, const ProtocolConsts& pc) -> void;
    friend auto from_json(const json& j, ProtocolConsts& pc) -> void;
};

// Struct for heavyDelegation entries
struct DelegationData
{
    std::string cert;
    std::string delegate_pk;
    std::string issuer_pk;
    uint64_t omega;

    friend auto to_json(json& j, const DelegationData& dd) -> void;
    friend auto from_json(const json& j, DelegationData& dd) -> void;
};

// Struct for vssCerts entries
struct VssCert
{
    uint32_t expiry_epoch;
    std::string signature;
    std::string signing_key;
    std::string vss_key;

    friend auto to_json(json& j, const VssCert& vc) -> void;
    friend auto from_json(const json& j, VssCert& vc) -> void;
};

/// Structure representing Byron Era Genesis Parameters.
struct GenesisParameters
{
    std::map<std::string, std::string> avvm_distr;
    BlockVersionData block_version_data;
    std::string fts_seed;
    ProtocolConsts protocol_consts;
    uint64_t start_time;
    std::map<std::string, uint32_t> boot_stakeholders;
    std::map<std::string, DelegationData> heavy_delegation;
    std::map<std::string, uint64_t> non_avvm_balances;
    std::map<std::string, VssCert> vss_certs;

    friend auto to_json(json& j, const GenesisParameters& gp) -> void;
    friend auto from_json(const json& j, GenesisParameters& gp) -> void;

    /// @brief Populate the genesis parameters from a JSON file.
    /// @param file_path Path to the genesis JSON file.
    /// @return A populated GenesisParameters object.
    static auto fromFile(const std::string& filename) -> GenesisParameters;

};  // GenesisParameters

}  // namespace byron

/// @brief The namespace for functions and types specific to the Shelley era.
namespace shelley
{

/// Structure representing the protocol version in the Shelley-Era genesis
/// parameters.
struct GenesisProtocolVersion
{
    uint32_t major;
    uint32_t minor;

    friend auto to_json(json& j, const GenesisProtocolVersion& pv) -> void;
    friend auto from_json(const json& j, GenesisProtocolVersion& pv) -> void;
};  // GenesisProtocolVersion

/// Structure representing the extra entropy field in the Shelley-Era genesis
/// parameters.
struct ExtraEntropy
{
    std::string tag;

    friend auto to_json(json& j, const ExtraEntropy& ee) -> void;
    friend auto from_json(const json& j, ExtraEntropy& ee) -> void;
};  // ExtraEntropy

/// Structure representing the protocol parameters in the Shelley-Era genesis
/// parameters.
struct ProtocolParameters
{
    GenesisProtocolVersion protocol_version;
    uint64_t decentralisation_param;
    uint64_t e_max;
    ExtraEntropy extra_entropy;
    uint64_t max_tx_size;
    uint64_t max_block_body_size;
    uint64_t max_block_header_size;
    uint64_t min_fee_a;
    uint64_t min_fee_b;
    uint64_t min_utxo_value;
    uint64_t pool_deposit;
    uint64_t min_pool_cost;
    uint64_t key_deposit;
    uint64_t n_opt;
    double rho;
    double tau;
    double a0;

    friend auto to_json(json& j, const ProtocolParameters& pp) -> void;
    friend auto from_json(const json& j, ProtocolParameters& pp) -> void;
};  // ProtocolParameters

// Struct for genDelegs entries
struct GenDeleg
{
    std::string delegate;
    std::string vrf;

    friend auto to_json(json& j, const GenDeleg& gd) -> void;
    friend auto from_json(const json& j, GenDeleg& gd) -> void;
};

/// Structure representing Shelley Era Genesis Parameters.
struct GenesisParameters
{
    double active_slots_coeff;
    ProtocolParameters protocol_parameters;
    std::unordered_map<std::string, GenDeleg> gen_delegs;
    uint64_t update_quorum;
    std::string network_id;

    uint64_t max_lovelace_supply;
    uint64_t network_magic;
    uint64_t epoch_length;
    std::string system_start;
    uint64_t slots_per_kes_period;
    uint64_t slot_length;
    uint64_t max_kes_evolutions;
    uint64_t security_param;

    friend auto to_json(json& j, const GenesisParameters& gp) -> void;
    friend auto from_json(const json& j, GenesisParameters& gp) -> void;

    /// @brief Populate the genesis parameters from a JSON file.
    /// @param file_path Path to the genesis JSON file.
    /// @return A populated GenesisParameters object.
    static auto fromFile(const std::string& file_path) -> GenesisParameters;
};  // GenesisParameters

}  // namespace shelley

/// @brief The namespace for functions and types specific to the Alonzo era.
namespace alonzo
{

/// Struct for execution price fractions (prSteps, prMem)
struct PriceFraction
{
    int64_t numerator;
    int64_t denominator;

    friend auto to_json(json& j, const PriceFraction& pf) -> void;
    friend auto from_json(const json& j, PriceFraction& pf) -> void;
};

/// Struct for execution prices
struct ExecutionPrices
{
    PriceFraction pr_steps;
    PriceFraction pr_mem;

    friend auto to_json(json& j, const ExecutionPrices& ep) -> void;
    friend auto from_json(const json& j, ExecutionPrices& ep) -> void;
};

/// Struct for execution units (maxTxExUnits, maxBlockExUnits)
struct ExecutionUnits
{
    uint64_t ex_units_mem;
    uint64_t ex_units_steps;

    friend auto to_json(json& j, const ExecutionUnits& eu) -> void;
    friend auto from_json(const json& j, ExecutionUnits& eu) -> void;
};

/// Struct for cost models (PlutusV1)
struct CostModels
{
    std::map<std::string, int64_t> plutus_v1;

    friend auto to_json(json& j, const CostModels& cm) -> void;
    friend auto from_json(const json& j, CostModels& cm) -> void;
};

/// Structure representing Alonzo Era Genesis Parameters.
struct GenesisParameters
{
    uint64_t lovelace_per_utxo_word;
    ExecutionPrices execution_prices;
    ExecutionUnits max_tx_ex_units;
    ExecutionUnits max_block_ex_units;
    uint32_t max_value_size;
    uint32_t collateral_percentage;
    uint32_t max_collateral_inputs;
    CostModels cost_models;

    friend auto to_json(json& j, const GenesisParameters& gp) -> void;
    friend auto from_json(const json& j, GenesisParameters& gp) -> void;

    /// @brief Populate the genesis parameters from a JSON file.
    /// @param file_path Path to the genesis JSON file.
    /// @return A populated GenesisParameters object.
    static auto fromFile(const std::string& file_path) -> GenesisParameters;
};  // GenesisParameters

}  // namespace alonzo

/// @brief The namespace for functions and types specific to the Conway era.
namespace conway
{

/// Structure representing the pool voting thresholds in the Conway-Era genesis
/// parameters.
struct PoolVotingThresholds
{
    double committee_normal;
    double committee_no_confidence;
    double hard_fork_initiation;
    double motion_no_confidence;
    double pp_security_group;

    friend auto to_json(json& j, const PoolVotingThresholds& pvt) -> void;
    friend auto from_json(const json& j, PoolVotingThresholds& pvt) -> void;
};

/// Structure representing the dRep voting thresholds in the Conway-Era genesis
/// parameters.
struct DRepVotingThresholds
{
    double motion_no_confidence;
    double committee_normal;
    double committee_no_confidence;
    double update_to_constitution;
    double hard_fork_initiation;
    double pp_network_group;
    double pp_economic_group;
    double pp_technical_group;
    double pp_gov_group;
    double treasury_withdrawal;

    friend auto to_json(json& j, const DRepVotingThresholds& drvt) -> void;
    friend auto from_json(const json& j, DRepVotingThresholds& drvt) -> void;
};

/// Structure representing the Constitution Anchor in the Conway-Era genesis
/// parameters.
struct ConstitutionAnchor
{
    std::string data_hash;
    std::string url;

    friend auto to_json(json& j, const ConstitutionAnchor& a) -> void;
    friend auto from_json(const json& j, ConstitutionAnchor& a) -> void;
};

/// Structure representing the Consitution settings in the Conway-Era genesis
/// parameters.
struct Constitution
{
    ConstitutionAnchor anchor;
    std::string script;

    friend auto to_json(json& j, const Constitution& c) -> void;
    friend auto from_json(const json& j, Constitution& c) -> void;
};

/// Structure representing the Committee threshold in the Conway-Era genesis
/// parameters.
struct CommitteeThreshold
{
    uint64_t numerator;
    uint64_t denominator;

    friend auto to_json(json& j, const CommitteeThreshold& t) -> void;
    friend auto from_json(const json& j, CommitteeThreshold& t) -> void;
};

/// Structure representing the Committee settings in the Conway-Era genesis
/// parameters.
struct Committee
{
    std::unordered_map<std::string, uint64_t> members;
    CommitteeThreshold threshold;

    friend auto to_json(json& j, const Committee& c) -> void;
    friend auto from_json(const json& j, Committee& c) -> void;
};

/// Structure representing Conway-Era genesis parameters.
struct GenesisParameters
{
    PoolVotingThresholds pool_voting_thresholds;
    DRepVotingThresholds drep_voting_thresholds;
    uint64_t committee_min_size;
    uint64_t committee_max_term_length;
    uint64_t gov_action_lifetime;
    uint64_t gov_action_deposit;
    uint64_t drep_deposit;
    uint64_t drep_activity;
    uint64_t min_fee_ref_script_cost_per_byte;
    std::array<int64_t, 251> plutus_v3_cost_model;
    Constitution constitution;
    Committee committee;

    friend auto to_json(json& j, const GenesisParameters& gp) -> void;
    friend auto from_json(const json& j, GenesisParameters& gp) -> void;

    /// @brief Populate the genesis parameters from a JSON file.
    /// @param file_path Path to the genesis JSON file.
    /// @return A populated GenesisParameters object.
    static auto fromFile(const std::string& file_path) -> GenesisParameters;
};  // GenesisParameters

}  // namespace conway

}  // namespace cardano

#endif  // _CARDANO_GENESIS_HPP_