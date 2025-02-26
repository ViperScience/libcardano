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

#include <cardano/genesis.hpp>
#include <fstream>

namespace cardano::shelley
{

auto to_json(json& j, const GenesisProtocolVersion& pv) -> void
{
    j = json{{"major", pv.major}, {"minor", pv.minor}};
}

auto from_json(const json& j, GenesisProtocolVersion& pv) -> void
{
    j.at("major").get_to(pv.major);
    j.at("minor").get_to(pv.minor);
}

auto to_json(json& j, const ExtraEntropy& ee) -> void
{
    j = json{{"tag", ee.tag}};
}

auto from_json(const json& j, ExtraEntropy& ee) -> void
{
    j.at("tag").get_to(ee.tag);
}

auto to_json(json& j, const ProtocolParameters& pp) -> void
{
    j = json{
        {"protocolVersion", pp.protocol_version},
        {"decentralisationParam", pp.decentralisation_param},
        {"eMax", pp.e_max},
        {"extraEntropy", pp.extra_entropy},
        {"maxTxSize", pp.max_tx_size},
        {"maxBlockBodySize", pp.max_block_body_size},
        {"maxBlockHeaderSize", pp.max_block_header_size},
        {"minFeeA", pp.min_fee_a},
        {"minFeeB", pp.min_fee_b},
        {"minUTxOValue", pp.min_utxo_value},
        {"poolDeposit", pp.pool_deposit},
        {"minPoolCost", pp.min_pool_cost},
        {"keyDeposit", pp.key_deposit},
        {"nOpt", pp.n_opt},
        {"rho", pp.rho},
        {"tau", pp.tau},
        {"a0", pp.a0}
    };
}

auto from_json(const json& j, ProtocolParameters& pp) -> void
{
    j.at("protocolVersion").get_to(pp.protocol_version);
    j.at("decentralisationParam").get_to(pp.decentralisation_param);
    j.at("eMax").get_to(pp.e_max);
    j.at("extraEntropy").get_to(pp.extra_entropy);
    j.at("maxTxSize").get_to(pp.max_tx_size);
    j.at("maxBlockBodySize").get_to(pp.max_block_body_size);
    j.at("maxBlockHeaderSize").get_to(pp.max_block_header_size);
    j.at("minFeeA").get_to(pp.min_fee_a);
    j.at("minFeeB").get_to(pp.min_fee_b);
    j.at("minUTxOValue").get_to(pp.min_utxo_value);
    j.at("poolDeposit").get_to(pp.pool_deposit);
    j.at("minPoolCost").get_to(pp.min_pool_cost);
    j.at("keyDeposit").get_to(pp.key_deposit);
    j.at("nOpt").get_to(pp.n_opt);
    j.at("rho").get_to(pp.rho);
    j.at("tau").get_to(pp.tau);
    j.at("a0").get_to(pp.a0);
}

auto to_json(json& j, const GenDeleg& gd) -> void
{
    j = json{{"delegate", gd.delegate}, {"vrf", gd.vrf}};
}

auto from_json(const json& j, GenDeleg& gd) -> void
{
    j.at("delegate").get_to(gd.delegate);
    j.at("vrf").get_to(gd.vrf);
}

auto to_json(json& j, const GenesisParameters& gp) -> void
{
    j = json{
        {"activeSlotsCoeff", gp.active_slots_coeff},
        {"protocolParams", gp.protocol_parameters},
        {"genDelegs", gp.gen_delegs},
        {"updateQuorum", gp.update_quorum},
        {"networkId", gp.network_id},
        {"initialFunds", json{}},
        {"maxLovelaceSupply", gp.max_lovelace_supply},
        {"networkMagic", gp.network_magic},
        {"epochLength", gp.epoch_length},
        {"systemStart", gp.system_start},
        {"slotsPerKESPeriod", gp.slots_per_kes_period},
        {"slotLength", gp.slot_length},
        {"maxKESEvolutions", gp.max_kes_evolutions},
        {"securityParam", gp.security_param},
    };
}

auto from_json(const json& j, GenesisParameters& gp) -> void
{
    j.at("activeSlotsCoeff").get_to(gp.active_slots_coeff);
    j.at("protocolParams").get_to(gp.protocol_parameters);
    j.at("genDelegs").get_to(gp.gen_delegs);
    j.at("updateQuorum").get_to(gp.update_quorum);
    j.at("networkId").get_to(gp.network_id);
    j.at("maxLovelaceSupply").get_to(gp.max_lovelace_supply);
    j.at("networkMagic").get_to(gp.network_magic);
    j.at("epochLength").get_to(gp.epoch_length);
    j.at("systemStart").get_to(gp.system_start);
    j.at("slotsPerKESPeriod").get_to(gp.slots_per_kes_period);
    j.at("securityParam").get_to(gp.slot_length);
    j.at("maxKESEvolutions").get_to(gp.max_kes_evolutions);
    j.at("securityParam").get_to(gp.security_param);
}

auto GenesisParameters::fromFile(const std::string& filename
) -> GenesisParameters
{
    std::ifstream file(filename);
    if (!file.is_open())
    {
        throw std::runtime_error("Failed to open genesis file: " + filename);
    }
    json j;
    file >> j;                          // Parse JSON from file
    return j.get<GenesisParameters>();  // Deserialize into struct
}

}  // namespace cardano::shelley