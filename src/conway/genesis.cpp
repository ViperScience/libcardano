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

namespace cardano::conway
{

auto to_json(json& j, const PoolVotingThresholds& pvt) -> void
{
    j = json{
        {"committeeNormal", pvt.committee_normal},
        {"committeeNoConfidence", pvt.committee_no_confidence},
        {"hardForkInitiation", pvt.hard_fork_initiation},
        {"motionNoConfidence", pvt.motion_no_confidence},
        {"ppSecurityGroup", pvt.pp_security_group}
    };
}

auto from_json(const json& j, PoolVotingThresholds& pvt) -> void
{
    j.at("committeeNormal").get_to(pvt.committee_normal);
    j.at("committeeNoConfidence").get_to(pvt.committee_no_confidence);
    j.at("hardForkInitiation").get_to(pvt.hard_fork_initiation);
    j.at("motionNoConfidence").get_to(pvt.motion_no_confidence);
    j.at("ppSecurityGroup").get_to(pvt.pp_security_group);
}

auto to_json(json& j, const DRepVotingThresholds& drvt) -> void
{
    j = json{
        {"motionNoConfidence", drvt.motion_no_confidence},
        {"committeeNormal", drvt.committee_normal},
        {"committeeNoConfidence", drvt.committee_no_confidence},
        {"updateToConstitution", drvt.update_to_constitution},
        {"hardForkInitiation", drvt.hard_fork_initiation},
        {"ppNetworkGroup", drvt.pp_network_group},
        {"ppEconomicGroup", drvt.pp_economic_group},
        {"ppTechnicalGroup", drvt.pp_technical_group},
        {"ppGovGroup", drvt.pp_gov_group},
        {"treasuryWithdrawal", drvt.treasury_withdrawal}
    };
}

auto from_json(const json& j, DRepVotingThresholds& drvt) -> void
{
    j.at("motionNoConfidence").get_to(drvt.motion_no_confidence);
    j.at("committeeNormal").get_to(drvt.committee_normal);
    j.at("committeeNoConfidence").get_to(drvt.committee_no_confidence);
    j.at("updateToConstitution").get_to(drvt.update_to_constitution);
    j.at("hardForkInitiation").get_to(drvt.hard_fork_initiation);
    j.at("ppNetworkGroup").get_to(drvt.pp_network_group);
    j.at("ppEconomicGroup").get_to(drvt.pp_economic_group);
    j.at("ppTechnicalGroup").get_to(drvt.pp_technical_group);
    j.at("ppGovGroup").get_to(drvt.pp_gov_group);
    j.at("treasuryWithdrawal").get_to(drvt.treasury_withdrawal);
}

auto to_json(json& j, const ConstitutionAnchor& ca) -> void
{
    j = json{{"dataHash", ca.data_hash}, {"url", ca.url}};
}

auto from_json(const json& j, ConstitutionAnchor& ca) -> void
{
    j.at("dataHash").get_to(ca.data_hash);
    j.at("url").get_to(ca.url);
}

auto to_json(json& j, const Constitution& c) -> void
{
    j = json{{"anchor", c.anchor}, {"script", c.script}};
}

auto from_json(const json& j, Constitution& c) -> void
{
    j.at("anchor").get_to(c.anchor);
    j.at("script").get_to(c.script);
}

auto to_json(json& j, const CommitteeThreshold& ct) -> void
{
    j = json{{"numerator", ct.numerator}, {"denominator", ct.denominator}};
}

auto from_json(const json& j, CommitteeThreshold& ct) -> void
{
    j.at("numerator").get_to(ct.numerator);
    j.at("denominator").get_to(ct.denominator);
}

auto to_json(json& j, const Committee& c) -> void
{
    j = json{{"members", c.members}, {"threshold", c.threshold}};
}

auto from_json(const json& j, Committee& c) -> void
{
    j.at("members").get_to(c.members);
    j.at("threshold").get_to(c.threshold);
}

auto to_json(json& j, const GenesisParameters& gp) -> void
{
    j = json{
        {"poolVotingThresholds", gp.pool_voting_thresholds},
        {"dRepVotingThresholds", gp.drep_voting_thresholds},
        {"committeeMinSize", gp.committee_min_size},
        {"committeeMaxTermLength", gp.committee_max_term_length},
        {"govActionLifetime", gp.gov_action_lifetime},
        {"govActionDeposit", gp.gov_action_deposit},
        {"dRepDeposit", gp.drep_deposit},
        {"dRepActivity", gp.drep_activity},
        {"minFeeRefScriptCostPerByte", gp.min_fee_ref_script_cost_per_byte},
        {"plutusV3CostModel", gp.plutus_v3_cost_model},
        {"constitution", gp.constitution},
        {"committee", gp.committee}
    };
}

auto from_json(const json& j, GenesisParameters& gp) -> void
{
    j.at("poolVotingThresholds").get_to(gp.pool_voting_thresholds);
    j.at("dRepVotingThresholds").get_to(gp.drep_voting_thresholds);
    j.at("committeeMinSize").get_to(gp.committee_min_size);
    j.at("committeeMaxTermLength").get_to(gp.committee_max_term_length);
    j.at("govActionLifetime").get_to(gp.gov_action_lifetime);
    j.at("govActionDeposit").get_to(gp.gov_action_deposit);
    j.at("dRepDeposit").get_to(gp.drep_deposit);
    j.at("dRepActivity").get_to(gp.drep_activity);
    j.at("minFeeRefScriptCostPerByte")
        .get_to(gp.min_fee_ref_script_cost_per_byte);
    j.at("plutusV3CostModel").get_to(gp.plutus_v3_cost_model);
    j.at("constitution").get_to(gp.constitution);
    j.at("committee").get_to(gp.committee);
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

}  // namespace cardano::conway