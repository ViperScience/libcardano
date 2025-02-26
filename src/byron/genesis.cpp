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

namespace cardano::byron
{

auto to_json(json& j, const SoftforkRule& sr) -> void
{
    j = json{
        {"initThd", sr.init_thd},
        {"minThd", sr.min_thd},
        {"thdDecrement", sr.thd_decrement}
    };
}

auto from_json(const json& j, SoftforkRule& sr) -> void
{
    j.at("initThd").get_to(sr.init_thd);
    j.at("minThd").get_to(sr.min_thd);
    j.at("thdDecrement").get_to(sr.thd_decrement);
}

auto to_json(json& j, const TxFeePolicy& tfp) -> void
{
    j = json{{"multiplier", tfp.multiplier}, {"summand", tfp.summand}};
}

auto from_json(const json& j, TxFeePolicy& tfp) -> void
{
    j.at("multiplier").get_to(tfp.multiplier);
    j.at("summand").get_to(tfp.summand);
}

auto to_json(json& j, const BlockVersionData& bvd) -> void
{
    j = json{
        {"heavyDelThd", bvd.heavy_del_thd},
        {"maxBlockSize", bvd.max_block_size},
        {"maxHeaderSize", bvd.max_header_size},
        {"maxProposalSize", bvd.max_proposal_size},
        {"maxTxSize", bvd.max_tx_size},
        {"mpcThd", bvd.mpc_thd},
        {"scriptVersion", bvd.script_version},
        {"slotDuration", bvd.slot_duration},
        {"softforkRule", bvd.softfork_rule},
        {"txFeePolicy", bvd.tx_fee_policy},
        {"unlockStakeEpoch", bvd.unlock_stake_epoch},
        {"updateImplicit", bvd.update_implicit},
        {"updateProposalThd", bvd.update_proposal_thd},
        {"updateVoteThd", bvd.update_vote_thd}
    };
}

auto from_json(const json& j, BlockVersionData& bvd) -> void
{
    j.at("heavyDelThd").get_to(bvd.heavy_del_thd);
    j.at("maxBlockSize").get_to(bvd.max_block_size);
    j.at("maxHeaderSize").get_to(bvd.max_header_size);
    j.at("maxProposalSize").get_to(bvd.max_proposal_size);
    j.at("maxTxSize").get_to(bvd.max_tx_size);
    j.at("mpcThd").get_to(bvd.mpc_thd);
    j.at("scriptVersion").get_to(bvd.script_version);
    j.at("slotDuration").get_to(bvd.slot_duration);
    j.at("softforkRule").get_to(bvd.softfork_rule);
    j.at("txFeePolicy").get_to(bvd.tx_fee_policy);
    j.at("unlockStakeEpoch").get_to(bvd.unlock_stake_epoch);
    j.at("updateImplicit").get_to(bvd.update_implicit);
    j.at("updateProposalThd").get_to(bvd.update_proposal_thd);
    j.at("updateVoteThd").get_to(bvd.update_vote_thd);
}

auto to_json(json& j, const ProtocolConsts& pc) -> void
{
    j = json{
        {"k", pc.k},
        {"protocolMagic", pc.protocol_magic},
        {"vssMaxTTL", pc.vss_max_ttl},
        {"vssMinTTL", pc.vss_min_ttl}
    };
}

auto from_json(const json& j, ProtocolConsts& pc) -> void
{
    j.at("k").get_to(pc.k);
    j.at("protocolMagic").get_to(pc.protocol_magic);
    j.at("vssMaxTTL").get_to(pc.vss_max_ttl);
    j.at("vssMinTTL").get_to(pc.vss_min_ttl);
}

auto to_json(json& j, const DelegationData& dd) -> void
{
    j = json{
        {"cert", dd.cert},
        {"delegatePk", dd.delegate_pk},
        {"issuerPk", dd.issuer_pk},
        {"omega", dd.omega}
    };
}

auto from_json(const json& j, DelegationData& dd) -> void
{
    j.at("cert").get_to(dd.cert);
    j.at("delegatePk").get_to(dd.delegate_pk);
    j.at("issuerPk").get_to(dd.issuer_pk);
    j.at("omega").get_to(dd.omega);
}

auto to_json(json& j, const VssCert& vc) -> void
{
    j = json{
        {"expiryEpoch", vc.expiry_epoch},
        {"signature", vc.signature},
        {"signingKey", vc.signing_key},
        {"vssKey", vc.vss_key}
    };
}

auto from_json(const json& j, VssCert& vc) -> void
{
    j.at("expiryEpoch").get_to(vc.expiry_epoch);
    j.at("signature").get_to(vc.signature);
    j.at("signingKey").get_to(vc.signing_key);
    j.at("vssKey").get_to(vc.vss_key);
}

auto to_json(json& j, const GenesisParameters& gp) -> void
{
    j = json{
        {"avvmDistr", gp.avvm_distr},
        {"blockVersionData", gp.block_version_data},
        {"ftsSeed", gp.fts_seed},
        {"protocolConsts", gp.protocol_consts},
        {"startTime", gp.start_time},
        {"bootStakeholders", gp.boot_stakeholders},
        {"heavyDelegation", gp.heavy_delegation},
        {"nonAvvmBalances", gp.non_avvm_balances},
        {"vssCerts", gp.vss_certs}
    };
}

auto from_json(const json& j, GenesisParameters& gp) -> void
{
    j.at("avvmDistr").get_to(gp.avvm_distr);
    j.at("blockVersionData").get_to(gp.block_version_data);
    j.at("ftsSeed").get_to(gp.fts_seed);
    j.at("protocolConsts").get_to(gp.protocol_consts);
    j.at("startTime").get_to(gp.start_time);
    j.at("bootStakeholders").get_to(gp.boot_stakeholders);
    j.at("heavyDelegation").get_to(gp.heavy_delegation);
    j.at("nonAvvmBalances").get_to(gp.non_avvm_balances);
    j.at("vssCerts").get_to(gp.vss_certs);
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

}  // namespace cardano::byron