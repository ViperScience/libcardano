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

namespace cardano::alonzo
{

auto to_json(json& j, const PriceFraction& pf) -> void
{
    j = json{{"numerator", pf.numerator}, {"denominator", pf.denominator}};
}

auto from_json(const json& j, PriceFraction& pf) -> void
{
    j.at("numerator").get_to(pf.numerator);
    j.at("denominator").get_to(pf.denominator);
}

auto to_json(json& j, const ExecutionPrices& ep) -> void
{
    j = json{{"prSteps", ep.pr_steps}, {"prMem", ep.pr_mem}};
}

auto from_json(const json& j, ExecutionPrices& ep) -> void
{
    j.at("prSteps").get_to(ep.pr_steps);
    j.at("prMem").get_to(ep.pr_mem);
}

auto to_json(json& j, const ExecutionUnits& eu) -> void
{
    j = json{
        {"exUnitsMem", eu.ex_units_mem}, {"exUnitsSteps", eu.ex_units_steps}
    };
}

auto from_json(const json& j, ExecutionUnits& eu) -> void
{
    j.at("exUnitsMem").get_to(eu.ex_units_mem);
    j.at("exUnitsSteps").get_to(eu.ex_units_steps);
}

auto to_json(json& j, const CostModels& cm) -> void
{
    j = json{{"PlutusV1", cm.plutus_v1}};
}

auto from_json(const json& j, CostModels& cm) -> void
{
    j.at("PlutusV1").get_to(cm.plutus_v1);
}

auto to_json(json& j, const GenesisParameters& gp) -> void
{
    j = json{
        {"lovelacePerUTxOWord", gp.lovelace_per_utxo_word},
        {"executionPrices", gp.execution_prices},
        {"maxTxExUnits", gp.max_tx_ex_units},
        {"maxBlockExUnits", gp.max_block_ex_units},
        {"maxValueSize", gp.max_value_size},
        {"collateralPercentage", gp.collateral_percentage},
        {"maxCollateralInputs", gp.max_collateral_inputs},
        {"costModels", gp.cost_models}
    };
}

auto from_json(const json& j, GenesisParameters& gp) -> void
{
    j.at("lovelacePerUTxOWord").get_to(gp.lovelace_per_utxo_word);
    j.at("executionPrices").get_to(gp.execution_prices);
    j.at("maxTxExUnits").get_to(gp.max_tx_ex_units);
    j.at("maxBlockExUnits").get_to(gp.max_block_ex_units);
    j.at("maxValueSize").get_to(gp.max_value_size);
    j.at("collateralPercentage").get_to(gp.collateral_percentage);
    j.at("maxCollateralInputs").get_to(gp.max_collateral_inputs);
    j.at("costModels").get_to(gp.cost_models);
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

}  // namespace cardano::alonzo