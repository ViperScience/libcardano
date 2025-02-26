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

// Third-party library headers
#include <catch2/catch_test_macros.hpp>

// Public libcardano headers
#include <cardano/genesis.hpp>

TEST_CASE("testCardanoGenesisAPI")
{
    SECTION("testByronGenesisParameters")
    {
        const auto params = cardano::byron::GenesisParameters::fromFile("data/genesis/byron-genesis.json");
        REQUIRE(params.protocol_consts.protocol_magic == 764824073);
    }

    SECTION("testShelleyGenesisParameters")
    {
        const auto params = cardano::shelley::GenesisParameters::fromFile("data/genesis/shelley-genesis.json");
        REQUIRE(params.protocol_parameters.protocol_version.major == 2);
        REQUIRE(params.epoch_length == 432000);
    }

    SECTION("testAlonzoGenesisParameters")
    {
        const auto params = cardano::alonzo::GenesisParameters::fromFile("data/genesis/alonzo-genesis.json");
        REQUIRE(params.lovelace_per_utxo_word == 34482);
    }

    SECTION("testConwayGenesisParameters")
    {
        const auto params = cardano::conway::GenesisParameters::fromFile("data/genesis/conway-genesis.json");
        REQUIRE(params.committee_min_size == 7);
    }
}