// Copyright (c) 2024 Viper Science LLC
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

#include <iostream>
#include <cardano/cardano.hpp>

using namespace cardano;

auto main(int argc, char** argv) -> int
{
    constexpr std::string_view seed_phrase = "exercise club noble adult miracle awkward problem olympic puppy private goddess piano fatal fashion vacuum";    

    const auto mn = cardano::Mnemonic(seed_phrase, cardano::BIP39Language::English);

    const auto cold_skey = cardano::stake_pool::ExtendedColdSigningKey::fromMnemonic(mn);
    const auto cold_vkey = cold_skey.verificationKey();

    std::cout << "Generating stake pool keys for pool with ID:" << std::endl;
    std::cout << BECH32::encode("pool", cold_vkey.poolId()) << std::endl;

    // Write the cold keys to file
    cold_skey.saveToFile("./cold.skey");
    cold_vkey.saveToFile("./cold.vkey");

    // Generate a new set of KES keys
    const auto kes_skey = cardano::stake_pool::KesSigningKey::generate();
    const auto kes_vkey = kes_skey.verificationKey();

    // Write the KES keys to file
    kes_skey.saveToFile("./kes.skey");
    kes_vkey.saveToFile("./kes.vkey");

    // Generate a new op cert issue counter
    auto ocic = cardano::stake_pool::OperationalCertificateIssueCounter();
    ocic.saveToFile("./cold.counter", cold_vkey);

    // Generate a new op cert
    const auto kes_period = 1;
    auto op_cert = cardano::stake_pool::OperationalCertificateManager::generate(
        kes_vkey, ocic, kes_period, cold_skey
    );
    op_cert.saveToFile("./pool.cert", cold_vkey);

    // Generate a new set of VRF keys
    const auto vrf_skey = cardano::stake_pool::VrfSigningKey::generate();
    const auto vrf_vkey = vrf_skey.verificationKey(); 

    // Write the VRF keys to file
    vrf_skey.saveToFile("./vrf.skey");
    vrf_vkey.saveToFile("./vrf.vkey");

    return 0;
}