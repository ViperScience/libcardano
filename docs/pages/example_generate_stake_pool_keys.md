@page example-generate-stake-pool-keys Generate Stake Pool Keys

This example demonstrates how libcardano primitives might be used to generate a new set of stake pool keys.
The example is currently in progress.

@cpp
#include <iostream>
#include <cardano/cardano.hpp>

int main(int argc, char** argv)
{
    constexpr std::string_view seed_phrase = "exercise club noble adult miracle awkward problem olympic puppy private goddess piano fatal fashion vacuum";    

    auto mn = cardano::Mnemonic(seed_phrase, cardano::BIP39Language::English);

    auto cold_skey = cardano::stake_pool::ExtendedColdSigningKey::fromMnemonic(mn);
    auto cold_vkey = cold_skey.verificationKey();

    std::cout << "Cold SKey: " << cold_skey.asBech32() << std::endl;
    std::cout << "Cold VKey: " << cold_vkey.asBech32() << std::endl;
    std::cout << "Pool ID : " << BECH32::encode("pool", cold_vkey.poolId()) << std::endl;

    // Write the keys to file
    cold_skey.saveToFile("./cold.skey");
    cold_vkey.saveToFile("./cold.vkey");

    // Generate a new op cert issue counter
    auto ocic = cardano::stake_pool::OperationalCertificateIssueCounter();
    ocic.saveToFile("./cold.counter", cold_vkey);

    return 0;
}
@endcpp

Example output: