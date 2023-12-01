@mainpage libcardano
@image html logo.png width=1280px
@tableofcontents

<!-- --------------------------------------------------------------------------------------------------------------- -->

Libcardano is a high-performance library of Cardano blockchain tools written in modern C++.

<!-- --------------------------------------------------------------------------------------------------------------- -->

@section mainpage-features Features

- Simple API exposing Cardano functionality and data types
    - Byron and Shelley Addresses
    - HD Wallets
    - BIP-39 Mnemonic seed phrase generation (supporting all language lists)
    - Stake pool keys and certificates
    - Transactions
    - Other ledger data structures e.g., certificates and block headers
- Encodings: Base16, Base58, Bech32
- Object serialization and de-serialization in CBOR formats
- C++20

<!-- --------------------------------------------------------------------------------------------------------------- -->

@section mainpage-api-documentation API documentation

Browse the docs using the links at the top of the page.
You can search from anywhere by pressing the TAB key.

<!-- --------------------------------------------------------------------------------------------------------------- -->

@section mainpage-basic-usage Basic Usage

Libcardano is designed to be a simple plugin for C++ applications to include Cardano blockchain functionality. In your C++ code simply add `#include <cardano/cardano.hpp>` and then use library objects and methods under the `cardano` namespace. Finally, link against libcardano during build. If built and installed properly using the provided CMake configuration, libcardano may be included in your own CMake projects via `find_package(Cardano)`.

<!-- --------------------------------------------------------------------------------------------------------------- -->

@section mainpage-building Building from Source

The libcardano library currently relies on functionality provided in submodules. Prior to building, you must clone the repository including the submodules.

    git clone --recurse-submodules -j8 https://gitlab.com/viperscience/libcardano.git

A CMake build file is included which simplifies the compilation, test, and install process.

    cd libcardano
    mkdir build && cd build \
    cmake -DCMAKE_BUILD_TYPE=Release ..
    make -j 8
    make test
    make install

A Docker build option is also provided.

    docker build -t libcardano:latest .

<!-- --------------------------------------------------------------------------------------------------------------- -->

@subsection mainpage-ext External Dependencies

Libcardano links with the following external dependencies. 

* [Botan-2](https://botan.randombit.net/)

The provided Docker file demonstrates how to build and install the required dependencies and Cmake find scripts are also provided.

<!-- --------------------------------------------------------------------------------------------------------------- -->

@section mainpage-example Basic examples

<!-- --------------------------------------------------------------------------------------------------------------- -->

@subsection mainpage-example-parsing-files Generate a Payment Address from Mnemonic

@cpp
#include <iostream>
#include <cardano/cardano.hpp>

int main(int argc, char** argv)
{
    constexpr std::string_view seed_phrase = "exercise club noble adult miracle awkward problem olympic puppy private goddess piano fatal fashion vacuum";    

    auto mn = cardano::Mnemonic(seed_phrase, cardano::BIP39Language::English);

    auto root_xsk = cardano::BIP32PrivateKey::fromMnemonic(mn);

    auto acct_xsk = root_xsk.deriveChild(cardano::HardenIndex(1852))
                            .deriveChild(cardano::HardenIndex(1815))
                            .deriveChild(cardano::HardenIndex(0));
    auto acct_xvk = acct_xsk.toPublic();
    auto addr_xvk = acct_xvk.deriveChild(0).deriveChild(0);
    auto stake_xvk = acct_xvk.deriveChild(2).deriveChild(0);

    // Derive the base address (testnet)
    auto addr = cardano::BaseAddress::fromKeys(cardano::NetworkID::testnet, addr_xvk, stake_xvk);
    std::cout << addr.toBech32("addr_test") << std::endl;

    return 0;
}
@endcpp

@see

-   cardano::BIP32PrivateKey
-   cardano::Mnemonic
-   cardano::BaseAddress

@subsection mainpage-example-stake-pool-keys Generate Stake Pool Keys

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

@see

-   cardano::stake_pool::ExtendedColdSigningKey
-   cardano::stake_pool::ColdVerificationKey
-   cardano::stake_pool::OperationalCertificateIssueCounter
<!-- --------------------------------------------------------------------------------------------------------------- -->