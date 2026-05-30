@mainpage libcardano
@image html logo.png width=1280px
@tableofcontents

<!-- --------------------------------------------------------------------------------------------------------------- -->

Libcardano is a high-performance library of Cardano blockchain tools written in modern C++.

Libcardano is an **offline** SDK: it focuses on key management, address derivation, and transaction construction, signing, and (de)serialization. It does **not** include node networking or chain synchronization — the signed transactions it produces are handed off for submission by your own node, wallet backend, or service. Ledger data structures span the Byron through Conway eras; the active transaction-building path currently targets the **Babbage** era (the Shelley implementation is retained for older eras).

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

Libcardano is designed to be a simple plugin for C++ applications to include Cardano blockchain functionality. In your C++ code simply add `#include <cardano/cardano.hpp>` and then use library objects and methods under the `cardano` namespace. Finally, link against libcardano during build. If built and installed properly using the provided CMake configuration, libcardano may be included in your own CMake projects via `find_package(cardano)`.

<!-- --------------------------------------------------------------------------------------------------------------- -->

@section mainpage-building Building from Source

Clone the repository and change into it:

    git clone https://gitlab.com/viperscience/libcardano.git
    cd libcardano

Building requires a C++20 toolchain (GCC 14+ or a recent Clang) and CMake 3.25+. Only Botan 3 and OpenSSL development libraries need to be present on the system; every other dependency is fetched automatically by CMake at configure time.

A [`justfile`](https://gitlab.com/viperscience/libcardano/-/blob/main/justfile) wraps the configure/build/test/install workflow into a single step:

    just build      # Release build (library + examples)
    just test       # build, then run the full test suite
    just install    # test, then install system-wide (uses sudo)

To invoke CMake directly instead:

    cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
    cmake --build build --parallel 8
    ctest --test-dir build --output-on-failure
    cmake --install build

A Docker build option is also provided.

    docker build -t libcardano:latest .

A pre-configured Dev Container (see `.devcontainer/`) ships the full toolchain and all system dependencies, requiring only a dev-container-compatible editor on the host.

<!-- --------------------------------------------------------------------------------------------------------------- -->

@subsection mainpage-ext External Dependencies

Libcardano links with the following external dependencies. 

* [Botan-3](https://botan.randombit.net/) — general cryptography (hashing, RNG, encryption/decryption).
* [libsodium](https://github.com/IntersectMBO/libsodium) — the Cardano fork provides the VRF keys used in the protocol; its Ed25519 functions are also used.

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