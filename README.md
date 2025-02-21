<img 
    style="display: block; 
           margin-left: auto;
           margin-right: auto;
           width: 60%;"
    src="docs/img/logo.png" 
    alt="libcardano logo">
</img>

# libcardano

A high-performance Software Development Kit (SDK) for the Cardano Blockchain written in modern C++.

## Features

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

## Basic Usage

Libcardano is designed to be a simple plugin for modern C++ applications that require Cardano blockchain functionality.
In your C++ code simply add `#include <cardano/cardano.hpp>` and then use library objects and methods within the `cardano` namespace.
Finally, link against libcardano during build using one of the methods outlined below. 

### CMake via Git submodule
Add libcardano as a submodule to an existing cmake project and then add the libcardano directory, e.g., `add_subdirectory(./libcardano)`, which provides the target `cardano::cardano` for linking.

    add_subdirectory(./libcardano)
    target_link_libraries(${PROJECT_NAME} PRIVATE cardano::cardano)

### CMake via find\_package
If previously built and installed on your system using the provided CMake configuration, libcardano may be included in your own CMake projects via `find_package(Cardano)`.

    find_package(Cardano)
    target_link_libraries(${PROJECT_NAME} PRIVATE cardano::cardano)

### CMake via FetchContent
Libcardano is fully compatible with CMake FetchContent.

    FetchContent_Declare(
      libcardano
      GIT_REPOSITORY https://gitlab.com/viperscience/libcardano.git
      GIT_TAG 3e6748857439797d53e31d0ba613be82e650ae40
    )
    FetchContent_MakeAvailable(libcardano)

    target_link_libraries(${PROJECT_NAME} PRIVATE cardano::cardano)

## Building from Source

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

### Building Examples

The project contains example programs that may be compiled and executed.
To include the examples during the build, set the `BUILD_LIBCARDANO_EXAMPLES` flag.
An example is shown below.

    cmake -B build/ -S . -DBUILD_LIBCARDANO_EXAMPLES=ON
    cmake --build build/ --parallel 4

### CMake FetchContent Dependencies
CMake FetchContent is used to add functionality from the following external dependencies. 

* [Crypto++](https://github.com/ViperScience/cryptopp): Crypto++ is a free C++ class library of cryptographic schemes. The Viper Science fork adds public API methods to support BIP32-Ed25519 style keys used for Cardano wallets.
* [Cryptopp-CMake](https://github.com/abdes/cryptopp-cmake): A modern CMake build project for Crypto++. Used by libcardano to pull in the Viper Science fork of Crypto++.
* [Catch2](https://github.com/catchorg/Catch2): A unit testing framework for C++. Libcardano uses Catch2 for structuring unit tests, it is not included the library.
* [Libcppbor](https://gitlab.com/viperscience/libcppbor): A modern C++ CBOR parser and generator. This library was originally part of the Android source code but was forked by Viper Science team in order to add a CMake build system and further enhancements for integration with libcardano.

### External Dependencies
Libcardano links with the following external dependencies. See the respective project documentation for installation instructions.

* [Botan-3](https://botan.randombit.net/): Crypto and TLS for Modern C++. Botan is used to provide a significant portion of cryptographic tooling in libcardano such as random number generation, hashing of all kinds, encryption/decryption. etc. 
* [libsodium](https://github.com/IntersectMBO/libsodium): A modern, portable, easy to use crypto library. The Cardano fork of libsodium provides implementations of the VRF keys used in the protocol. The basic Ed25519 functions are also used in libcardano.

The provided Docker file demonstrates how to build and install the required dependencies and Cmake find scripts are also provided.
