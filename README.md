<img 
    style="display: block; 
           margin-left: auto;
           margin-right: auto;
           width: 60%;"
    src="docs/img/logo.png" 
    alt="libcardano logo">
</img>

# libcardano

A high-performance library of Cardano blockchain tools written in modern C++.

## Basic Usage

Libcardano is designed to be a simple plugin for C++ applications to include Cardano blockchain functionality. In your C++ code simply add `#include <cardano/cardano.hpp>` and then use library objects and methods under the `cardano` namespace. Finally, link against libcardano during build. If built and installed properly using the provided CMake configuration, libcardano may be included in your own CMake projects via `find_package(Cardano)`.

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

### External Dependencies

Libcardano links with the following external dependencies. 

* [Botan-2](https://botan.randombit.net/)

The provided Docker file demonstrates how to build and install the required dependencies and Cmake find scripts are also provided.

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
