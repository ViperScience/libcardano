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

📖 **[Full API documentation →](https://viperscience.gitlab.io/libcardano/)** — class reference plus worked code examples (deriving an address from a mnemonic, generating stake pool keys and certificates, and more).

libcardano is an **offline** SDK: it focuses on key management, address derivation, and transaction construction, signing, and (de)serialization. It does **not** include node networking or chain synchronization — the signed transactions it produces are handed off for submission by your own node, wallet backend, or service. Ledger data structures span the Byron through Conway eras; the active transaction-building path currently targets the **Babbage** era (the Shelley implementation is retained for older eras).

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

## Quick Start

The fastest way to start developing is with the bundled
[**Dev Container**](https://containers.dev/). It ships every dependency
preinstalled — Botan 3, OpenSSL, a C++20 toolchain (GCC 14 + Clang), CMake, the
[`just`](https://github.com/casey/just) task runner, and the `mold` linker — so
there is nothing to install on your host beyond the container runtime.

1. Clone the repository:

       git clone https://gitlab.com/viperscience/libcardano.git

2. Open the project in your dev-container-compatible editor and reopen it in the
   container when prompted. The image builds on first use.

3. Inside the container, build and test the library with a single command:

       just test

That's it. `just test` configures a Release build, compiles the library and
examples, and runs the full test suite. Run `just` on its own to list every
available recipe. See [Building with `just`](#building-with-just) for the
complete recipe reference.

## Basic Usage

Libcardano is designed to be a simple plugin for modern C++ applications that require Cardano blockchain functionality.
In your C++ code simply add `#include <cardano/cardano.hpp>` and then use library objects and methods within the `cardano` namespace.
Finally, link against libcardano during build using one of the methods outlined below.
For API reference and end-to-end code examples, see the [full API documentation](https://viperscience.gitlab.io/libcardano/).

### CMake via Git submodule
Add libcardano as a submodule to an existing cmake project and then add the libcardano directory, e.g., `add_subdirectory(./libcardano)`, which provides the target `cardano::cardano` for linking.

    add_subdirectory(./libcardano)
    target_link_libraries(${PROJECT_NAME} PRIVATE cardano::cardano)

### CMake via find\_package
If previously built and installed on your system using the provided CMake configuration, libcardano may be included in your own CMake projects via `find_package(cardano)`.

    find_package(cardano)
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

Obtain the source code and change to the project directory.

    git clone https://gitlab.com/viperscience/libcardano.git
    cd libcardano

Building requires a **C++20 toolchain** (GCC 14+ or a recent Clang) and
**CMake 3.25+**. Linux is the primary supported and CI-tested platform; the
build is also configured for MSVC, but other platforms are not regularly
exercised.

Only **Botan 3** and **OpenSSL** development libraries need to be present on
the system; every other dependency is fetched automatically by CMake at
configure time. The [Quick Start](#quick-start) Dev Container provides these
prerequisites for you — if you build outside the container, install them first
using your platform's package manager (or see the
[`.devcontainer/Dockerfile`](.devcontainer/Dockerfile) for reference).

### Building with `just`

A [`justfile`](justfile) wraps the configure/build/test/install workflow so the
library can be built repeatably in a single step. This is the recommended path:

    just build      # Release build (library + examples)
    just test       # build, then run the full test suite
    just install    # test, then install system-wide (uses sudo)

Run `just` (or `just --list`) to see every recipe.

### Building with CMake directly

If you would rather not use `just`, invoke CMake yourself. The example programs
are built only when `BUILD_LIBCARDANO_EXAMPLES=ON`:

    cmake -S . -B build -DCMAKE_BUILD_TYPE=Release -DBUILD_LIBCARDANO_EXAMPLES=ON
    cmake --build build --parallel 8
    ctest --test-dir build --output-on-failure
    cmake --install build

### Building with Docker

A Docker build is also provided, which compiles, tests, and installs the library
in a self-contained image:

    docker build -t libcardano:latest .

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

## License

libcardano is released under the **MIT License** — see [`LICENSE`](LICENSE) for
the full text. Bundled and fetched dependencies remain under their own
respective licenses.
