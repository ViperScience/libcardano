# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project

libcardano is a C++20 SDK for the Cardano blockchain. The public API lives under `include/cardano/` in the `cardano::` namespace; users include `<cardano/cardano.hpp>` and link against the `cardano::cardano` CMake target.

## Build & Test

The standard, preferred toolchain is **cpx + CMake + vcpkg**. [cpx](https://github.com/ozacod/cpx) is a Cargo-like CLI wrapper over CMake and vcpkg; it owns the build directory and auto-injects the vcpkg toolchain file. Dependencies come from vcpkg (see `vcpkg.json`): **Botan** (pinned to **3.7.1** via the `overrides` block), OpenSSL, nlohmann-json, libcppbor, and libsodium — the last two from the ViperScience custom registry declared in `vcpkg-configuration.json`. Tests pull `boost-multiprecision` and `catch2` via the `tests` vcpkg feature.

```bash
# Preferred: cpx (CMake + vcpkg toolchain, cpx-managed build dir)
cpx build -j8 --verbose                 # Debug
cpx build -j8 --verbose --release -O3   # Release
cpx test --verbose                      # Debug build + full test suite
cpx test --toolchain release --verbose  # Release (-O3) build + tests
cpx clean
```

cpx toolchains are defined in `cpx-ci.yaml`: `release` and `release-clang` set the vcpkg toolchain file explicitly (cpx's `--toolchain` path does not auto-inject it), while `release-fetchcontent` omits it to exercise the no-vcpkg path.

`vcpkg` is the desired dependency source, but the CMake tree also has a **FetchContent fallback**: each hybrid dependency is probed with `find_package()` first and only fetched if that probe fails, so the same tree configures with or without a vcpkg toolchain. Set `-DCARDANO_PREFER_FETCHCONTENT=ON` to force the legacy all-FetchContent path (no vcpkg). Botan and OpenSSL have no FetchContent fallback — they must come from vcpkg or the system.

A `justfile` wraps the common workflows (run `just <recipe>`):

- `just bb` (`cpx-test`) — Debug build + test via cpx.
- `just bbr` (`cpx-test-release`) — Release (-O3) build + test via cpx.
- `cpx-test-release-clang`, `cpx-test-fetchcontent` — same via the clang / no-vcpkg toolchains.
- The pure-CMake recipes (`just build`, `just debug-build`, `just test`, `just install`) bypass cpx/vcpkg entirely and build into `cmake-build-release/` / `cmake-build-debug/` using the FetchContent path — useful when cpx/vcpkg aren't available.

Run a single test binary directly from the build dir, e.g. `./<build>/test/test_cardano_address` or `./<build>/test/test_cardano_kes_api "[some Catch2 tag]"`.

Test data files are copied from `test/data/` into `<build>/test/data/` at configure time — if you add a new data file, re-run CMake configure or it won't be present at test runtime.

Docker build (used by CI): `docker build -t libcardano:latest .` — builds on top of `registry.gitlab.com/viperscience/libcardano:base` which has the system deps pre-installed.

## Architecture

### Era-partitioned ledger code
Cardano evolved through multiple eras (Byron → Shelley → Allegra → Mary → Alonzo → Babbage → Conway). Code that differs per era lives in era-named subdirectories under `src/`:

- `src/byron/`, `src/shelley/`, `src/alonzo/`, `src/babbage/`, `src/conway/` — era-specific genesis/ledger/transaction implementations
- The `Era` enum in `include/cardano/transaction.hpp` is the canonical list

Top-level files in `src/` (e.g. `ledger.cpp`, `address.cpp`) contain era-agnostic logic. The current "live" transaction-building path is `src/babbage/transaction.cpp` — the Shelley implementation is kept for older era support.

### Header layout
All public headers live in `include/cardano/`. `cardano.hpp` is the umbrella include. The structures in `ledger.hpp` are a deliberate C++ representation of the Cardano CDDL spec — when modifying them, cross-reference the linked CDDL in the header (Babbage CDDL link is in the file). Type aliases like `Bytes28`, `Bytes32`, `Vkey`, `Address` are defined there and used throughout.

### Cryptographic backends
The library mixes two crypto stacks, each for a specific reason — they are not interchangeable:

- **cardano-libsodium** (Cardano fork): VRF keys (Cardano-specific construction not in upstream libsodium), the Ed25519 primitives used by Cardano consensus, and the BIP32-Ed25519 HD-wallet derivation in `src/bip32_ed25519.cpp` (built on libsodium's low-level `crypto_core_ed25519_*` / `crypto_scalarmult_ed25519_*` scalar and point operations).
- **Botan 3** (vcpkg port `botan`, pinned to 3.7.1; or a system install): general crypto — hashing, RNG, encryption/decryption.

When adding crypto code, pick the backend that already owns that primitive in this codebase rather than introducing a new one.

### Threshold signatures (TSS)
The `cardano::tss` namespace (`include/cardano/tss.hpp`, `src/tss.cpp`) implements a threshold signature scheme over BIP32-Ed25519 keys, following [draft-hallambaker-threshold-sigs](https://datatracker.ietf.org/doc/html/draft-hallambaker-threshold-sigs-06). The aggregate signature it produces is a standard Ed25519 signature that verifies against the composite public key.

- Two key-sharing algorithms, auto-selected by `Dealer` from `(n, t)`: **Direct** (simple additive split, used when threshold `t == n`) and **Shamir Secret Sharing** (general `t < n`, requires Lagrange interpolation to recombine). `KeySharingAlgorithm::Direct` is rejected when `t != n`.
- Roles: `Dealer` (immutable; key splitting via `generate`/`splitSeed`/`splitRootKey`, composite-key construction, `computeLagrangeCoefficients`, commitment/signature aggregation, verification), the stateless static helpers in `Signer`, and `StatefulSigner` which holds per-signer state across the multi-round signing protocol (nonce → commitment → aggregate commitment → signature share). A `KeyShare` bundles a `{id, PrivateKey}` — the `id` is the Shamir x-coordinate and is unused for Direct splits.

The protocol math relies on Ed25519 scalar (mod the group order ℓ) and curve-point arithmetic that libsodium doesn't expose ergonomically. That lives in a dedicated shim, `cardano::tss::ed25519` (`include/cardano/curve25519.hpp`, `src/curve25519.cpp`): the `Scalar` and `Point` value types wrap libsodium's low-level `crypto_core_ed25519_*` / `crypto_scalarmult_ed25519_*` primitives with operators (`+ - * /`, `mulBasepoint`, reduce, random). When `tss.cpp` needs scalar/point operations, use these types rather than calling libsodium directly.

### CBOR serialization
Cardano ledger structures are CBOR-encoded. Serialization uses the ViperScience fork of **libcppbor** (also pulled by FetchContent). Look at existing era files (e.g. `src/babbage/transaction.cpp`) for the encoding patterns before writing new ones.

### CMake integration surface
Consumers can pull libcardano in three ways: `add_subdirectory`, installed `find_package(Cardano)`, or `FetchContent`. When changing the public CMake interface or installed headers list, update `CMakeLists.txt` in three places: `CARDANO_SOURCES`, `CARDANO_HEADERS` (install list), and (if relevant) `cmake/Config.cmake.in`. The `cmake/cmake_integration_test/` project is exercised by CI to catch regressions in the installed package.

## Conventions

- C++20, warnings-as-errors-ish: `-Wall -Wextra -Wpedantic -Wshadow -Wconversion` plus `-ftrivial-auto-var-init=pattern` on GCC/Clang; `/W4 /WX /RTC1` on MSVC. Don't introduce warnings.
- `.clang-format` is checked in — run it on new code.
- The codebase uses `[[nodiscard]]` and `noexcept` deliberately on value-returning and move-only APIs (see address.hpp). Match the existing style when adding similar methods.
