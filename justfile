# Default aliases (cpx / CMake + vcpkg):
#   bb  = Debug build + test
#   bbr = Release (-O3) build + test
# Note: these commands are intended to be run in and environment like the dev
# container which has all the necessary prerequisits.
alias bb := cpx-test
alias bbr := cpx-test-release

# List the available recipes (runs when `just` is invoked with no arguments)
default:
    @just --list

# ---------------------------------------------------------------------------
# cpx builds (CMake + vcpkg) — default
# ---------------------------------------------------------------------------

# Debug build via cpx (CMake + vcpkg toolchain; cpx-managed build dir)
cpx-debug:
    echo `pwd`
    cpx build -j8 --verbose

# Release build via cpx (CMake + vcpkg toolchain; cpx-managed build dir)
cpx-build:
    echo `pwd`
    cpx build -j8 --verbose --release -O3

# Build, then run the full test suite via cpx (Debug)
cpx-test:
    cpx test --verbose

# Build + run the test suite in Release (-O3) via the `release` toolchain (vcpkg)
cpx-test-release:
    cpx test --toolchain release --verbose

# Build + run the test suite in Release (-O3) without vcpkg (FetchContent path)
cpx-test-fetchcontent:
    cpx test --toolchain release-fetchcontent --verbose

# Remove the cpx build directory
cpx-clean:
    cpx clean

# ---------------------------------------------------------------------------
# Pure CMake builds (no vcpkg; dependencies resolved via FetchContent)
# ---------------------------------------------------------------------------

# Configure + build a Debug build (examples off, single-threaded) into cmake-build-debug/
debug-build:
    cmake -S . -B cmake-build-debug/ -D CMAKE_BUILD_TYPE=Debug -D BUILD_LIBCARDANO_EXAMPLES=OFF
    cmake --build cmake-build-debug/ --parallel 1

# Configure + build a Release build (examples on, 16-way parallel) into cmake-build-release/
build:
    cmake -S . -B cmake-build-release/ -D CMAKE_BUILD_TYPE=Release -D BUILD_LIBCARDANO_EXAMPLES=ON
    cmake --build cmake-build-release/ --parallel 16

# Build (Release) then run the full test suite
test: build
    ctest --test-dir cmake-build-release/ --output-on-failure -T Test

# Run the tests then install the library system-wide (requires sudo)
install: test
    sudo cmake --install cmake-build-release/

# Remove the generated build directories
clean:
    rm -rf cmake-build-debug/ cmake-build-release/
