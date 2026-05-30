alias bb := debug-build
alias bbr := install

# List the available recipes (runs when `just` is invoked with no arguments)
default:
    @just --list

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
