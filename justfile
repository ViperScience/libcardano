alias bb := debug-build
alias bbr := install

debug-build:
    cmake -S . -B cmake-build-debug/ -D CMAKE_BUILD_TYPE=Debug -D BUILD_LIBCARDANO_EXAMPLES=OFF
    cmake --build cmake-build-debug/ --parallel 1

build:
    cmake -S . -B cmake-build-release/ -D CMAKE_BUILD_TYPE=Release -D BUILD_LIBCARDANO_EXAMPLES=ON
    cmake --build cmake-build-release/ --parallel 16

test: build
    ctest --test-dir cmake-build-release/ --output-on-failure -T Test

install: test
    sudo cmake --install cmake-build-release/
