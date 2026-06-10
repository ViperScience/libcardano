# Copyright (c) 2024 Viper Science LLC
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
# THE SOFTWARE.

cmake_minimum_required(VERSION 3.25)

# set the project name, language,  and version
project(cardano
    DESCRIPTION "A modern C++ development kit for the Cardano blockchain."
    VERSION 0.2.0
    LANGUAGES C CXX
)

# Default to Release build type if not specified
if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE "Release")
endif()

# Determine if this is the top-level project
set(CARDANO_IS_TOP_LEVEL ${CMAKE_PROJECT_NAME} STREQUAL ${PROJECT_NAME})

# Only do these if this is the main project, and not if it is included through
# add_subdirectory.
if(CARDANO_IS_TOP_LEVEL)
    # Let's ensure -std=c++xx instead of -std=g++xx
    set(CMAKE_CXX_EXTENSIONS OFF)

    # Let's nicely support folders in IDEs
    set_property(GLOBAL PROPERTY USE_FOLDERS ON)

    # For use with code analyzers
    set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
endif()

########################################################################
# Additional packages / dependency resolution
########################################################################
#
# libcardano resolves its dependencies through two strategies that can be
# freely mixed within a single build:
#
#   * find_package() — for dependencies available via vcpkg or as system
#     packages: Botan, OpenSSL and nlohmann-json from the public registry
#     (and Catch2 for the tests), plus the ViperScience forks libsodium and
#     libcppbor from the custom registry declared in vcpkg-configuration.json.
#     When configured with the vcpkg toolchain these are supplied by vcpkg; the
#     dependencies listed in vcpkg.json drive that.
#
#   * FetchContent — fallback for every probed dependency. Each hybrid
#     dependency is probed with find_package() first and only fetched if that
#     probe fails, so the same tree builds with or without a vcpkg toolchain.
#
# Set CARDANO_PREFER_FETCHCONTENT=ON to force the legacy all-FetchContent
# behaviour (handy when building without a vcpkg toolchain or to pin exact
# dependency revisions regardless of what is installed on the system).
########################################################################
include(FetchContent)

# Add the local cmake directory to the path for custom search files
list(INSERT CMAKE_MODULE_PATH 0 ${CMAKE_CURRENT_SOURCE_DIR}/cmake)

option(CARDANO_PREFER_FETCHCONTENT
    "Always use FetchContent for dependencies, even those available via vcpkg/system" OFF)

# Load static libraries since we are building a static library.
# Note: under a vcpkg toolchain the library kind is governed by the selected
# triplet, so only constrain the suffixes when not building with vcpkg.
if(NOT DEFINED VCPKG_TARGET_TRIPLET)
    if(WIN32)
        list(INSERT CMAKE_FIND_LIBRARY_SUFFIXES 0 .lib .a)
    else()
        set(CMAKE_FIND_LIBRARY_SUFFIXES .a)
    endif()
endif()

# Include a thread library for linking that is specific to the platform.
find_package(Threads REQUIRED)

# Include OpenSSL for the Botan library (vcpkg port: openssl).
find_package(OpenSSL REQUIRED)

# Include the Botan library for cryptographic functions. Botan 3.3+ installs
# botan-config.cmake, so find_package works for both a system install and the
# vcpkg `botan` port (both expose the Botan::Botan target). There is no
# practical FetchContent fallback for Botan.
find_package(Botan 3.4.0 REQUIRED)
# vcpkg's static triplets export only the Botan::Botan-static target, whereas a
# typical system/shared install provides Botan::Botan. Normalise to Botan::Botan
# so the library, tests, and examples link a single target name in either case.
if(NOT TARGET Botan::Botan AND TARGET Botan::Botan-static)
    add_library(Botan::Botan ALIAS Botan::Botan-static)
endif()

# --- nlohmann/json: vcpkg/system first, FetchContent fallback ---------------
if(NOT CARDANO_PREFER_FETCHCONTENT)
    find_package(nlohmann_json 3.11 CONFIG QUIET)
endif()
if(nlohmann_json_FOUND)
    message(STATUS "libcardano: nlohmann_json found via find_package (${nlohmann_json_DIR})")
else()
    message(STATUS "libcardano: nlohmann_json provided by FetchContent")
    FetchContent_Declare(
        json
        URL https://github.com/nlohmann/json/releases/download/v3.11.3/json.tar.xz
    )
    if(CARDANO_IS_TOP_LEVEL)
        set(JSON_Install ON)
    endif()
    FetchContent_MakeAvailable(json)
endif()

# --- libsodium (Cardano fork): vcpkg registry first, FetchContent fallback --
# The ViperScience libsodium fork carries the Cardano VRF construction. The
# vcpkg port exports it as `unofficial-sodium` (target unofficial-sodium::sodium),
# while the FetchContent fork exports `cardano_sodium` (target
# cardano_sodium::cardano_sodium). Normalise to CARDANO_SODIUM_TARGET so the rest
# of the build links a single name regardless of how it was resolved.
if(NOT CARDANO_PREFER_FETCHCONTENT)
    find_package(unofficial-sodium CONFIG QUIET)
endif()
if(unofficial-sodium_FOUND)
    message(STATUS "libcardano: libsodium found via find_package (unofficial-sodium)")
    set(CARDANO_SODIUM_TARGET unofficial-sodium::sodium)
    set(CARDANO_SODIUM_DEPENDENCY "unofficial-sodium CONFIG")
else()
    message(STATUS "libcardano: libsodium provided by FetchContent (ViperScience cardano fork)")
    FetchContent_Declare(
        cardano_sodium
        GIT_REPOSITORY https://gitlab.com/viperscience/cardano-libsodium-cmake.git
        GIT_TAG        295d5ba29e62c2fd2899085a9583f6629e1795e0
    )
    set(SODIUM_DISABLE_TESTS ON)
    FetchContent_MakeAvailable(cardano_sodium)
    set(CARDANO_SODIUM_TARGET cardano_sodium::cardano_sodium)
    set(CARDANO_SODIUM_DEPENDENCY "cardano_sodium")
endif()

# --- libcppbor fork: not in vcpkg, FetchContent (probe first) ---------------
if(NOT CARDANO_PREFER_FETCHCONTENT)
    find_package(cppbor QUIET)
endif()
if(cppbor_FOUND)
    message(STATUS "libcardano: cppbor found via find_package (${cppbor_DIR})")
else()
    message(STATUS "libcardano: cppbor provided by FetchContent (ViperScience fork)")
    FetchContent_Declare(
        libcppbor
        GIT_REPOSITORY https://gitlab.com/viperscience/libcppbor.git
        GIT_TAG        bddc539f6fa6b38205029d58d6a707a7efbf5740
    )
    FetchContent_MakeAvailable(libcppbor)
endif()

################################################################################
# Define the Library Target
################################################################################

# Specify the libcardano source files
set(CARDANO_SOURCES
    ${CMAKE_CURRENT_SOURCE_DIR}/src/address.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/src/alonzo/genesis.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/src/bip32_ed25519.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/src/byron/genesis.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/src/babbage/ledger.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/src/babbage/transaction.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/src/conway/genesis.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/src/curve25519.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/src/ed25519.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/src/encodings.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/src/kes.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/src/ledger.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/src/mnemonic.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/src/shelley/genesis.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/src/shelley/ledger.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/src/shelley/transaction.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/src/stake_pool.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/src/tss.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/src/util.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/src/vrf.cpp
)

# Add the library to build but do not specify STATIC vs. SHARED. A shared
# library will be built if CMake is run with: -DBUILD_SHARED_LIBS=ON
add_library(${PROJECT_NAME} ${CARDANO_SOURCES})
add_library(cardano::cardano ALIAS ${PROJECT_NAME})

################################################################################
# Include directories
################################################################################

# Make cache variables for install destinations
include(GNUInstallDirs)

target_include_directories(${PROJECT_NAME}
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>
)
# Note: We need to tell CMake that we want to use different include directories
#       depending on if we're building the library or using it from an installed
#       location.

################################################################################
# Additional Target Properties
################################################################################

set_target_properties(${PROJECT_NAME} PROPERTIES
    # COMPILE_WARNING_AS_ERROR ON
    CXX_STANDARD 20
    CXX_STANDARD_REQUIRED ON
)

if(MSVC)
    target_compile_options(${PROJECT_NAME} PRIVATE /W4 /WX /RTC1)
elseif(CMAKE_CXX_COMPILER_ID MATCHES ".*Clang|GNU")
    target_compile_options(${PROJECT_NAME} PRIVATE
        -Wall -Wextra -Wpedantic  -Wshadow -Wconversion -ftrivial-auto-var-init=pattern
        "$<$<CONFIG:DEBUG>:-g;-O0;--coverage>"
    )
    target_link_libraries(${PROJECT_NAME} PRIVATE
        "$<$<CONFIG:DEBUG>:--coverage>"
    )
endif()

################################################################################
# Link
################################################################################

# Specify libraries for linking
target_link_libraries(${PROJECT_NAME}
    PRIVATE
        ${CARDANO_SODIUM_TARGET}
        Threads::Threads
        OpenSSL::SSL
    PUBLIC
        Botan::Botan
        cppbor::cppbor
        nlohmann_json::nlohmann_json
)

################################################################################
# Tests
################################################################################

# Enable testing only if this is the top level project or if explicitly set.
option(ENABLE_CARDANO_TESTS "Enable cardano project tests" OFF)
if(CARDANO_IS_TOP_LEVEL OR ENABLE_CARDANO_TESTS)
    include(CTest)
    if(BUILD_TESTING)
        # Individual tests may be found in the `tests`subdirectory of the
        # repository.
        add_subdirectory(test)

        # Copy data files for integration tests
        file(COPY test/data DESTINATION ${CMAKE_CURRENT_BINARY_DIR}/test)
    endif()
endif()

################################################################################
# Examples
################################################################################

option(BUILD_LIBCARDANO_EXAMPLES "Build the project examples" OFF)

if(BUILD_LIBCARDANO_EXAMPLES)
    add_subdirectory(examples)
endif()

################################################################################
# Install the Target (if top-level project)
################################################################################

option(ENABLE_CARDANO_INSTALL "Install the cardano library and headers" OFF)
if(CARDANO_IS_TOP_LEVEL OR ENABLE_CARDANO_INSTALL)

    set(PROJECT_NAME_TARGETS ${PROJECT_NAME}Targets)

    # Install the library file.
    install(TARGETS ${PROJECT_NAME}
            EXPORT ${PROJECT_NAME_TARGETS}
            LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
            ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
            RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
            INCLUDES DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/${PROJECT_NAME}
    )

    # Install the header files. Use lowercase for the directory name.
    set(CARDANO_HEADERS
        ${CMAKE_CURRENT_SOURCE_DIR}/include/cardano/cardano.hpp
        ${CMAKE_CURRENT_SOURCE_DIR}/include/cardano/address.hpp
        ${CMAKE_CURRENT_SOURCE_DIR}/include/cardano/bip32_ed25519.hpp
        ${CMAKE_CURRENT_SOURCE_DIR}/include/cardano/bip39_dictionary.hpp
        ${CMAKE_CURRENT_SOURCE_DIR}/include/cardano/ed25519.hpp
        ${CMAKE_CURRENT_SOURCE_DIR}/include/cardano/encodings.hpp
        ${CMAKE_CURRENT_SOURCE_DIR}/include/cardano/genesis.hpp
        ${CMAKE_CURRENT_SOURCE_DIR}/include/cardano/kes.hpp
        ${CMAKE_CURRENT_SOURCE_DIR}/include/cardano/ledger.hpp
        ${CMAKE_CURRENT_SOURCE_DIR}/include/cardano/mnemonic.hpp
        ${CMAKE_CURRENT_SOURCE_DIR}/include/cardano/secmem.hpp
        ${CMAKE_CURRENT_SOURCE_DIR}/include/cardano/serialization.hpp
        ${CMAKE_CURRENT_SOURCE_DIR}/include/cardano/stake_pool.hpp
        ${CMAKE_CURRENT_SOURCE_DIR}/include/cardano/transaction.hpp
        ${CMAKE_CURRENT_SOURCE_DIR}/include/cardano/util.hpp
        ${CMAKE_CURRENT_SOURCE_DIR}/include/cardano/vrf.hpp
    )
    install(FILES ${CARDANO_HEADERS}
            DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/${PROJECT_NAME}
    )

    # Install the CMake files required in order to use `find_package(cardano)`
    install(EXPORT ${PROJECT_NAME_TARGETS}
            FILE ${PROJECT_NAME_TARGETS}.cmake
            NAMESPACE ${PROJECT_NAME}::
            DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/${PROJECT_NAME}
    )

    include(CMakePackageConfigHelpers)

    configure_package_config_file(${CMAKE_CURRENT_SOURCE_DIR}/cmake/Config.cmake.in
        "${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME}Config.cmake"
        INSTALL_DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/${PROJECT_NAME}
    )
    write_basic_package_version_file(
        "${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME}ConfigVersion.cmake"
        VERSION ${PROJECT_VERSION}
        COMPATIBILITY SameMajorVersion
    )

    install(FILES
        "${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME}Config.cmake"
        "${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME}ConfigVersion.cmake"
        DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/${PROJECT_NAME}
    )

endif()
