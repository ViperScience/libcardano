cmake_minimum_required(VERSION 3.14)

# set the project name, language,  and version
project(Cardano 
    DESCRIPTION "A modern C++ development kit for the Cardano blockchain."
    VERSION 1.0.0
    LANGUAGES C CXX
)

# specify the C++ standard
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED True)

# Default to Release build type if not specified
if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE "Release")
endif()

# Specifiy compiler flags
if (MSVC)
    add_compile_options(/W4 /WX)
else()
    add_compile_options(
        -Wall
    )
endif()

########################################################################
# Additional packages
########################################################################

# Include a thread library for linking that is specific to the platform.
find_package(Threads REQUIRED)

# Include OpenSSL for the Botan library
find_package(OpenSSL REQUIRED)

# Add the local cmake directory to the path for custom search files
list(INSERT CMAKE_MODULE_PATH 0 ${CMAKE_CURRENT_SOURCE_DIR}/cmake)

# Load static libraries since we are building a static library
if(WIN32)
    list(INSERT CMAKE_FIND_LIBRARY_SUFFIXES 0 .lib .a)
else()
    set(CMAKE_FIND_LIBRARY_SUFFIXES .a)
endif()

# Add 3rd party libraries that should be installed on the system
set(sodium_USE_STATIC_LIBS ON)
find_package(Sodium REQUIRED)
find_package(Botan REQUIRED)

# Add the submodules
add_subdirectory(${CMAKE_SOURCE_DIR}/libs)

################################################################################
# Include directories
################################################################################

# Make cache variables for install destinations
include(GNUInstallDirs)

include_directories(${PROJECT_NAME}
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}
        ${CMAKE_CURRENT_SOURCE_DIR}/src
        ${VIPER25519_INCLUDE}
        ${LIBCPPBOR_INCLUDE}
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>
)
# Note: We need to tell CMake that we want to use different include directories
#       depending on if we're building the library or using it from an installed
#       location.

################################################################################
# Tests
################################################################################

# Enable testing only if this is the top level project.
if(CMAKE_PROJECT_NAME STREQUAL PROJECT_NAME)
    include(CTest)
endif()
if(CMAKE_PROJECT_NAME STREQUAL PROJECT_NAME AND BUILD_TESTING)
    add_subdirectory(libs/Catch2)
    
    # Individual tests may be found in the `tests`subdirectory of the
    # repository.
    add_subdirectory(test)
endif()

# include(CTest)
# add_subdirectory(lib/Catch2)
# enable_testing()
# add_subdirectory(test)

################################################################################
# Target Build and Link
################################################################################

# Specify the libcardano source files (including submodules)
set(CARDANO_SOURCES
    ${CMAKE_SOURCE_DIR}/src/address.cpp
    ${CMAKE_SOURCE_DIR}/src/crypto.cpp
    ${CMAKE_SOURCE_DIR}/src/encodings.cpp
    ${CMAKE_SOURCE_DIR}/src/ledger.cpp
    ${CMAKE_SOURCE_DIR}/src/mnemonic.cpp
    ${CMAKE_SOURCE_DIR}/src/stake_pool.cpp
    ${VIPER25519_SOURCES}
    ${LIBCPPBOR_SOURCES}
)

# Add the library to build but do not specify STATIC vs. SHARED. A shared 
# library will be built if CMake is run with: -DBUILD_SHARED_LIBS=ON
add_library(${PROJECT_NAME} ${CARDANO_SOURCES})

# Specify libraries for linking
target_link_libraries(${PROJECT_NAME} PRIVATE
    botan::botan
    sodium::sodium
    Threads::Threads
    OpenSSL::SSL
)

################################################################################
# Install the Target
################################################################################
set(PROJECT_NAME_TARGETS ${PROJECT_NAME}Targets)

# Install the library file.
install(TARGETS ${PROJECT_NAME}
        EXPORT ${PROJECT_NAME_TARGETS}
        LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
        ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
        RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
        INCLUDES DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/cardano
)

# Install the header files. Use lowercase for the directory name.
set(CARDANO_HEADERS
    ${CMAKE_SOURCE_DIR}/include/cardano/cardano.hpp
    ${CMAKE_SOURCE_DIR}/include/cardano/address.hpp
    ${CMAKE_SOURCE_DIR}/include/cardano/bip39_dictionary.hpp
    ${CMAKE_SOURCE_DIR}/include/cardano/crypto.hpp
    ${CMAKE_SOURCE_DIR}/include/cardano/encodings.hpp
    ${CMAKE_SOURCE_DIR}/include/cardano/mnemonic.hpp
)
install(FILES ${CARDANO_HEADERS} 
        DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/cardano
)

# We also need to install the Viper25519 headers since they are used in the 
# cardano/crypto.hpp header.
set(VIPER25519_HEADERS
    ${CMAKE_SOURCE_DIR}/libs/viper25519/include/viper25519/ed25519.hpp
    ${CMAKE_SOURCE_DIR}/libs/viper25519/include/viper25519/curve25519.hpp
    ${CMAKE_SOURCE_DIR}/libs/viper25519/include/viper25519/secmem.hpp
)
install(FILES ${VIPER25519_HEADERS} 
        DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/viper25519
)

################################################################################
# Install the CMake Target files
################################################################################

# Install the CMake files required in order to use `find_package(Cardano)`
install(EXPORT ${PROJECT_NAME_TARGETS}
        FILE ${PROJECT_NAME_TARGETS}.cmake
        NAMESPACE ${PROJECT_NAME}::
        DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/${PROJECT_NAME}
)

include(CMakePackageConfigHelpers)

configure_package_config_file(${CMAKE_CURRENT_SOURCE_DIR}/cmake/Config.cmake.in
    "${CMAKE_CURRENT_BINARY_DIR}/CardanoConfig.cmake"
    INSTALL_DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/${PROJECT_NAME}
)
write_basic_package_version_file(
    "${CMAKE_CURRENT_BINARY_DIR}/CardanoConfigVersion.cmake"
    VERSION ${PROJECT_VERSION}
    COMPATIBILITY SameMajorVersion
)

install(FILES
    "${CMAKE_CURRENT_BINARY_DIR}/CardanoConfig.cmake"
    "${CMAKE_CURRENT_BINARY_DIR}/CardanoConfigVersion.cmake"
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/${PROJECT_NAME}
)