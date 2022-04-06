cmake_minimum_required(VERSION 3.14)

# set the project name, language,  and version
project(cardano 
    DESCRIPTION "A blazingly fast library of Cardano blockchain tools written in modern C++."
    VERSION 1.0
    LANGUAGES C CXX
)

# specify the C++ standard
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED True)

########################################################################
# Additional packages
########################################################################

# Add the local cmake directory to the path for custom search files
list(INSERT CMAKE_MODULE_PATH 0 ${CMAKE_CURRENT_SOURCE_DIR}/cmake)

# Add 3rd party libraries that should be installed on the system
find_package(Botan REQUIRED)

find_package(libcbor REQUIRED)

# Add the submodules
add_subdirectory(${CMAKE_SOURCE_DIR}/libs)

########################################################################
# Include directories
########################################################################

include_directories(${PROJECT_NAME}
    PRIVATE
        ${CMAKE_SOURCE_DIR}
        ${CMAKE_SOURCE_DIR}/src
        ${CARDANO_CRYPTO_CBITS_INCLUDE}
        ${CRYPTONITE_CBITS_INCLUDE}
    PUBLIC
        ${CMAKE_SOURCE_DIR}/include
)

########################################################################
# Tests
########################################################################

# Enable testing globally. Individual tests may be found in the `tests`
# subdirectory of the repository.
ENABLE_TESTING()

ADD_SUBDIRECTORY( test build )

########################################################################
# Target Build
########################################################################

# specify the source files
set(SOURCES
    ${CMAKE_SOURCE_DIR}/src/encodings.cpp
    ${CMAKE_SOURCE_DIR}/src/crypto.cpp
    ${CMAKE_SOURCE_DIR}/src/address.cpp
    ${CMAKE_SOURCE_DIR}/src/utils.cpp
    ${CMAKE_SOURCE_DIR}/src/cardano_crypto_interface.c
    ${CARDANO_CRYPTO_CBITS_SOURCES}
    ${CRYPTONITE_CBITS_SOURCES}
)

# add the library to build
add_library(cardano ${SOURCES})

########################################################################
# Target Link
########################################################################

# specify libraries for linking
target_link_libraries(${PROJECT_NAME} PUBLIC
    cbor::cbor
    botan::botan
)

########################################################################
# Install Target
########################################################################

install(TARGETS ${PROJECT_NAME} DESTINATION lib)
set(HEADERS
    ${CMAKE_SOURCE_DIR}/include/cardano/cardano.hpp
    ${CMAKE_SOURCE_DIR}/include/cardano/encodings.hpp
    ${CMAKE_SOURCE_DIR}/include/cardano/crypto.hpp
    ${CMAKE_SOURCE_DIR}/include/cardano/address.hpp
)
install(FILES ${HEADERS} DESTINATION "include/cardano")
