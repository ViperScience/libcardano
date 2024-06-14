# MIT License
#
# Copyright (c) 2022 Viper Staking
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED True)

set(LIBCARDANO_LINK_LIBS
    Botan::Botan
    cryptopp::cryptopp
    sodium::sodium
    Threads::Threads
    OpenSSL::SSL
    cppbor::cppbor
)

set(TEST_LIBCARDANO_LIBS
    Catch2::Catch2WithMain
    OpenSSL::SSL
    Threads::Threads
    Botan::Botan
    cryptopp::cryptopp
    cppbor::cppbor
    sodium::sodium
)

include_directories(
    ${CMAKE_CURRENT_SOURCE_DIR}/../src
    ${CMAKE_CURRENT_SOURCE_DIR}/../include
    ${VIPER25519_INCLUDE}
)

################################################################################
# Test the encoding capabilites
################################################################################
set(TEST_CARDANO_ENCODINGS_SOURCES
    test_cardano_encodings.cpp
    ${CMAKE_SOURCE_DIR}/src/encodings.cpp
    ${CMAKE_SOURCE_DIR}/src/utils.cpp
    ${LIBCPPBOR_SOURCES}
)
ADD_EXECUTABLE(test_cardano_encodings ${TEST_CARDANO_ENCODINGS_SOURCES})
target_link_libraries(test_cardano_encodings PRIVATE
    OpenSSL::SSL
)
ADD_TEST(cardano_encodings test_cardano_encodings)

################################################################################
# Test the key implementations
################################################################################
set(TEST_CARDANO_CRYPTO_SOURCES
    test_cardano_crypto.cpp
    ${CMAKE_SOURCE_DIR}/src/mnemonic.cpp
    ${CMAKE_SOURCE_DIR}/src/crypto.cpp
    ${CMAKE_SOURCE_DIR}/src/address.cpp
    ${CMAKE_SOURCE_DIR}/src/encodings.cpp
    ${VIPER25519_SOURCES}
    ${LIBCPPBOR_SOURCES}
)
ADD_EXECUTABLE(test_cardano_crypto ${TEST_CARDANO_CRYPTO_SOURCES})
target_link_libraries(test_cardano_crypto PRIVATE ${LIBCARDANO_LINK_LIBS})
ADD_TEST(cardano_crypto test_cardano_crypto)

################################################################################
# Test the address implementations
################################################################################
set(TEST_CARDANO_ADDRESS_SOURCES
    test_cardano_address.cpp
    ${CMAKE_SOURCE_DIR}/src/address.cpp
    ${CMAKE_SOURCE_DIR}/src/crypto.cpp
    ${CMAKE_SOURCE_DIR}/src/encodings.cpp
    ${CMAKE_SOURCE_DIR}/src/mnemonic.cpp
    ${VIPER25519_SOURCES}
    ${LIBCPPBOR_SOURCES}
)
ADD_EXECUTABLE(test_cardano_address ${TEST_CARDANO_ADDRESS_SOURCES})
target_link_libraries(test_cardano_address PRIVATE ${LIBCARDANO_LINK_LIBS})
ADD_TEST(cardano_address test_cardano_address)

################################################################################
# Test the Byron era address implementations
################################################################################
set(TEST_CARDANO_BYRON_ADDRESS_SOURCES
    test_cardano_byron_address.cpp
    ${CMAKE_SOURCE_DIR}/src/mnemonic.cpp
    ${CMAKE_SOURCE_DIR}/src/crypto.cpp
    ${CMAKE_SOURCE_DIR}/src/address.cpp
    ${CMAKE_SOURCE_DIR}/src/encodings.cpp
    ${VIPER25519_SOURCES}
    ${LIBCPPBOR_SOURCES}
)
ADD_EXECUTABLE(test_cardano_byron_address ${TEST_CARDANO_BYRON_ADDRESS_SOURCES})
target_link_libraries(test_cardano_byron_address PRIVATE
    ${LIBCARDANO_LINK_LIBS}
)
ADD_TEST(cardano_byron_address test_cardano_byron_address)

################################################################################
# Test the Mnemonic generation and root key derivation
################################################################################
set(TEST_CARDANO_MNEMONIC_SOURCES
    test_cardano_mnemonic.cpp
    ${CMAKE_SOURCE_DIR}/src/mnemonic.cpp
)
ADD_EXECUTABLE(test_cardano_mnemonic ${TEST_CARDANO_MNEMONIC_SOURCES})
target_link_libraries(test_cardano_mnemonic PRIVATE
    Botan::Botan
    cppbor::cppbor
    Threads::Threads
    OpenSSL::SSL
)
ADD_TEST(cardano_mnemonic test_cardano_mnemonic)

################################################################################
# Test address derivation from the Mnemonic
################################################################################
set(TEST_CARDANO_MNEMONIC_TO_ADDRESS_SOURCES
    test_cardano_mnemonic_to_address.cpp
    ${CMAKE_SOURCE_DIR}/src/mnemonic.cpp
    ${CMAKE_SOURCE_DIR}/src/crypto.cpp
    ${CMAKE_SOURCE_DIR}/src/address.cpp
    ${CMAKE_SOURCE_DIR}/src/encodings.cpp
    ${VIPER25519_SOURCES}
    ${LIBCPPBOR_SOURCES}
)
ADD_EXECUTABLE(test_cardano_mnemonic_to_address
    ${TEST_CARDANO_MNEMONIC_TO_ADDRESS_SOURCES}
)
target_link_libraries(test_cardano_mnemonic_to_address PRIVATE
    Botan::Botan
    cppbor::cppbor
    sodium::sodium
    Threads::Threads
    OpenSSL::SSL
)
ADD_TEST(cardano_mnemonic_to_address test_cardano_mnemonic_to_address)

################################################################################
# Test stake address derivation from the Mnemonic
################################################################################
set(TEST_CARDANO_MNEMONIC_TO_STAKE_ADDRESS_SOURCES
    test_cardano_mnemonic_to_stake_address.cpp
    ${CMAKE_SOURCE_DIR}/src/mnemonic.cpp
    ${CMAKE_SOURCE_DIR}/src/crypto.cpp
    ${CMAKE_SOURCE_DIR}/src/address.cpp
    ${CMAKE_SOURCE_DIR}/src/encodings.cpp
    ${VIPER25519_SOURCES}
    ${LIBCPPBOR_SOURCES}
)
ADD_EXECUTABLE(test_cardano_mnemonic_to_stake_address
    ${TEST_CARDANO_MNEMONIC_TO_STAKE_ADDRESS_SOURCES}
)
target_link_libraries(test_cardano_mnemonic_to_stake_address PRIVATE
    Botan::Botan
    cppbor::cppbor
    sodium::sodium
    Threads::Threads
    OpenSSL::SSL
)
ADD_TEST(cardano_mnemonic_to_stake_address
    test_cardano_mnemonic_to_stake_address
)

################################################################################
# Test Cardano ledger types and CBOR serialization.
################################################################################
# ADD_EXECUTABLE(test_cardano_ledger
#     test_cardano_ledger.cpp
# )
# target_link_libraries(test_cardano_ledger PRIVATE ${TEST_LIBCARDANO_LIBS})
# ADD_TEST("CardanoLedger" test_cardano_ledger)

################################################################################
# Test stake pool code
################################################################################
set(TEST_CARDANO_STAKE_POOL_SOURCES
    test_cardano_stake_pool.cpp
    ${CMAKE_SOURCE_DIR}/src/crypto.cpp
    ${CMAKE_SOURCE_DIR}/src/encodings.cpp
    ${CMAKE_SOURCE_DIR}/src/address.cpp
    ${CMAKE_SOURCE_DIR}/src/mnemonic.cpp
    ${CMAKE_SOURCE_DIR}/src/ledger.cpp
    ${CMAKE_SOURCE_DIR}/src/stake_pool.cpp
    ${CMAKE_SOURCE_DIR}/src/utils.cpp
    ${VIPER25519_SOURCES}
    ${LIBCPPBOR_SOURCES}
)
ADD_EXECUTABLE(test_cardano_stake_pool
    ${TEST_CARDANO_STAKE_POOL_SOURCES}
)
target_link_libraries(test_cardano_stake_pool PRIVATE ${TEST_LIBCARDANO_LIBS})
ADD_TEST("CardanoStakePool" test_cardano_stake_pool)

################################################################################
# Test Cardano transaction building, signing, and serializing to CBOR
################################################################################
ADD_EXECUTABLE(test_cardano_transaction
    test_cardano_transaction.cpp
    ${CMAKE_SOURCE_DIR}/src/address.cpp
    ${CMAKE_SOURCE_DIR}/src/crypto.cpp
    ${CMAKE_SOURCE_DIR}/src/encodings.cpp
    ${CMAKE_SOURCE_DIR}/src/ledger.cpp
    ${CMAKE_SOURCE_DIR}/src/mnemonic.cpp
    ${CMAKE_SOURCE_DIR}/src/transaction.cpp
    ${VIPER25519_SOURCES}
    ${LIBCPPBOR_SOURCES}
)
target_link_libraries(test_cardano_transaction PRIVATE ${TEST_LIBCARDANO_LIBS})
ADD_TEST("CardanoTransactions" test_cardano_transaction)

################################################################################
# Test the Cardano Ed25519 API (libsodium wrapper)
################################################################################
ADD_EXECUTABLE(test_cardano_ed25519_api
    test_cardano_ed25519_api.cpp
    ${CMAKE_SOURCE_DIR}/src/ed25519.cpp
)
target_link_libraries(test_cardano_ed25519_api PRIVATE ${TEST_LIBCARDANO_LIBS})
ADD_TEST("Cardano Ed25519 API" test_cardano_ed25519_api)

################################################################################
# Test the Cardano BIP32-Ed25519 API
################################################################################
ADD_EXECUTABLE(test_cardano_bip32_ed25519_api
    test_cardano_bip32_ed25519_api.cpp
    ${CMAKE_SOURCE_DIR}/src/bip32_ed25519.cpp
    ${CMAKE_SOURCE_DIR}/src/encodings.cpp
    ${CMAKE_SOURCE_DIR}/src/mnemonic.cpp
)
target_link_libraries(test_cardano_bip32_ed25519_api PRIVATE ${TEST_LIBCARDANO_LIBS})
ADD_TEST("Cardano BIP32-Ed25519 API" test_cardano_bip32_ed25519_api)

################################################################################
# Test the Cardano VRF API (libsodium wrapper)
################################################################################
ADD_EXECUTABLE(test_cardano_vrf_api
    test_cardano_vrf_api.cpp
    ${CMAKE_SOURCE_DIR}/src/ed25519.cpp
    ${CMAKE_SOURCE_DIR}/src/encodings.cpp
    ${CMAKE_SOURCE_DIR}/src/vrf.cpp
)
target_link_libraries(test_cardano_vrf_api PRIVATE ${TEST_LIBCARDANO_LIBS})
ADD_TEST("Cardano VRF API" test_cardano_vrf_api)