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

# Use Catch2 as the unit testing framework
FetchContent_Declare(
  Catch2
  GIT_REPOSITORY https://github.com/catchorg/Catch2.git
  GIT_TAG        v3.6.0
)
FetchContent_MakeAvailable(Catch2)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED True)

set(TEST_LIBCARDANO_LIBS
    Catch2::Catch2WithMain
    OpenSSL::SSL
    Threads::Threads
    Botan::Botan
    cryptopp::cryptopp
    cppbor::cppbor
    cardano_sodium::cardano_sodium
    cardano::cardano
)

include_directories(
    ${CMAKE_CURRENT_SOURCE_DIR}/../src
    ${CMAKE_CURRENT_SOURCE_DIR}/../include
)

################################################################################
# Test the encoding APIs
################################################################################
ADD_EXECUTABLE(test_cardano_encodings  test_cardano_encoding_apis.cpp)
target_link_libraries(test_cardano_encodings PRIVATE ${TEST_LIBCARDANO_LIBS})
ADD_TEST("Encoding APIs" test_cardano_encodings)

################################################################################
# Test the Cardano Ed25519 API (libsodium wrapper)
################################################################################
ADD_EXECUTABLE(test_cardano_ed25519_api test_cardano_ed25519_api.cpp)
target_link_libraries(test_cardano_ed25519_api PRIVATE ${TEST_LIBCARDANO_LIBS})
ADD_TEST("Cardano Ed25519 API" test_cardano_ed25519_api)

################################################################################
# Test the Cardano BIP32-Ed25519 API
################################################################################
ADD_EXECUTABLE(test_cardano_bip32_ed25519_api
    test_cardano_bip32_ed25519_api.cpp
)
target_link_libraries(test_cardano_bip32_ed25519_api PRIVATE 
    ${TEST_LIBCARDANO_LIBS}
)
ADD_TEST("Cardano BIP32-Ed25519 API" test_cardano_bip32_ed25519_api)

################################################################################
# Test the Cardano Address API
################################################################################
ADD_EXECUTABLE(test_cardano_address test_cardano_address_api.cpp)
target_link_libraries(test_cardano_address PRIVATE ${TEST_LIBCARDANO_LIBS})
ADD_TEST("Cardano Address API" test_cardano_address)

################################################################################
# Test the Cardano Mnemonic API
################################################################################
ADD_EXECUTABLE(test_cardano_mnemonic test_cardano_mnemonic_api.cpp)
target_link_libraries(test_cardano_mnemonic PRIVATE ${TEST_LIBCARDANO_LIBS})
ADD_TEST("Cardano Mnemonic API" test_cardano_mnemonic)

################################################################################
# Test Cardano ledger types and CBOR serialization.
################################################################################

################################################################################
# Test Shelley-Era transaction building, signing, and serializing to CBOR.
################################################################################
ADD_EXECUTABLE(test_shelley_tx test_cardano_shelley_transaction_api.cpp)
target_link_libraries(test_shelley_tx PRIVATE ${TEST_LIBCARDANO_LIBS})
ADD_TEST("Cardano Transaction API [Shelley-Era]" test_shelley_tx)

################################################################################
# Test Cardano transaction building, signing, and serializing to CBOR
################################################################################
ADD_EXECUTABLE(test_cardano_transaction test_cardano_transaction_api.cpp)
target_link_libraries(test_cardano_transaction PRIVATE ${TEST_LIBCARDANO_LIBS})
ADD_TEST("Cardano Transaction API" test_cardano_transaction)

################################################################################
# Test the Cardano VRF API (libsodium wrapper)
################################################################################
ADD_EXECUTABLE(test_cardano_vrf_api test_cardano_vrf_api.cpp)
target_link_libraries(test_cardano_vrf_api PRIVATE ${TEST_LIBCARDANO_LIBS})
ADD_TEST("Cardano VRF API" test_cardano_vrf_api)

################################################################################
# Test the Cardano KES API
################################################################################
ADD_EXECUTABLE(test_cardano_kes_api test_cardano_kes_api.cpp)
target_link_libraries(test_cardano_kes_api PRIVATE ${TEST_LIBCARDANO_LIBS})
ADD_TEST("Cardano KES API" test_cardano_kes_api)

################################################################################
# Test the Cardano KES Implementation for Integration with the Haskell code
################################################################################
ADD_EXECUTABLE(test_cardano_kes_integration test_cardano_kes_integration.cpp)
target_link_libraries(test_cardano_kes_integration PRIVATE ${TEST_LIBCARDANO_LIBS})
ADD_TEST("Cardano KES Integration" test_cardano_kes_integration)

################################################################################
# Test Cardano Stake Pool API
################################################################################
ADD_EXECUTABLE(test_cardano_stake_pool test_cardano_stake_pool_api.cpp)
target_link_libraries(test_cardano_stake_pool PRIVATE ${TEST_LIBCARDANO_LIBS})
ADD_TEST("Cardano Stake Pool API" test_cardano_stake_pool)

################################################################################
# Test Cardano Utilities API
################################################################################
ADD_EXECUTABLE(test_cardano_util test_cardano_util_api.cpp)
target_link_libraries(test_cardano_util PRIVATE ${TEST_LIBCARDANO_LIBS})
ADD_TEST("Cardano Utilities API" test_cardano_util)

################################################################################
# Test Cardano Secure Memory API
################################################################################
ADD_EXECUTABLE(test_cardano_secmem test_cardano_secmem_api.cpp)
target_link_libraries(test_cardano_secmem PRIVATE ${TEST_LIBCARDANO_LIBS})
ADD_TEST("Cardano Secure Memory API" test_cardano_secmem)

################################################################################
# Test Cardano Genesis API
################################################################################
ADD_EXECUTABLE(test_cardano_genesis test_cardano_genesis_api.cpp)
target_link_libraries(test_cardano_genesis PRIVATE ${TEST_LIBCARDANO_LIBS})
ADD_TEST("Cardano Genesis API" test_cardano_genesis)