########################################################################
# Test the encoding capabilites
########################################################################

set(TEST_CARDANO_ENCODINGS_SOURCES 
    test_cardano_encodings.cpp
    ${CMAKE_SOURCE_DIR}/src/encodings.cpp
    ${CMAKE_SOURCE_DIR}/src/utils.cpp
    ${QCBOR_SOURCES}
)
ADD_EXECUTABLE(test_cardano_encodings ${TEST_CARDANO_ENCODINGS_SOURCES})
ADD_TEST(cardano_encodings test_cardano_encodings)

########################################################################
# Test the key implementations
########################################################################

set(TEST_CARDANO_CRYPTO_SOURCES 
    test_cardano_crypto.cpp
    ${CMAKE_SOURCE_DIR}/src/mnemonic.cpp
    ${CMAKE_SOURCE_DIR}/src/crypto.cpp
    ${CMAKE_SOURCE_DIR}/src/address.cpp
    ${CMAKE_SOURCE_DIR}/src/encodings.cpp
    ${VIPER25519_SOURCES}
    ${QCBOR_SOURCES}
)
ADD_EXECUTABLE(test_cardano_crypto ${TEST_CARDANO_CRYPTO_SOURCES})
target_link_libraries(test_cardano_crypto PRIVATE
    botan::botan
    Threads::Threads
    OpenSSL::SSL
)
ADD_TEST(cardano_crypto test_cardano_crypto)

# ########################################################################
# # Test the address implementations
# ########################################################################

set(TEST_CARDANO_ADDRESS_SOURCES 
    test_cardano_address.cpp
    ${CMAKE_SOURCE_DIR}/src/mnemonic.cpp
    ${CMAKE_SOURCE_DIR}/src/crypto.cpp
    ${CMAKE_SOURCE_DIR}/src/address.cpp
    ${CMAKE_SOURCE_DIR}/src/encodings.cpp
    ${VIPER25519_SOURCES}
    ${QCBOR_SOURCES}
)
ADD_EXECUTABLE(test_cardano_address ${TEST_CARDANO_ADDRESS_SOURCES})
target_link_libraries(test_cardano_address PRIVATE
    botan::botan
    Threads::Threads
    OpenSSL::SSL
)
ADD_TEST(cardano_address test_cardano_address)

########################################################################
# Test the Byron era address implementations
########################################################################

set(TEST_CARDANO_BYRON_ADDRESS_SOURCES 
    test_cardano_byron_address.cpp
    ${CMAKE_SOURCE_DIR}/src/mnemonic.cpp
    ${CMAKE_SOURCE_DIR}/src/crypto.cpp
    ${CMAKE_SOURCE_DIR}/src/address.cpp
    ${CMAKE_SOURCE_DIR}/src/encodings.cpp
    ${VIPER25519_SOURCES}
    ${QCBOR_SOURCES}
)
ADD_EXECUTABLE(test_cardano_byron_address ${TEST_CARDANO_BYRON_ADDRESS_SOURCES})
target_link_libraries(test_cardano_byron_address PRIVATE
    botan::botan
    Threads::Threads
    OpenSSL::SSL
)
ADD_TEST(cardano_byron_address test_cardano_byron_address)

########################################################################
# Test the Mnemonic generation and root key derivation
########################################################################

set(TEST_CARDANO_MNEMONIC_SOURCES 
    test_cardano_mnemonic.cpp
    ${CMAKE_SOURCE_DIR}/src/mnemonic.cpp
)
ADD_EXECUTABLE(test_cardano_mnemonic ${TEST_CARDANO_MNEMONIC_SOURCES})
target_link_libraries(test_cardano_mnemonic PRIVATE
    botan::botan
    Threads::Threads
    OpenSSL::SSL
)
ADD_TEST(cardano_mnemonic test_cardano_mnemonic)

########################################################################
# Test address derivation from the Mnemonic
########################################################################

set(TEST_CARDANO_MNEMONIC_TO_ADDRESS_SOURCES 
    test_cardano_mnemonic_to_address.cpp
    ${CMAKE_SOURCE_DIR}/src/mnemonic.cpp
    ${CMAKE_SOURCE_DIR}/src/crypto.cpp
    ${CMAKE_SOURCE_DIR}/src/address.cpp
    ${CMAKE_SOURCE_DIR}/src/encodings.cpp
    ${VIPER25519_SOURCES}
    ${QCBOR_SOURCES}
)
ADD_EXECUTABLE(test_cardano_mnemonic_to_address
    ${TEST_CARDANO_MNEMONIC_TO_ADDRESS_SOURCES}
)
target_link_libraries(test_cardano_mnemonic_to_address PRIVATE
    botan::botan
    Threads::Threads
    OpenSSL::SSL
)
ADD_TEST(cardano_mnemonic_to_address test_cardano_mnemonic_to_address)

########################################################################
# Test stake address derivation from the Mnemonic
########################################################################

set(TEST_CARDANO_MNEMONIC_TO_STAKE_ADDRESS_SOURCES 
    test_cardano_mnemonic_to_stake_address.cpp
    ${CMAKE_SOURCE_DIR}/src/mnemonic.cpp
    ${CMAKE_SOURCE_DIR}/src/crypto.cpp
    ${CMAKE_SOURCE_DIR}/src/address.cpp
    ${CMAKE_SOURCE_DIR}/src/encodings.cpp
    ${VIPER25519_SOURCES}
    ${QCBOR_SOURCES}
)
ADD_EXECUTABLE(test_cardano_mnemonic_to_stake_address
    ${TEST_CARDANO_MNEMONIC_TO_STAKE_ADDRESS_SOURCES}
)
target_link_libraries(test_cardano_mnemonic_to_stake_address PRIVATE
    botan::botan
    Threads::Threads
    OpenSSL::SSL
)
ADD_TEST(cardano_mnemonic_to_stake_address 
    test_cardano_mnemonic_to_stake_address
)

########################################################################
# Test the CBOR encoding functionality
########################################################################

set(TEST_CARDANO_CBOR_ENCODINGS_SOURCES 
    test_cardano_cbor_encodings.cpp
    ${CMAKE_SOURCE_DIR}/src/encodings.cpp
    ${QCBOR_SOURCES}
)
ADD_EXECUTABLE(test_cardano_cbor_encodings
    ${TEST_CARDANO_CBOR_ENCODINGS_SOURCES}
)
ADD_TEST(cardano_cbor_encodings test_cardano_cbor_encodings)

########################################################################
# Test transaction building and serializing to CBOR
########################################################################

set(TEST_CARDANO_TRANSACTION_BUILD_SOURCES 
    test_cardano_transaction_build.cpp
    ${CMAKE_SOURCE_DIR}/src/address.cpp
    ${CMAKE_SOURCE_DIR}/src/crypto.cpp
    ${CMAKE_SOURCE_DIR}/src/encodings.cpp
    ${CMAKE_SOURCE_DIR}/src/mnemonic.cpp
    ${CMAKE_SOURCE_DIR}/src/transaction.cpp
    ${VIPER25519_SOURCES}
    ${QCBOR_SOURCES}
)
ADD_EXECUTABLE(test_cardano_transaction_build
    ${TEST_CARDANO_TRANSACTION_BUILD_SOURCES}
)
target_link_libraries(test_cardano_transaction_build PRIVATE
    botan::botan
    Threads::Threads
    OpenSSL::SSL
)
ADD_TEST(cardano_transaction_build test_cardano_transaction_build)

########################################################################
# Test transaction building, signing, and serializing to CBOR
########################################################################

set(TEST_CARDANO_TRANSACTION_SIGN_SOURCES 
    test_cardano_transaction_sign.cpp
    ${CMAKE_SOURCE_DIR}/src/address.cpp
    ${CMAKE_SOURCE_DIR}/src/crypto.cpp
    ${CMAKE_SOURCE_DIR}/src/encodings.cpp
    ${CMAKE_SOURCE_DIR}/src/mnemonic.cpp
    ${CMAKE_SOURCE_DIR}/src/transaction.cpp
    ${VIPER25519_SOURCES}
    ${QCBOR_SOURCES}
)
ADD_EXECUTABLE(test_cardano_transaction_sign
    ${TEST_CARDANO_TRANSACTION_SIGN_SOURCES}
)
target_link_libraries(test_cardano_transaction_sign PRIVATE
    botan::botan
    Threads::Threads
    OpenSSL::SSL
)
ADD_TEST(cardano_transaction_sign test_cardano_transaction_sign)