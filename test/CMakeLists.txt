########################################################################
# Test the encoding capabilites
########################################################################

set(TEST_CARDANO_ENCODINGS_SOURCES 
    test_cardano_encodings.cpp
    ${CMAKE_SOURCE_DIR}/src/encodings.cpp
    ${CMAKE_SOURCE_DIR}/src/utils.cpp)
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
    ${CMAKE_SOURCE_DIR}/src/utils.cpp
    ${CMAKE_SOURCE_DIR}/src/cardano_crypto_interface.c
    ${CARDANO_CRYPTO_CBITS_SOURCES}
    ${CRYPTONITE_CBITS_SOURCES}
)
ADD_EXECUTABLE(test_cardano_crypto ${TEST_CARDANO_CRYPTO_SOURCES})
target_link_libraries(test_cardano_crypto
    cbor::cbor
    botan::botan
)
ADD_TEST(cardano_crypto test_cardano_crypto)

########################################################################
# Test the address implementations
########################################################################

set(TEST_CARDANO_ADDRESS_SOURCES 
    test_cardano_address.cpp
    ${CMAKE_SOURCE_DIR}/src/mnemonic.cpp
    ${CMAKE_SOURCE_DIR}/src/crypto.cpp
    ${CMAKE_SOURCE_DIR}/src/address.cpp
    ${CMAKE_SOURCE_DIR}/src/encodings.cpp
    ${CMAKE_SOURCE_DIR}/src/utils.cpp
    ${CMAKE_SOURCE_DIR}/src/cardano_crypto_interface.c
    ${CARDANO_CRYPTO_CBITS_SOURCES}
    ${CRYPTONITE_CBITS_SOURCES}
)
ADD_EXECUTABLE(test_cardano_address ${TEST_CARDANO_ADDRESS_SOURCES})
target_link_libraries(test_cardano_address
    cbor::cbor
    botan::botan
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
    ${CMAKE_SOURCE_DIR}/src/utils.cpp
    ${CMAKE_SOURCE_DIR}/src/cardano_crypto_interface.c
    ${CARDANO_CRYPTO_CBITS_SOURCES}
    ${CRYPTONITE_CBITS_SOURCES}
)
ADD_EXECUTABLE(test_cardano_byron_address ${TEST_CARDANO_BYRON_ADDRESS_SOURCES})
target_link_libraries(test_cardano_byron_address
    cbor::cbor
    botan::botan
)
ADD_TEST(cardano_byron_address test_cardano_byron_address)

########################################################################
# Test the Mnemonic generation and root key derivation
########################################################################

set(TEST_CARDANO_MNEMONIC_SOURCES 
    test_cardano_mnemonic.cpp
    ${CMAKE_SOURCE_DIR}/src/mnemonic.cpp
    ${CMAKE_SOURCE_DIR}/src/crypto.cpp
    ${CMAKE_SOURCE_DIR}/src/address.cpp
    ${CMAKE_SOURCE_DIR}/src/encodings.cpp
    ${CMAKE_SOURCE_DIR}/src/utils.cpp
    ${CMAKE_SOURCE_DIR}/src/cardano_crypto_interface.c
    ${CARDANO_CRYPTO_CBITS_SOURCES}
    ${CRYPTONITE_CBITS_SOURCES}
)
ADD_EXECUTABLE(test_cardano_mnemonic ${TEST_CARDANO_MNEMONIC_SOURCES})
target_link_libraries(test_cardano_mnemonic
    cbor::cbor
    botan::botan
)
ADD_TEST(cardano_mnemonic test_cardano_mnemonic)
