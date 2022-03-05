set(TEST_CARDANO_ENCODINGS_SOURCES 
    test_cardano_encodings.cpp
    ${CMAKE_SOURCE_DIR}/src/encodings.cpp
    ${CMAKE_SOURCE_DIR}/src/utils.cpp)
ADD_EXECUTABLE(test_cardano_encodings ${TEST_CARDANO_ENCODINGS_SOURCES})
ADD_TEST(cardano_encodings test_cardano_encodings)

set(TEST_CARDANO_CRYPTO_SOURCES 
    test_cardano_crypto.cpp
    ${CMAKE_SOURCE_DIR}/src/crypto.cpp
    ${CMAKE_SOURCE_DIR}/src/address.cpp
    ${CMAKE_SOURCE_DIR}/src/encodings.cpp
    ${CMAKE_SOURCE_DIR}/src/utils.cpp
    ${CMAKE_SOURCE_DIR}/src/cardano_crypto_interface.c
    ${CARDANO_CRYPTO_CBITS_SOURCES}
    ${CRYPTONITE_CBITS_SOURCES}
)
ADD_EXECUTABLE(test_cardano_crypto ${TEST_CARDANO_CRYPTO_SOURCES})
ADD_TEST(cardano_crypto test_cardano_crypto)

set(TEST_CARDANO_ADDRESS_SOURCES 
    test_cardano_address.cpp
    ${CMAKE_SOURCE_DIR}/src/crypto.cpp
    ${CMAKE_SOURCE_DIR}/src/address.cpp
    ${CMAKE_SOURCE_DIR}/src/encodings.cpp
    ${CMAKE_SOURCE_DIR}/src/utils.cpp
    ${CMAKE_SOURCE_DIR}/src/cardano_crypto_interface.c
    ${CARDANO_CRYPTO_CBITS_SOURCES}
    ${CRYPTONITE_CBITS_SOURCES}
)
ADD_EXECUTABLE(test_cardano_address ${TEST_CARDANO_ADDRESS_SOURCES})
ADD_TEST(cardano_address test_cardano_address)