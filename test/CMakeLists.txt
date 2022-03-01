set(TEST_CARDANO_ENCODINGS_SOURCES 
    test_cardano_encodings.cpp
    ${CMAKE_SOURCE_DIR}/src/encodings.cpp)
ADD_EXECUTABLE(test_cardano_encodings ${TEST_CARDANO_ENCODINGS_SOURCES})
ADD_TEST(cardano_encodings test_cardano_encodings)
