set(VIPER25519_SOURCES
    ${CMAKE_CURRENT_LIST_DIR}/viper25519/src/curve25519.cpp
    ${CMAKE_CURRENT_LIST_DIR}/viper25519/src/ed25519.cpp
    ${CMAKE_CURRENT_LIST_DIR}/viper25519/src/vrf25519.cpp
    PARENT_SCOPE
)
set(VIPER25519_INCLUDE
    ${CMAKE_CURRENT_LIST_DIR}/viper25519/src
    ${CMAKE_CURRENT_LIST_DIR}/viper25519/include
    PARENT_SCOPE
)
set(LIBCPPBOR_SOURCES
    ${CMAKE_CURRENT_LIST_DIR}/libcppbor/src/cppbor.cpp
    ${CMAKE_CURRENT_LIST_DIR}/libcppbor/src/cppbor_parse.cpp
    PARENT_SCOPE
)
set(LIBCPPBOR_INCLUDE
    ${CMAKE_CURRENT_LIST_DIR}/libcppbor/include
    PARENT_SCOPE
)