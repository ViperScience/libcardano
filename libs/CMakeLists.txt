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

add_subdirectory(libcppbor)
# add_subdirectory(viper25519)
