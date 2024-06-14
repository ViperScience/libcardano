add_subdirectory(libcppbor)

set(CRYPTOPP_SOURCES ${CMAKE_CURRENT_LIST_DIR}/cryptopp)
set(CRYPTOPP_USE_MASTER_BRANCH 1)
set(CRYPTOPP_BUILD_TESTING OFF)
add_subdirectory(cryptopp-cmake)
