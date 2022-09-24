cmake_minimum_required(VERSION 3.15)
project(cmake_integration_test)

# specify the C++ standard
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED True)

# Add the local cmake directory to the path for custom search files
list(INSERT CMAKE_MODULE_PATH 0 ${CMAKE_CURRENT_SOURCE_DIR}/..)

# Load static libraries
if(WIN32)
    list(INSERT CMAKE_FIND_LIBRARY_SUFFIXES 0 .lib .a)
else()
    set(CMAKE_FIND_LIBRARY_SUFFIXES .a)
endif()

find_package(Cardano REQUIRED)
find_package(Threads REQUIRED)
find_package(Botan REQUIRED)

if (APPLE)
    include_directories("/usr/local/include")
endif()

add_executable(${PROJECT_NAME} test_cardano_cmake.cpp)

target_link_libraries(${PROJECT_NAME} PRIVATE 
    Cardano::Cardano
    botan::botan
    Threads::Threads
)
