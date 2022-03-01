cmake_minimum_required(VERSION 3.14)

# set the project name, language,  and version
project(cardano 
    DESCRIPTION "A blazingly fast library of Cardano blockchain tools written in modern C++."
    VERSION 1.0
    LANGUAGES C CXX
)

# specify the C++ standard
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED True)

########################################################################
# Additional packages
########################################################################

########################################################################
# Include directories
########################################################################

include_directories(${PROJECT_NAME}
    PRIVATE
        ${CMAKE_SOURCE_DIR}
    PUBLIC
        ${CMAKE_SOURCE_DIR}/include
)

########################################################################
# Tests
########################################################################

# Enable testing globally. Individual tests may be found in the `tests`
# subdirectory of the repository.
ENABLE_TESTING()

ADD_SUBDIRECTORY( test build )

########################################################################
# Target Build
########################################################################

# specify the source files
set(SOURCES
    ${CMAKE_SOURCE_DIR}/src/encodings.cpp
)

# add the library to build
add_library(cardano ${SOURCES})

########################################################################
# Target Link
########################################################################

# specify libraries for linking
# target_link_libraries(${PROJECT_NAME}
#     Threads::Threads)

########################################################################
# Install Target
########################################################################

install(TARGETS ${PROJECT_NAME} DESTINATION lib)
set(HEADERS
    ${CMAKE_SOURCE_DIR}/include/cardano/cardano.hpp
    ${CMAKE_SOURCE_DIR}/include/cardano/encodings.hpp
)
install(FILES ${HEADERS} DESTINATION "include/cardano")
