# Find the Botan library
# If found, a target botan::botan will be availible for linking.

include(FindPackageHandleStandardArgs)

find_library(Botan_LIBRARY 
    NAMES 
        botan-2
        botan 
    PATHS
        /usr/lib
        /usr/lib64
        /usr/local/lib
        /usr/local/lib64
)
find_path(Botan_INCLUDE_DIR 
    NAMES botan/botan.h
    PATHS /usr/local/include/botan-2
)

find_package_handle_standard_args(Botan REQUIRED_VARS Botan_LIBRARY Botan_INCLUDE_DIR)

if (Botan_FOUND)
    mark_as_advanced(Botan_INCLUDE_DIR)
    mark_as_advanced(Botan_LIBRARY)
endif()

if (Botan_FOUND AND NOT TARGET botan::botan)
    add_library(botan::botan STATIC IMPORTED)
    set_property(TARGET botan::botan PROPERTY IMPORTED_LOCATION ${Botan_LIBRARY})
    target_include_directories(botan::botan INTERFACE ${Botan_INCLUDE_DIR})
endif()