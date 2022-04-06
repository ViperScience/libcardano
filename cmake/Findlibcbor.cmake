# Find the libcbor library
# If found, a target cbor::cbor will be availible for linking.

include(FindPackageHandleStandardArgs)

find_library(libcbor_LIBRARY 
    NAMES 
        libcbor
        libcbor.a 
    PATHS
        /usr/lib
        /usr/lib64
        /usr/local/lib
        /usr/local/lib64
)
find_path(libcbor_INCLUDE_DIR NAMES cbor.h)

find_package_handle_standard_args(libcbor REQUIRED_VARS libcbor_LIBRARY libcbor_INCLUDE_DIR)

if (libcbor_FOUND)
    mark_as_advanced(libcbor_INCLUDE_DIR)
    mark_as_advanced(libcbor_LIBRARY)
endif()

if (libcbor_FOUND AND NOT TARGET cbor::cbor)
    add_library(cbor::cbor STATIC IMPORTED)
    set_property(TARGET cbor::cbor PROPERTY IMPORTED_LOCATION ${libcbor_LIBRARY})
    target_include_directories(cbor::cbor INTERFACE ${libcbor_INCLUDE_DIR})
endif()