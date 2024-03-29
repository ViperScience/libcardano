# Libcardano CMake Integration Test

This directory contains the source code for a simple app that uses the 
libcardano library and must be linked with it in order to run. The
CMakeLists.txt file uses `find_package` to load the library. If the target 
builds and runs successfully, the libcardano CMake target files were installed
correctly.

    cmake -S . -B ./build
    cmake --build ./build
