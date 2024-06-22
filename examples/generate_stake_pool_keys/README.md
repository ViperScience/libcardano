# Example: Generate Stake Pool Keys
This example shows how to use the __libcardano__ library to generate a set of stake pool keys.

## Build
Build the example as part of the top-level libogmios library build using the `BUILD_LIBCARDANO_EXAMPLES` flag.
A full example is shown below. 
Note that the project relies on the top level libcardano repository.

    # Clone the project (with submodules!)
    git clone --recurse-submodules https://gitlab.com/viperscience/libcardano.git
    cd libcardano

    # Setup the Cmake project
    # Note that vcpkg will be used by default so there is no need to specify here.
    # Set the flag to build the examples.
    cmake -B build/ -S . -DBUILD_LIBCARDANO_EXAMPLES=ON
    cmake --build build/ --parallel 4

## Run
Run the example as shown (replace `build` with your build directory if differently named).

    ./build/bin/genstakepoolkeys

The following key files will be located in the current working directory after the program is ran.
* cold.skey
* cold.vkey
* vrf.skey
* vrf.vkey
* kes.skey
* kes.vkey
