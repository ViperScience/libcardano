FROM debian:bookworm

RUN apt-get update && apt-get install -y \
    git \
    curl \
    libssl-dev \
    libbotan-2-dev \
    build-essential \
 && apt-get clean \
 && rm -rf /var/lib/apt/lists/*

# Install the newer version of CMake
RUN curl -LO https://github.com/Kitware/CMake/releases/download/v3.25.1/cmake-3.25.1-linux-x86_64.tar.gz \
 && tar --extract --file cmake-3.25.1-linux-x86_64.tar.gz \
 && mv cmake-3.25.1-linux-x86_64/bin/* /usr/local/bin \
 && mv cmake-3.25.1-linux-x86_64/share/cmake-3.25 /usr/local/share/

COPY . /opt
WORKDIR /opt

# Build, test, and install the libcardano library
WORKDIR /opt
COPY . /opt
ENV CTEST_OUTPUT_ON_FAILURE=1
RUN mkdir build && cd build \
 && cmake -DCMAKE_BUILD_TYPE=Release .. \
 && make -j16 \
 && make test \
 && make install

# Run the libcardano cmake integration test
WORKDIR /opt/cmake/cmake_integration_test
RUN mkdir build && cd build \
 && cmake -DCMAKE_BUILD_TYPE=Release .. \
 && make -j16
RUN ./build/cmake_integration_test
