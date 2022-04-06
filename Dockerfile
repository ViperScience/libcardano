FROM debian:bullseye-slim

RUN apt-get update && apt-get install -y \
    build-essential \
    curl \
    libssl-dev \
    gdb \
 && apt-get clean \
 && rm -rf /var/lib/apt/lists/*

# Copy dependencies from repo to /opt
COPY . /opt

# Install later version of CMake than what is included in the package repos
WORKDIR /opt
ARG CMAKE_VERSION=3.23.0
RUN curl -LO https://github.com/Kitware/CMake/releases/download/v$CMAKE_VERSION/cmake-$CMAKE_VERSION-linux-x86_64.tar.gz \
 && mkdir cmake \
 && tar -xvf cmake-$CMAKE_VERSION-linux-x86_64.tar.gz -C cmake --strip-components=1
ENV PATH "/opt/cmake/bin:$PATH"

# Build the password cruncher executable
ENV CTEST_OUTPUT_ON_FAILURE=1
WORKDIR /opt
RUN ls /opt/libs/cardano-crypto/cbits/ed25519/ed25519.c
RUN ls /opt/libs/
RUN ls /opt/libs/cardano-crypto/
RUN ls /opt/libs/cardano-crypto/cbits/
RUN ls /opt/libs/cardano-crypto/cbits/ed25519/
RUN mkdir build && cd build \
 && cmake -DCMAKE_BUILD_TYPE=Release .. \
 && make -j16 \
 && make test \
 && make install
