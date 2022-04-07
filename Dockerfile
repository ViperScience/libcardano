#FROM debian:bullseye-slim
FROM python:3.9-slim-bullseye

RUN apt-get update && apt-get install -y \
    build-essential \
    curl \
    gdb \
    git \
    libssl-dev \
 && apt-get clean \
 && rm -rf /var/lib/apt/lists/*

# Install later version of CMake than what is included in the package repos
WORKDIR /opt
ARG CMAKE_VERSION=3.23.0
RUN curl -LO https://github.com/Kitware/CMake/releases/download/v$CMAKE_VERSION/cmake-$CMAKE_VERSION-linux-x86_64.tar.gz \
 && mkdir -p cmake \
 && tar -xf cmake-$CMAKE_VERSION-linux-x86_64.tar.gz -C cmake --strip-components=1
ENV PATH "/opt/cmake/bin:$PATH"

# Install the libcbor library
WORKDIR /opt
RUN git clone https://github.com/PJK/libcbor.git \
 && cd libcbor \
 && git checkout tags/v0.9.0 \
 && mkdir build && cd build \
 && cmake -DCMAKE_BUILD_TYPE=Release .. \
 && make -j8 \
 && make install

# Install the botan library
WORKDIR /opt
RUN git clone https://github.com/randombit/botan.git \
 && cd botan \
 && git checkout tags/2.19.1 \
 && python3 ./configure.py \
 && make \
 && make install

# Build the Cardano++ library
WORKDIR /opt
COPY . /opt
ENV CTEST_OUTPUT_ON_FAILURE=1
RUN mkdir build && cd build \
 && cmake -DCMAKE_BUILD_TYPE=Release .. \
 && make -j16 \
 && make test \
 && make install
