FROM debian:bullseye-slim

RUN apt-get update && apt-get install -y \
    build-essential \
    curl \
    libssl-dev \
 && apt-get clean \
 && rm -rf /var/lib/apt/lists/*

# Install later version of CMake than what is included in the package repos
WORKDIR /opt
RUN curl -LO https://github.com/Kitware/CMake/releases/download/v3.22.1/cmake-3.22.1.tar.gz \
 && tar --extract --file cmake-3.22.1.tar.gz \
 && cd cmake-3.22.1 \
 && ./bootstrap -- -DCMAKE_BUILD_TYPE:STRING=Release \
 && make -j16 \
 && make install

# Build the password cruncher executable
ENV CTEST_OUTPUT_ON_FAILURE=1
COPY . /opt
WORKDIR /opt
RUN mkdir build && cd build \
 && /usr/local/bin/cmake -DCMAKE_BUILD_TYPE=Release .. \
 && make -j16 \
 && make test \
 && make install
