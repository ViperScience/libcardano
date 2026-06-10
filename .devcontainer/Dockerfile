FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
    autoconf \
    autoconf-archive \
    automake \
    build-essential \
    ca-certificates \
    cmake \
    curl \
    gcc-14 g++-14 \
    git \
    gnupg2 \
    just \
    libboost-all-dev \
    libssl-dev \
    libtool \
    meson \
    mold \
    ninja-build \
    pkg-config \
    python3 \
    software-properties-common \
    sudo \
    unzip \
    vim \
    wget \
    zip \
    zsh \
    && rm -rf /var/lib/apt/lists/*

# Make gcc-14/g++-14 the default cc/c++
RUN update-alternatives --install /usr/bin/gcc gcc /usr/bin/gcc-14 100 \
    --slave /usr/bin/g++ g++ /usr/bin/g++-14 \
    --slave /usr/bin/gcov gcov /usr/bin/gcov-14

# Download and run the official LLVM install script
RUN wget -O - https://apt.llvm.org/llvm.sh | bash -s -- all

# Build and install Botan 3
WORKDIR /tmp
RUN curl -LO https://botan.randombit.net/releases/Botan-3.7.1.tar.xz \
    && tar --extract --file Botan-3.7.1.tar.xz \
    && cd Botan-3.7.1 \
    && python3 ./configure.py \
    && make -j8 \
    && make install \
    && cd .. && rm -rf Botan*

# Use the default non-root user and set zsh as its shell.
# Add a password so that additional packages may be installed.
ARG USERNAME=ubuntu
RUN usermod --shell /usr/bin/zsh ${USERNAME}
RUN echo "${USERNAME}:${USERNAME}" | chpasswd
USER ${USERNAME}

# Install oh-my-zsh and spaceship theme
ENV ZSH=/home/${USERNAME}/.oh-my-zsh
RUN sh -c "$(curl -fsSL https://raw.githubusercontent.com/ohmyzsh/ohmyzsh/master/tools/install.sh)" "" --unattended \
    && git clone https://github.com/spaceship-prompt/spaceship-prompt.git "${ZSH}/custom/themes/spaceship-prompt" --depth=1 \
    && ln -s "${ZSH}/custom/themes/spaceship-prompt/spaceship.zsh-theme" "${ZSH}/custom/themes/spaceship.zsh-theme" \
    && sed -i 's/ZSH_THEME="robbyrussell"/ZSH_THEME="spaceship"/' ~/.zshrc

# Install Claude for the user
RUN curl -fsSL https://claude.ai/install.sh | bash

# Install CPX
RUN curl -fsSL https://raw.githubusercontent.com/ozacod/cpx/master/install.sh | sh

# Add the local bin to the PATH
RUN echo "export PATH=\$PATH:/home/${USERNAME}/.local/bin" >> ~/.zshrc
