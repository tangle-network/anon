FROM debian:buster-slim
LABEL AUTHOR="Webb Developers <dev@webb.tools>"
ENV RUST_BACKTRACE=full

ARG RUST_VERSION=nightly-2021-06-01
ARG PROFILE=release
ARG GIT_REPO=https://github.com/webb-tools/anon
ARG BINARY_NAME=webb
ARG PACKAGE_NAME=webb-node

RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y \
    clang \
    cmake \
    curl \
    git \
    libssl-dev \
    pkg-config

# Get Rust
RUN curl https://raw.githubusercontent.com/rust-lang/rustup/master/rustup-init.sh -sSf | sh -s -- -y
RUN echo 'source $HOME/.cargo/env' >> $HOME/.bashrc
RUN $HOME/.cargo/bin/rustup default stable
RUN $HOME/.cargo/bin/rustup uninstall nightly 
RUN $HOME/.cargo/bin/rustup toolchain install ${RUST_VERSION}
RUN $HOME/.cargo/bin/rustup target add wasm32-unknown-unknown --toolchain ${RUST_VERSION}

RUN git clone ${GIT_REPO} source
RUN cd source && $HOME/.cargo/bin/cargo build -p ${PACKAGE_NAME} --${PROFILE}

EXPOSE 9615
EXPOSE 9944
EXPOSE 9933
EXPOSE 30333

CMD ["./source/webb-node/target/release --dev"]
