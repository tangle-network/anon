FROM lukemathwalker/cargo-chef as planner
WORKDIR app
COPY . .
RUN cargo chef prepare  --recipe-path recipe.json

FROM lukemathwalker/cargo-chef as cacher
WORKDIR app
COPY --from=planner /app/recipe.json recipe.json
RUN cargo chef cook --release --recipe-path recipe.json

FROM rustlang/rust:nightly as builder
WORKDIR app
COPY . .
# Copy over the cached dependencies
COPY --from=cacher /app/target target
COPY --from=cacher $CARGO_HOME $CARGO_HOME
RUN ./scripts/build.sh

FROM rust as runtime
WORKDIR app
VOLUME /files
VOLUME /images

COPY --from=builder /app/target/release/node-template /usr/local/bin
RUN /usr/local/bin/node-template purge-chain --dev -y

ENTRYPOINT ["/usr/local/bin/node-template"]
