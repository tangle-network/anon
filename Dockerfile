FROM gcr.io/distroless/cc
LABEL AUTHOR="Webb Developers <dev@webb.tools>"

ADD target/release/node-template /

ENV RUST_BACKTRACE=full

EXPOSE 9615
EXPOSE 9944

CMD ["/node-template"]
