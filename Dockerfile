FROM debian:buster-slim
LABEL AUTHOR="Webb Developers <dev@webb.tools>"
ENV RUST_BACKTRACE=full

RUN apt-get update && \
        apt-get install -y libc6 && \
        rm -rf /var/lib/apt/lists/*

ADD build/webb-node /usr/local/bin/webb-node

EXPOSE 9615
EXPOSE 9944

CMD ["webb-node"]
