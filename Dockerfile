FROM ubuntu:20.04
LABEL AUTHOR="Webb Developers <dev@webb.tools>"
ENV RUST_BACKTRACE=full

ADD build/webb-node /usr/local/bin/webb-node

EXPOSE 9615
EXPOSE 9944

CMD ["webb-node"]
