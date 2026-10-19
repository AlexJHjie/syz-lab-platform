FROM ubuntu:24.04

RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
    bc bison build-essential ca-certificates flex git kmod \
    libelf-dev libgmp10 libmpc3 libmpfr6 libssl-dev \
    libncurses-dev libz3-4 perl python3 xz-utils zlib1g-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /tmp
