FROM ubuntu:18.04

RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
    bc bison build-essential ca-certificates flex git kmod \
    libelf-dev libgmp10 libmpc3 libmpfr6 libssl-dev \
    libncurses-dev perl python3 xz-utils zlib1g-dev \
    && rm -rf /var/lib/apt/lists/*

# 0084's unmodified SELinux host tools require PF_MAX <= 45.
RUN printf '#include <sys/socket.h>\n#if PF_MAX > 45\n#error incompatible socket headers\n#endif\n' \
    | cc -E -x c - > /dev/null

WORKDIR /tmp
