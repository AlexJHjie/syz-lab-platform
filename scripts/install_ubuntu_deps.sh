#!/usr/bin/env bash
set -euo pipefail

sudo apt-get update
sudo apt-get install -y \
  bc \
  bison \
  build-essential \
  ca-certificates \
  curl \
  debootstrap \
  dwarves \
  e2fsprogs \
  flex \
  git \
  golang-go \
  libelf-dev \
  libssl-dev \
  openssh-client \
  patch \
  python3 \
  qemu-system-x86 \
  util-linux \
  xz-utils

echo "Ubuntu dependencies installed."
