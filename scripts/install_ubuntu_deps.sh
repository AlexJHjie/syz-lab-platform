#!/usr/bin/env bash
set -euo pipefail

sudo apt-get update
sudo apt-get install -y \
  bc \
  bison \
  build-essential \
  ca-certificates \
  debootstrap \
  dwarves \
  e2fsprogs \
  flex \
  libelf-dev \
  libssl-dev \
  qemu-system-x86 \
  util-linux

echo "Ubuntu dependencies installed."
