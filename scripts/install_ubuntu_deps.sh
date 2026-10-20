#!/usr/bin/env bash
set -euo pipefail

# Host dependencies for syzkaller builds, QEMU and rootfs creation.
# Kernel build dependencies and toolchain runtime libraries live in the image.
# Docker and Go must be installed separately (see README.md).
sudo apt-get update
sudo apt-get install -y \
  build-essential \
  ca-certificates \
  debootstrap \
  e2fsprogs \
  qemu-system-x86 \
  util-linux \
  debootstrap

echo "Ubuntu host dependencies installed."
