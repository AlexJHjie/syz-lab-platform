#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"

usage() {
  cat <<'EOF'
Usage:
  ./scripts/setup.sh deps
  ./scripts/setup.sh toolchains [toolchain-key ...]
  ./scripts/setup.sh rootfs [rootfs-dir]
  ./scripts/setup.sh rootfs-firmware [rootfs-dir]
  ./scripts/setup.sh rootfs-minimal [rootfs-dir]
  ./scripts/setup.sh all

Commands:
  deps              Install Ubuntu host dependencies.
  toolchains        Install all or selected kernel toolchains.
  rootfs            Create the default QEMU rootfs.
  rootfs-firmware   Create the firmware QEMU rootfs.
  rootfs-minimal    Create the minimal QEMU rootfs.
  all               Run every setup step in order.
EOF
}

run_script() {
  local script="$1"
  shift
  echo "+ ${script} $*"
  "${SCRIPT_DIR}/${script}" "$@"
}

command="${1:-}"
if [[ -z "${command}" || "${command}" == "-h" || "${command}" == "--help" ]]; then
  usage
  exit 0
fi
shift

case "${command}" in
  deps)
    run_script install_ubuntu_deps.sh "$@"
    ;;
  toolchains)
    run_script setup_toolchains.sh "$@"
    ;;
  rootfs)
    run_script create_rootfs.sh "$@"
    ;;
  rootfs-firmware)
    run_script create_rootfs-firmware.sh "$@"
    ;;
  rootfs-minimal)
    run_script create_rootfs-minimal.sh "$@"
    ;;
  all)
    if (( $# != 0 )); then
      echo "error: the all command does not accept arguments" >&2
      exit 2
    fi
    run_script install_ubuntu_deps.sh
    run_script setup_toolchains.sh
    run_script create_rootfs.sh
    run_script create_rootfs-firmware.sh
    run_script create_rootfs-minimal.sh
    ;;
  *)
    echo "error: unknown setup command: ${command}" >&2
    usage >&2
    exit 2
    ;;
esac
