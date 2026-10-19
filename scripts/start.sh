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
  ./scripts/setup.sh rootfs-legacy-env [rootfs-dir]
  ./scripts/setup.sh rootfs-rsyslog [rootfs-dir]
  ./scripts/setup.sh rootfs-scsi-partition [rootfs-dir]
  ./scripts/setup.sh all

Commands:
  deps              Install Ubuntu host dependencies.
  toolchains        Install all or selected kernel toolchains.
  rootfs            Create the default QEMU rootfs.
  rootfs-firmware   Create the firmware QEMU rootfs.
  rootfs-minimal    Create the minimal QEMU rootfs.
  rootfs-legacy-env Create the QEMU rootfs with inherited SSH service keyrings.
  rootfs-rsyslog    Create the QEMU rootfs with rsyslog and imklog enabled.
  rootfs-scsi-partition
                    Create an MBR-partitioned QEMU rootfs for virtio-scsi.
  all               Run every setup step in order, continuing after failures.
                    Report failed scripts at the end; exit nonzero if any fail.
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
  rootfs-legacy-env)
    run_script create_rootfs-legacy-env.sh "$@"
    ;;
  rootfs-rsyslog)
    run_script create_rootfs-rsyslog.sh "$@"
    ;;
  rootfs-scsi-partition)
    run_script create_rootfs-scsi-partition.sh "$@"
    ;;
  all)
    if (( $# != 0 )); then
      echo "error: the all command does not accept arguments" >&2
      exit 2
    fi
    failed_scripts=()
    for script in \
      install_ubuntu_deps.sh \
      setup_toolchains.sh \
      create_rootfs.sh \
      create_rootfs-firmware.sh \
      create_rootfs-minimal.sh \
      create_rootfs-legacy-env.sh \
      create_rootfs-rsyslog.sh \
      create_rootfs-scsi-partition.sh; do
      if run_script "${script}"; then
        :
      else
        status=$?
        failed_scripts+=("${script} (exit ${status})")
      fi
    done
    if (( ${#failed_scripts[@]} > 0 )); then
      printf '\nFailed setup scripts:\n' >&2
      printf '  - %s\n' "${failed_scripts[@]}" >&2
      exit 1
    fi
    echo "All setup scripts completed successfully."
    ;;
  *)
    echo "error: unknown setup command: ${command}" >&2
    usage >&2
    exit 2
    ;;
esac
