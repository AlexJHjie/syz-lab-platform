#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"

usage() {
  cat <<'EOF'
Usage:
  ./scripts/start.sh deps
  ./scripts/start.sh toolchains [toolchain-key ...]
  ./scripts/start.sh rootfs-base [rootfs-dir]
  ./scripts/start.sh rootfs-firmware [rootfs-dir]
  ./scripts/start.sh rootfs-minimal [rootfs-dir]
  ./scripts/start.sh rootfs-legacy-env [rootfs-dir]
  ./scripts/start.sh rootfs-rsyslog [rootfs-dir]
  ./scripts/start.sh rootfs-scsi-partition [rootfs-dir]
  ./scripts/start.sh rootfs-evdev3 [rootfs-dir]
  ./scripts/start.sh rootfs-hungtask [rootfs-dir]
  ./scripts/start.sh rootfs-syzbot-stretch [rootfs-dir]
  ./scripts/start.sh rootfs-usbautopm [rootfs-dir]
  ./scripts/start.sh rootfs-vim2m [rootfs-dir]
  ./scripts/start.sh all

Commands:
  deps              Install Ubuntu host dependencies.
  toolchains        Install all or selected kernel toolchains.
  rootfs-base       Create the base QEMU rootfs.
  rootfs-firmware   Create the firmware QEMU rootfs.
  rootfs-minimal    Create the minimal QEMU rootfs.
  rootfs-legacy-env Create the QEMU rootfs with inherited SSH service keyrings.
  rootfs-rsyslog    Create the QEMU rootfs with rsyslog and imklog enabled.
  rootfs-scsi-partition
                    Create an MBR-partitioned QEMU rootfs for virtio-scsi.
  rootfs-evdev3      Create the QEMU rootfs with the PS/2 mouse event3 alias.
  rootfs-hungtask    Create the QEMU rootfs with a short hung-task timeout.
  rootfs-syzbot-stretch
                    Create the Debian stretch QEMU rootfs with sysvinit.
  rootfs-usbautopm   Create the QEMU rootfs with USB network autosuspend setup.
  rootfs-vim2m      Create the QEMU rootfs with a vim2m device alias.
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
  rootfs-base)
    run_script rootfs/create_rootfs-base.sh "$@"
    ;;
  rootfs-firmware)
    run_script rootfs/create_rootfs-firmware.sh "$@"
    ;;
  rootfs-minimal)
    run_script rootfs/create_rootfs-minimal.sh "$@"
    ;;
  rootfs-legacy-env)
    run_script rootfs/create_rootfs-legacy-env.sh "$@"
    ;;
  rootfs-rsyslog)
    run_script rootfs/create_rootfs-rsyslog.sh "$@"
    ;;
  rootfs-scsi-partition)
    run_script rootfs/create_rootfs-scsi-partition.sh "$@"
    ;;
  rootfs-evdev3)
    run_script rootfs/create_rootfs-evdev3.sh "$@"
    ;;
  rootfs-hungtask)
    run_script rootfs/create_rootfs-hungtask.sh "$@"
    ;;
  rootfs-syzbot-stretch)
    run_script rootfs/create_rootfs-syzbot-stretch.sh "$@"
    ;;
  rootfs-usbautopm)
    run_script rootfs/create_rootfs-usbautopm.sh "$@"
    ;;
  rootfs-vim2m)
    run_script rootfs/create_rootfs-vim2m.sh "$@"
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
      rootfs/create_rootfs-base.sh \
      rootfs/create_rootfs-firmware.sh \
      rootfs/create_rootfs-minimal.sh \
      rootfs/create_rootfs-legacy-env.sh \
      rootfs/create_rootfs-rsyslog.sh \
      rootfs/create_rootfs-scsi-partition.sh \
      rootfs/create_rootfs-evdev3.sh \
      rootfs/create_rootfs-hungtask.sh \
      rootfs/create_rootfs-syzbot-stretch.sh \
      rootfs/create_rootfs-usbautopm.sh \
      rootfs/create_rootfs-vim2m.sh; do
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
