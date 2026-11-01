#!/usr/bin/env bash
# Source from rootfs builders; pass an optional privilege command (e.g. sudo).

rootfs_mount_dev() {
  local rootfs_dir device major minor
  rootfs_dir="$(realpath -e -- "$1")" || return
  shift
  if [[ "${rootfs_dir}" == / || -L "${rootfs_dir}/dev" ]] ||
    mountpoint -q "${rootfs_dir}/dev"; then
    echo "refusing to replace an unsafe or mounted /dev: ${rootfs_dir}/dev" >&2
    return 1
  fi

  # A bind mount shares host inodes. In particular, udev's postinst runs
  # systemd-tmpfiles and can chown host /dev/kvm using the guest's kvm GID.
  # devtmpfs also shares host device nodes; use a fresh tmpfs instead.
  "$@" mkdir -p "${rootfs_dir}/dev" || return
  "$@" mount -t tmpfs -o mode=0755,nosuid,noexec tmpfs "${rootfs_dir}/dev" || return
  while read -r device major minor; do
    "$@" mknod -m 0666 "${rootfs_dir}/dev/${device}" c "${major}" "${minor}" || return
  done <<'DEVICES'
null 1 3
zero 1 5
full 1 7
random 1 8
urandom 1 9
tty 5 0
DEVICES
  "$@" mknod -m 0600 "${rootfs_dir}/dev/console" c 5 1 || return

  "$@" mkdir -p "${rootfs_dir}/dev/pts" "${rootfs_dir}/dev/shm" || return
  "$@" chmod 1777 "${rootfs_dir}/dev/shm" || return
  "$@" mount -t devpts -o newinstance,nosuid,noexec,ptmxmode=0666,mode=0620 \
    devpts "${rootfs_dir}/dev/pts" || return
  "$@" ln -s pts/ptmx "${rootfs_dir}/dev/ptmx" || return
  "$@" ln -s /proc/self/fd "${rootfs_dir}/dev/fd" || return
  "$@" ln -s /proc/self/fd/0 "${rootfs_dir}/dev/stdin" || return
  "$@" ln -s /proc/self/fd/1 "${rootfs_dir}/dev/stdout" || return
  "$@" ln -s /proc/self/fd/2 "${rootfs_dir}/dev/stderr" || return
}
