#!/usr/bin/env bash
set -euo pipefail

ROOTFS_DIR="${1:-${PLATFORM_WORK_DIR:-work}/cache/rootfs-minimal}"
IMAGE="${ROOTFS_DIR}/rootfs.img"
KEY="${ROOTFS_DIR}/id_rsa"
SIZE="${PLATFORM_ROOTFS_SIZE:-2G}"
SUITE="${PLATFORM_DEBIAN_SUITE:-bookworm}"
MIRROR="${PLATFORM_DEBIAN_MIRROR:-http://deb.debian.org/debian}"
MARKER_PATH="/etc/expert-minimal-rootfs"

mkdir -p "${ROOTFS_DIR}"

if [[ ! -f "${KEY}" ]]; then
  ssh-keygen -t ed25519 -N "" -f "${KEY}"
fi

image_has_path() {
  local path="$1"
  debugfs -R "stat ${path}" "${IMAGE}" 2>/dev/null | grep -q "^Inode:"
}

minimal_image_is_valid() {
  image_has_path "${MARKER_PATH}" &&
    image_has_path "/sbin/init" &&
    image_has_path "/usr/sbin/sshd" &&
    image_has_path "/root/.ssh/authorized_keys" &&
    debugfs -R "cat /sbin/init" "${IMAGE}" 2>/dev/null |
      grep -q "expert minimal init"
}

if [[ -f "${IMAGE}" ]]; then
  if ! minimal_image_is_valid; then
    echo "existing rootfs is not a valid expert minimal image: ${IMAGE}" >&2
    echo "remove the incomplete image and run this script again" >&2
    exit 1
  fi
  echo "minimal rootfs already exists: ${IMAGE}"
  echo "verified init: /sbin/init"
  echo "ssh key: ${KEY}"
  exit 0
fi

TMP="$(mktemp -d)"
MNT="${TMP}/mnt"
mkdir -p "${MNT}"
cleanup() {
  set +e
  if mountpoint -q "${MNT}/dev"; then sudo umount -lf "${MNT}/dev"; fi
  if mountpoint -q "${MNT}/proc"; then sudo umount -lf "${MNT}/proc"; fi
  if mountpoint -q "${MNT}/sys"; then sudo umount -lf "${MNT}/sys"; fi
  if mountpoint -q "${MNT}"; then sudo umount -lf "${MNT}"; fi
  if [[ -n "${LOOPDEV:-}" ]]; then sudo losetup -d "${LOOPDEV}" || true; fi
  rm -rf "${TMP}"
}
trap cleanup EXIT

truncate -s "${SIZE}" "${IMAGE}"
mkfs.ext4 -F "${IMAGE}"
LOOPDEV="$(sudo losetup --find --show "${IMAGE}")"
sudo mount "${LOOPDEV}" "${MNT}"

sudo debootstrap --variant=minbase --arch=amd64 "${SUITE}" "${MNT}" "${MIRROR}"
sudo mount --bind /dev "${MNT}/dev"
sudo mount -t proc proc "${MNT}/proc"
sudo mount -t sysfs sysfs "${MNT}/sys"

sudo chroot "${MNT}" apt-get update
sudo chroot "${MNT}" apt-get install -y --no-install-recommends \
  busybox-static \
  ca-certificates \
  coreutils \
  iproute2 \
  openssh-server \
  procps \
  strace

echo "root:root" | sudo chroot "${MNT}" chpasswd
echo "platform" | sudo tee "${MNT}/etc/hostname" >/dev/null
echo "127.0.0.1 localhost platform" | sudo tee "${MNT}/etc/hosts" >/dev/null

sudo mkdir -p "${MNT}/root/.ssh" "${MNT}/etc/ssh/sshd_config.d"
sudo cp "${KEY}.pub" "${MNT}/root/.ssh/authorized_keys"
sudo chmod 700 "${MNT}/root/.ssh"
sudo chmod 600 "${MNT}/root/.ssh/authorized_keys"
sudo chown -R root:root "${MNT}/root/.ssh"

sudo tee "${MNT}/etc/ssh/sshd_config.d/99-expert-minimal.conf" >/dev/null <<'EOF'
PermitRootLogin yes
PasswordAuthentication no
PubkeyAuthentication yes
UsePAM no
EOF
sudo chroot "${MNT}" ssh-keygen -A

# Replace systemd's /sbin/init entry point. This init deliberately leaves all
# cgroup hierarchies untouched so the historical syz-executor can set them up.
sudo rm -f "${MNT}/sbin/init"
sudo tee "${MNT}/sbin/init" >/dev/null <<'EOF'
#!/bin/sh
# expert minimal init: boot enough userspace for SSH without mounting cgroups.
export PATH=/usr/sbin:/usr/bin:/sbin:/bin

mount -t proc proc /proc 2>/dev/null || true
mount -t sysfs sysfs /sys 2>/dev/null || true
mount -t devtmpfs devtmpfs /dev 2>/dev/null || true
mkdir -p /dev/pts /run/sshd /tmp
mount -t devpts devpts /dev/pts 2>/dev/null || true
mount -t tmpfs -o mode=0755 tmpfs /run 2>/dev/null || true
mkdir -p /run/sshd
chmod 1777 /tmp

hostname platform
ip link set lo up
ip link set eth0 up
ip addr add 10.0.2.15/24 dev eth0 2>/dev/null || true
ip route add default via 10.0.2.2 dev eth0 2>/dev/null || true

echo "expert minimal init: starting sshd"
exec /usr/sbin/sshd -D -e
EOF
sudo chmod 755 "${MNT}/sbin/init"
echo "version=1" | sudo tee "${MNT}${MARKER_PATH}" >/dev/null

sudo chroot "${MNT}" apt-get clean
sync

if ! sudo test -x "${MNT}/sbin/init" ||
  ! sudo test -x "${MNT}/usr/sbin/sshd" ||
  ! sudo test -f "${MNT}/root/.ssh/authorized_keys" ||
  ! sudo grep -q "expert minimal init" "${MNT}/sbin/init"; then
  echo "created image failed minimal rootfs validation: ${IMAGE}" >&2
  exit 1
fi

echo "minimal rootfs created: ${IMAGE}"
echo "verified init: /sbin/init (no cgroup mounts)"
echo "ssh key: ${KEY}"
