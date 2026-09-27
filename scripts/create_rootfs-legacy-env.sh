#!/usr/bin/env bash
# Build a Debian rootfs whose SSH sessions inherit the service keyring.
set -euo pipefail

ROOTFS_DIR="${1:-${PLATFORM_WORK_DIR:-work}/cache/rootfs-legacy-env}"
IMAGE="${ROOTFS_DIR}/rootfs.img"
KEY="${ROOTFS_DIR}/id_rsa"
SIZE="${PLATFORM_ROOTFS_SIZE:-8G}"
SUITE="${PLATFORM_DEBIAN_SUITE:-bookworm}"
MIRROR="${PLATFORM_DEBIAN_MIRROR:-http://deb.debian.org/debian}"
MARKER_PATH="/etc/expert-legacy-env-rootfs"

if (( $# > 1 )); then
  echo "usage: $0 [rootfs-dir]" >&2
  exit 2
fi

image_has_path() {
  local path="$1"
  debugfs -R "stat ${path}" "${IMAGE}" 2>/dev/null | grep -q '^Inode:'
}

image_has_keyring_mode() {
  local service="$1"
  debugfs -R "cat /etc/systemd/system/${service}.service.d/keyring.conf" \
    "${IMAGE}" 2>/dev/null | grep -qx 'KeyringMode=inherit'
}

legacy_image_is_valid() {
  [[ -f "${IMAGE}" && -f "${KEY}" ]] &&
    image_has_path "${MARKER_PATH}" &&
    image_has_path "/sbin/init" &&
    image_has_path "/usr/sbin/sshd" &&
    image_has_path "/root/.ssh/authorized_keys" &&
    image_has_path "/etc/pam.d/sshd" &&
    ! debugfs -R 'cat /etc/pam.d/sshd' "${IMAGE}" 2>/dev/null | grep -q pam_keyinit &&
    image_has_keyring_mode ssh &&
    image_has_keyring_mode sshd
}

mkdir -p "${ROOTFS_DIR}"

if [[ -f "${IMAGE}" ]]; then
  if ! legacy_image_is_valid; then
    echo "existing rootfs is not a valid expert legacy image: ${IMAGE}" >&2
    echo "remove the incomplete image and run this script again" >&2
    exit 1
  fi
  echo "legacy rootfs already exists: ${IMAGE}"
  echo "ssh key: ${KEY}"
  exit 0
fi

if [[ ! -f "${KEY}" ]]; then
  ssh-keygen -t ed25519 -N "" -f "${KEY}"
fi
chmod 600 "${KEY}"

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

sudo debootstrap --arch=amd64 "${SUITE}" "${MNT}" "${MIRROR}"
sudo mount --bind /dev "${MNT}/dev"
sudo mount -t proc proc "${MNT}/proc"
sudo mount -t sysfs sysfs "${MNT}/sys"

sudo chroot "${MNT}" apt-get update
sudo chroot "${MNT}" apt-get install -y \
  ca-certificates \
  coreutils \
  iproute2 \
  iptables \
  openssh-server \
  procps \
  strace

echo 'root:root' | sudo chroot "${MNT}" chpasswd
echo 'platform' | sudo tee "${MNT}/etc/hostname" >/dev/null
echo '127.0.0.1 localhost platform' | sudo tee "${MNT}/etc/hosts" >/dev/null
echo '/dev/vda / ext4 defaults 0 1' | sudo tee "${MNT}/etc/fstab" >/dev/null
sudo tee "${MNT}/etc/network/interfaces" >/dev/null <<'NETWORK'
auto lo
iface lo inet loopback

auto eth0
iface eth0 inet static
    address 10.0.2.15
    netmask 255.255.255.0
    gateway 10.0.2.2
NETWORK

sudo mkdir -p "${MNT}/root/.ssh"
sudo cp "${KEY}.pub" "${MNT}/root/.ssh/authorized_keys"
sudo chmod 700 "${MNT}/root/.ssh"
sudo chmod 600 "${MNT}/root/.ssh/authorized_keys"
sudo chown -R root:root "${MNT}/root/.ssh"

sudo sed -i 's/^#\?PermitRootLogin .*/PermitRootLogin yes/' "${MNT}/etc/ssh/sshd_config"
sudo sed -i 's/^#\?PasswordAuthentication .*/PasswordAuthentication yes/' "${MNT}/etc/ssh/sshd_config"
sudo chroot "${MNT}" systemctl enable networking
sudo chroot "${MNT}" systemctl enable ssh

sudo sed -i '/pam_keyinit/d' "${MNT}/etc/pam.d/sshd"
sudo mkdir -p "${MNT}/etc/systemd/system/sshd.service.d" \
  "${MNT}/etc/systemd/system/ssh.service.d"
printf '[Service]\nKeyringMode=inherit\n' |
  sudo tee "${MNT}/etc/systemd/system/sshd.service.d/keyring.conf" >/dev/null
sudo cp "${MNT}/etc/systemd/system/sshd.service.d/keyring.conf" \
  "${MNT}/etc/systemd/system/ssh.service.d/keyring.conf"
printf 'version=1\n' | sudo tee "${MNT}${MARKER_PATH}" >/dev/null

cleanup
trap - EXIT

if ! legacy_image_is_valid; then
  echo "created image failed legacy rootfs validation: ${IMAGE}" >&2
  exit 1
fi
echo "legacy rootfs created: ${IMAGE}"
echo "verified: pam_keyinit removed from sshd; KeyringMode=inherit installed"
echo "ssh key: ${KEY}"
