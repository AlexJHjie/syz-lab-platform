#!/usr/bin/env bash
# Create a Debian disk with an MBR partition for virtio-scsi (root=/dev/sda1).
# Usage: ./scripts/create_rootfs-scsi-partition.sh [rootfs-dir]
set -euo pipefail

ROOTFS_DIR="${1:-${PLATFORM_WORK_DIR:-work}/cache/rootfs-scsi}"
IMAGE="${ROOTFS_DIR}/rootfs.img"
KEY="${ROOTFS_DIR}/id_rsa"
SIZE="${PLATFORM_ROOTFS_SIZE:-8G}"
SUITE="${PLATFORM_DEBIAN_SUITE:-bookworm}"
MIRROR="${PLATFORM_DEBIAN_MIRROR:-http://deb.debian.org/debian}"

mkdir -p "${ROOTFS_DIR}"

if [[ ! -f "${KEY}" ]]; then
  ssh-keygen -t ed25519 -N "" -f "${KEY}"
fi

if [[ -f "${IMAGE}" ]]; then
  echo "rootfs already exists: ${IMAGE}"
  echo "ssh key: ${KEY}"
  exit 0
fi

TMP="$(mktemp -d)"
PENDING="$(mktemp "${ROOTFS_DIR}/.rootfs.XXXXXX")"
MNT="${TMP}/mnt"
mkdir -p "${MNT}"
cleanup() {
  set +e
  if mountpoint -q "${MNT}/dev"; then sudo umount -lf "${MNT}/dev"; fi
  if mountpoint -q "${MNT}/proc"; then sudo umount -lf "${MNT}/proc"; fi
  if mountpoint -q "${MNT}/sys"; then sudo umount -lf "${MNT}/sys"; fi
  if mountpoint -q "${MNT}"; then sudo umount -lf "${MNT}"; fi
  if [[ -n "${LOOPDEV:-}" ]]; then sudo losetup -d "${LOOPDEV}" || true; fi
  rm -f "${PENDING}"
  rm -rf "${TMP}"
}
trap cleanup EXIT

truncate -s "${SIZE}" "${PENDING}"
printf 'label: dos\nunit: sectors\n\nstart=2048, type=83\n' | sfdisk "${PENDING}"
LOOPDEV="$(sudo losetup --find --show --partscan "${PENDING}")"
# Wait briefly for the partition device to become available.
for _ in {1..10}; do
  [[ -b "${LOOPDEV}p1" ]] && break
  sleep 1
done
sudo mkfs.ext4 -F -L scsipart1 "${LOOPDEV}p1"
sudo mount "${LOOPDEV}p1" "${MNT}"

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

echo "root:root" | sudo chroot "${MNT}" chpasswd
echo "platform" | sudo tee "${MNT}/etc/hostname" >/dev/null
echo "127.0.0.1 localhost platform" | sudo tee "${MNT}/etc/hosts" >/dev/null
echo "/dev/sda1 / ext4 defaults 0 1" | sudo tee "${MNT}/etc/fstab" >/dev/null
sudo tee "${MNT}/etc/network/interfaces" >/dev/null <<'EOF'
auto lo
iface lo inet loopback

auto eth0
iface eth0 inet static
    address 10.0.2.15
    netmask 255.255.255.0
    gateway 10.0.2.2
EOF

sudo mkdir -p "${MNT}/root/.ssh"
sudo cp "${KEY}.pub" "${MNT}/root/.ssh/authorized_keys"
sudo chmod 700 "${MNT}/root/.ssh"
sudo chmod 600 "${MNT}/root/.ssh/authorized_keys"
sudo chown -R root:root "${MNT}/root/.ssh"

sudo sed -i 's/^#\?PermitRootLogin .*/PermitRootLogin yes/' "${MNT}/etc/ssh/sshd_config"
sudo sed -i 's/^#\?PasswordAuthentication .*/PasswordAuthentication yes/' "${MNT}/etc/ssh/sshd_config"
sudo chroot "${MNT}" systemctl enable networking
sudo chroot "${MNT}" systemctl enable ssh

sudo umount "${MNT}/sys" "${MNT}/proc" "${MNT}/dev"
sudo umount "${MNT}"
sudo losetup -d "${LOOPDEV}"
LOOPDEV=""
mv "${PENDING}" "${IMAGE}"

echo "rootfs created: ${IMAGE}"
echo "ssh key: ${KEY}"
