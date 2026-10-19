#!/usr/bin/env bash
# 在 Debian rootfs 基础上装 rsyslog：有些 syzbot 崩溃要有人读 /proc/kmsg 才会触发
# （崩溃进程名形如 "in:imklog"），公共镜像不装 syslog 守护进程，崩点就永远走不到。
#
# 用法： ./scripts/create_rootfs-rsyslog.sh [rootfs-dir]
# 产出： <rootfs-dir>/rootfs.img（默认 work/cache/rootfs-rsyslog/rootfs.img）与 id_rsa
# 配法： 见 delivery-02-52/README.md

set -euo pipefail

ROOTFS_DIR="${1:-${PLATFORM_WORK_DIR:-work}/cache/rootfs-rsyslog}"
IMAGE="${ROOTFS_DIR}/rootfs.img"
KEY="${ROOTFS_DIR}/id_rsa"
SIZE="${PLATFORM_ROOTFS_SIZE:-8G}"
SUITE="${PLATFORM_DEBIAN_SUITE:-bookworm}"
MIRROR="${PLATFORM_DEBIAN_MIRROR:-http://deb.debian.org/debian}"
MARKER_PATH="/etc/expert-rsyslog-rootfs"
SYSLOG_UNIT="/etc/systemd/system/multi-user.target.wants/rsyslog.service"

if (( $# > 1 )); then
  echo "usage: $0 [rootfs-dir]" >&2
  exit 2
fi

mkdir -p "${ROOTFS_DIR}"

if [[ ! -f "${KEY}" ]]; then
  ssh-keygen -t ed25519 -N "" -f "${KEY}"
fi

image_has_path() {
  debugfs -R "stat $1" "${IMAGE}" 2>/dev/null | grep -q "^Inode:"
}

rsyslog_image_is_valid() {
  [[ -f "${IMAGE}" && -f "${KEY}" ]] &&
    image_has_path "${MARKER_PATH}" &&
    image_has_path "/sbin/init" &&
    image_has_path "/usr/sbin/sshd" &&
    image_has_path "/root/.ssh/authorized_keys" &&
    image_has_path "/usr/sbin/rsyslogd" &&
    image_has_path "${SYSLOG_UNIT}" &&
    debugfs -R "cat /etc/rsyslog.conf" "${IMAGE}" 2>/dev/null |
      grep -q 'imklog'
}

if [[ -f "${IMAGE}" ]]; then
  if ! rsyslog_image_is_valid; then
    echo "existing rootfs is not a valid expert rsyslog image: ${IMAGE}" >&2
    echo "remove the incomplete image and run this script again" >&2
    exit 1
  fi
  echo "rsyslog rootfs already exists: ${IMAGE}"
  echo "verified: /usr/sbin/rsyslogd, imklog enabled, rsyslog.service linked"
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
  if [[ -n "${LOOPDEV:-}" ]]; then
    if ! sudo losetup -d "${LOOPDEV}" 2>/dev/null; then
      echo "WARNING: failed to detach ${LOOPDEV}" >&2
    fi
  fi
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
  rsyslog \
  strace

if ! sudo test -x "${MNT}/usr/sbin/rsyslogd"; then
  echo "rsyslog package did not install /usr/sbin/rsyslogd" >&2
  exit 1
fi
if ! sudo grep -q 'imklog' "${MNT}/etc/rsyslog.conf"; then
  echo "rsyslog.conf does not load the imklog module" >&2
  exit 1
fi

echo "root:root" | sudo chroot "${MNT}" chpasswd
echo "platform" | sudo tee "${MNT}/etc/hostname" >/dev/null
echo "127.0.0.1 localhost platform" | sudo tee "${MNT}/etc/hosts" >/dev/null
echo "/dev/vda / ext4 defaults 0 1" | sudo tee "${MNT}/etc/fstab" >/dev/null
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
sudo chroot "${MNT}" systemctl enable rsyslog.service

# rsyslogd drops privileges before writing, so the spool and log targets must
# be group-writable by "adm". debootstrap images have root-only /var/log.
sudo mkdir -p "${MNT}/var/spool/rsyslog"
sudo chmod 700 "${MNT}/var/spool/rsyslog"
sudo chown root:root "${MNT}/var/spool/rsyslog"
sudo touch "${MNT}/var/log/syslog" "${MNT}/var/log/kern.log"
sudo chown root:adm "${MNT}/var/log/syslog" "${MNT}/var/log/kern.log"
sudo chmod 640 "${MNT}/var/log/syslog" "${MNT}/var/log/kern.log"

printf 'version=1\n' | sudo tee "${MNT}${MARKER_PATH}" >/dev/null

sudo chroot "${MNT}" apt-get clean
sync

cleanup
trap - EXIT

if ! rsyslog_image_is_valid; then
  echo "created image failed rsyslog rootfs validation: ${IMAGE}" >&2
  exit 1
fi
echo "rsyslog rootfs created: ${IMAGE}"
echo "verified: /usr/sbin/rsyslogd, imklog enabled, rsyslog.service linked"
echo "ssh key: ${KEY}"
