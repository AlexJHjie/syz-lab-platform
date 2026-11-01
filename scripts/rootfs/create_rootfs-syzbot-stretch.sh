#!/usr/bin/env bash
# Build a Debian stretch image that mirrors the syzbot VM environment:
# sysvinit via /etc/inittab, no systemd, no logind, no cgroup mounts.
# This keeps injected input/power events from suspending the guest and stops
# the init system from mounting cgroup v1 before syz-executor does.
set -euo pipefail

source "$(dirname -- "${BASH_SOURCE[0]}")/lib/rootfs-dev.sh"

ROOTFS_DIR="${1:-${PLATFORM_WORK_DIR:-work}/cache/rootfs/rootfs-syzbot-stretch}"
IMAGE="${ROOTFS_DIR}/rootfs.img"
KEY="${ROOTFS_DIR}/id_rsa"
SIZE="${PLATFORM_ROOTFS_SIZE:-2G}"
SUITE="${PLATFORM_DEBIAN_SUITE:-stretch}"
MIRROR="${PLATFORM_DEBIAN_MIRROR:-http://archive.debian.org/debian}"
MARKER_PATH="/etc/syzbot-stretch-rootfs"
PACKAGES="ca-certificates,curl,ifupdown,iproute2,openssh-server,procps,psmisc,strace,sudo,sysvinit-core"

mkdir -p "${ROOTFS_DIR}"

if [[ ! -f "${KEY}" ]]; then
  ssh-keygen -t ed25519 -N "" -f "${KEY}"
fi

image_has_path() {
  local path="$1"
  debugfs -R "stat ${path}" "${IMAGE}" 2>/dev/null | grep -q "^Inode:"
}

image_is_valid() {
  image_has_path "${MARKER_PATH}" &&
    image_has_path "/etc/inittab" &&
    image_has_path "/usr/sbin/sshd" &&
    image_has_path "/root/.ssh/authorized_keys" &&
    ! image_has_path "/lib/systemd/systemd-logind" &&
    debugfs -R "cat /etc/inittab" "${IMAGE}" 2>/dev/null | grep -q "getty"
}

if [[ -f "${IMAGE}" ]]; then
  if ! image_is_valid; then
    echo "existing rootfs is not a valid syzbot stretch image: ${IMAGE}" >&2
    echo "remove the incomplete image and run this script again" >&2
    exit 1
  fi
  echo "syzbot stretch rootfs already exists: ${IMAGE}"
  echo "verified init: /etc/inittab (sysvinit, no systemd)"
  echo "ssh key: ${KEY}"
  exit 0
fi

# sudo resets the environment, so proxy settings must be forwarded explicitly
# or debootstrap/wget/apt will stall on large package downloads. Fall back to
# the WSL proxy helper when the caller did not export them.
if [[ -z "${http_proxy:-}" && -r /usr/local/bin/wsl-proxy-url ]]; then
  resolved="$(/usr/local/bin/wsl-proxy-url 2>/dev/null || true)"
  if [[ -n "${resolved}" && "${resolved}" != "DIRECT" ]]; then
    http_proxy="${resolved}"
    https_proxy="${resolved}"
    all_proxy="${resolved}"
    export http_proxy https_proxy all_proxy
  fi
fi

PROXY_VARS=()
for name in http_proxy https_proxy all_proxy no_proxy; do
  value="${!name:-}"
  if [[ -n "${value}" ]]; then
    PROXY_VARS+=("${name}=${value}")
  fi
done
if [[ ${#PROXY_VARS[@]} -gt 0 ]]; then
  echo "forwarding proxy: ${PROXY_VARS[0]}"
else
  echo "no proxy in environment; direct downloads will be used"
fi

TMP="$(mktemp -d)"
MNT="${TMP}/mnt"
BUILD_IMAGE="${TMP}/rootfs.img"
mkdir -p "${MNT}"
cleanup() {
  set +e
  if mountpoint -q "${MNT}/dev/pts"; then sudo umount -lf "${MNT}/dev/pts"; fi
  if mountpoint -q "${MNT}/dev"; then sudo umount -lf "${MNT}/dev"; fi
  if mountpoint -q "${MNT}/proc"; then sudo umount -lf "${MNT}/proc"; fi
  if mountpoint -q "${MNT}/sys"; then sudo umount -lf "${MNT}/sys"; fi
  if mountpoint -q "${MNT}"; then sudo umount -lf "${MNT}"; fi
  if [[ -n "${LOOPDEV:-}" ]]; then sudo losetup -d "${LOOPDEV}" || true; fi
  rm -rf "${TMP}"
}
trap cleanup EXIT

truncate -s "${SIZE}" "${BUILD_IMAGE}"
mkfs.ext4 -F "${BUILD_IMAGE}"
LOOPDEV="$(sudo losetup --find --show "${BUILD_IMAGE}")"
sudo mount "${LOOPDEV}" "${MNT}"

# Retry individual downloads without discarding the entire bootstrap.
cat >"${TMP}/wgetrc" <<'EOF'
timeout = 30
tries = 10
retry_on_http_error = 429,500,502,503,504
wait_retry = 2
EOF
if ! sudo env "${PROXY_VARS[@]}" WGETRC="${TMP}/wgetrc" \
  debootstrap --variant=minbase --arch=amd64 --no-check-gpg --include="${PACKAGES}" \
  "${SUITE}" "${MNT}" "${MIRROR}"; then
  sudo cp "${MNT}/debootstrap/debootstrap.log" "${ROOTFS_DIR}/debootstrap.log" || true
  echo "debootstrap failed; see ${ROOTFS_DIR}/debootstrap.log" >&2
  exit 1
fi
sudo cp "${MNT}/var/log/bootstrap.log" "${ROOTFS_DIR}/bootstrap.log"
rootfs_mount_dev "${MNT}" sudo
sudo mount -t proc proc "${MNT}/proc"
sudo mount -t sysfs sysfs "${MNT}/sys"

sudo tee "${MNT}/etc/apt/sources.list" >/dev/null <<EOF
deb ${MIRROR} ${SUITE} main
EOF
sudo tee "${MNT}/etc/apt/apt.conf.d/99archive" >/dev/null <<'EOF'
Acquire::Check-Valid-Until "false";
Acquire::Retries "5";
EOF
echo "root:root" | sudo chroot "${MNT}" chpasswd
echo "syzkaller" | sudo tee "${MNT}/etc/hostname" >/dev/null
echo -en "127.0.0.1\tlocalhost\n" | sudo tee "${MNT}/etc/hosts" >/dev/null
echo "nameserver 8.8.8.8" | sudo tee "${MNT}/etc/resolv.conf" >/dev/null

sudo mkdir -p "${MNT}/root/.ssh"
sudo cp "${KEY}.pub" "${MNT}/root/.ssh/authorized_keys"
sudo chmod 700 "${MNT}/root/.ssh"
sudo chmod 600 "${MNT}/root/.ssh/authorized_keys"
sudo chown -R root:root "${MNT}/root/.ssh"

# stretch ships OpenSSH 7.4, which has no Include/sshd_config.d support, so the
# main config is edited in place.
sudo sed -i -E \
  -e 's/^#?PermitRootLogin .*/PermitRootLogin yes/' \
  -e 's/^#?PubkeyAuthentication .*/PubkeyAuthentication yes/' \
  -e 's/^#?PasswordAuthentication .*/PasswordAuthentication no/' \
  -e 's/^#?UsePAM .*/UsePAM no/' \
  "${MNT}/etc/ssh/sshd_config"
sudo chroot "${MNT}" ssh-keygen -A
# Fail early if the edited config cannot be parsed by this sshd.
sudo mkdir -p "${MNT}/run/sshd"
sudo chroot "${MNT}" /usr/sbin/sshd -t

# Serial console login, matching the syzbot image inittab.
echo 'T0:23:respawn:/sbin/getty -L ttyS0 115200 vt100' | sudo tee -a "${MNT}/etc/inittab" >/dev/null

# Filesystems the syzbot image mounts at boot.
sudo tee "${MNT}/etc/fstab" >/dev/null <<'EOF'
/dev/vda / ext4 defaults 0 0
debugfs /sys/kernel/debug debugfs defaults 0 0
securityfs /sys/kernel/security securityfs defaults 0 0
configfs /sys/kernel/config configfs defaults 0 0
binfmt_misc /proc/sys/fs/binfmt_misc binfmt_misc defaults 0 0
EOF

# sysctl values carried over from the syzbot image.
sudo tee "${MNT}/etc/sysctl.conf" >/dev/null <<'EOF'
kernel.printk = 7 4 1 3
debug.exception-trace = 0
net.core.bpf_jit_enable = 1
net.core.bpf_jit_kallsyms = 1
net.core.bpf_jit_harden = 0
kernel.softlockup_all_cpu_backtrace = 1
kernel.kptr_restrict = 0
kernel.watchdog_thresh = 60
net.ipv4.ping_group_range = 0 65535
EOF

# Static addressing on the QEMU user network; no DHCP client is installed.
sudo tee "${MNT}/etc/network/interfaces" >/dev/null <<'EOF'
auto lo
iface lo inet loopback

auto eth0
iface eth0 inet static
    address 10.0.2.15
    netmask 255.255.255.0
    gateway 10.0.2.2
EOF

sudo chroot "${MNT}" apt-get clean
sync

# Validate the mounted tree before publishing anything.
if ! sudo test -x "${MNT}/sbin/init" ||
  ! sudo test -x "${MNT}/usr/sbin/sshd" ||
  ! sudo test -f "${MNT}/root/.ssh/authorized_keys" ||
  ! sudo test -f "${MNT}/etc/inittab" ||
  ! sudo grep -q "getty" "${MNT}/etc/inittab" ||
  ! sudo grep -qE "^PermitRootLogin yes" "${MNT}/etc/ssh/sshd_config" ||
  ! sudo grep -qE "^PubkeyAuthentication yes" "${MNT}/etc/ssh/sshd_config" ||
  sudo test -e "${MNT}/lib/systemd/systemd-logind" ||
  sudo test -e "${MNT}/usr/lib/systemd/systemd-logind"; then
  echo "created image failed syzbot stretch validation" >&2
  exit 1
fi
if sudo readlink -f "${MNT}/sbin/init" | grep -q systemd; then
  echo "created image uses systemd as init; expected sysvinit" >&2
  exit 1
fi
echo "version=1" | sudo tee "${MNT}${MARKER_PATH}" >/dev/null

sudo umount "${MNT}/dev/pts" "${MNT}/dev" "${MNT}/proc" "${MNT}/sys" "${MNT}"
sudo losetup -d "${LOOPDEV}"
LOOPDEV=""
mv "${BUILD_IMAGE}" "${IMAGE}"

echo "syzbot stretch rootfs created: ${IMAGE}"
echo "verified init: /etc/inittab (sysvinit, no systemd, no logind)"
echo "ssh key: ${KEY}"
