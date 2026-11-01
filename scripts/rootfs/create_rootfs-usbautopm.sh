#!/usr/bin/env bash
# Build a fresh bookworm image for the gadget USB net case (repro-63 handoff
# 5091eca6): arm runtime autosuspend on the device and bring its netdev up with
# an IPv6 address, so MLD runs while the device can still suspend.
set -euo pipefail

source "$(dirname -- "${BASH_SOURCE[0]}")/lib/rootfs-dev.sh"

if (( $# > 1 )); then
  echo "usage: $0 [rootfs-dir]" >&2
  exit 2
fi

ROOTFS_DIR="${1:-${PLATFORM_WORK_DIR:-work}/cache/rootfs/rootfs-usbautopm}"
mkdir -p "${ROOTFS_DIR}"
ROOTFS_DIR="$(realpath "${ROOTFS_DIR}")"
IMAGE="${ROOTFS_DIR}/rootfs.img"
KEY="${ROOTFS_DIR}/id_rsa"
SUITE=bookworm
MIRROR=https://mirrors.tuna.tsinghua.edu.cn/debian
# 0525:a4a1 is the Linux-USB Ethernet/RNDIS gadget; delay is set before the
# device is allowed to suspend so the first autosuspend fires immediately.
RULE='ACTION=="add", SUBSYSTEM=="usb", ATTR{idVendor}=="0525", ATTR{idProduct}=="a4a1", ATTR{power/autosuspend_delay_ms}="0", ATTR{power/control}="auto"'
RULE_FILE=/etc/udev/rules.d/60-usbnet-autosuspend.rules
# Bringing the netdev up and giving it an IPv6 address makes MLD run on this
# interface; without it the pernet teardown path never allocates in mld_newpack.
NET_RULE='ACTION=="add", SUBSYSTEM=="net", ATTRS{idVendor}=="0525", ATTRS{idProduct}=="a4a1", RUN+="/usr/local/sbin/usbnet-up.sh %k"'
NET_RULE_FILE=/etc/udev/rules.d/70-usbnet-up.rules
HELPER_PATH=/usr/local/sbin/usbnet-up.sh
HELPER='#!/bin/sh
# Bring up the gadget netdev and add an IPv6 address so MLD joins groups.
# udev may hand us the kernel name before/after a rename, so fall back to the
# first non-loopback interface whose parent is a USB device.
set -eu
IFACE="${1:-}"
if [ -z "${IFACE}" ] || [ ! -e "/sys/class/net/${IFACE}" ]; then
  IFACE=""
  for d in /sys/class/net/*; do
    n="${d##*/}"
    [ "${n}" = lo ] && continue
    case "$(readlink -f "${d}/device" 2>/dev/null || true)" in
      *usb*) IFACE="${n}"; break ;;
    esac
  done
fi
[ -n "${IFACE}" ] || exit 0
/usr/sbin/ip link set "${IFACE}" up
/usr/sbin/ip -6 addr replace fd00::1/64 dev "${IFACE}"'
PACKAGES="ca-certificates coreutils ifupdown iproute2 iptables openssh-server procps strace"

image_cat() {
  debugfs -R "cat $2" "$1" 2>/dev/null
}

image_stat() {
  debugfs -R "stat $2" "$1" 2>/dev/null
}

validate_image() {
  local image="$1" key="$2" authorized public
  [[ -f "${image}" && -s "${key}" && -s "${key}.pub" ]] || return 1
  [[ "$(stat -c %s "${image}")" == 8589934592 ]] || return 1
  [[ "$(blkid -p -s TYPE -o value "${image}")" == ext4 ]] || return 1
  image_cat "${image}" /usr/lib/os-release | grep -qx 'VERSION_CODENAME=bookworm' || return 1
  image_cat "${image}" /var/lib/dpkg/status | grep -x 'Architecture: amd64' >/dev/null || return 1
  [[ "$(image_cat "${image}" "${RULE_FILE}")" == "${RULE}" ]] || return 1
  [[ "$(image_cat "${image}" "${NET_RULE_FILE}")" == "${NET_RULE}" ]] || return 1
  [[ "$(image_cat "${image}" "${HELPER_PATH}")" == "${HELPER}" ]] || return 1
  image_stat "${image}" "${HELPER_PATH}" | grep -Eq 'Mode: +0755' || return 1
  image_cat "${image}" /etc/ssh/sshd_config | grep -qx 'PermitRootLogin yes' || return 1
  image_cat "${image}" /etc/fstab | grep -qx '/dev/vda / ext4 defaults 0 1' || return 1
  [[ "$(image_cat "${image}" /etc/hostname)" == platform ]] || return 1
  image_cat "${image}" /etc/hosts | grep -qx '127.0.0.1 localhost platform' || return 1
  authorized="$(image_cat "${image}" /root/.ssh/authorized_keys)"
  public="$(cat "${key}.pub")"
  [[ -n "${authorized}" && "${authorized}" == "${public}" ]] || return 1
  [[ "$(ssh-keygen -y -f "${key}" | cut -d " " -f 1,2)" == "$(cut -d " " -f 1,2 "${key}.pub")" ]] || return 1
  image_stat "${image}" /root/.ssh | grep -Eq 'Mode: +0700' || return 1
  image_stat "${image}" /root/.ssh/authorized_keys | grep -Eq 'Mode: +0600' || return 1
  image_stat "${image}" /usr/lib/systemd/systemd | grep -q '^Inode:' || return 1
  image_stat "${image}" /usr/sbin/init | grep -q 'Fast link dest:.*systemd' || return 1
  image_stat "${image}" /etc/systemd/system/multi-user.target.wants/networking.service |
    grep -q 'Type: symlink' || return 1
  image_stat "${image}" /etc/systemd/system/multi-user.target.wants/ssh.service |
    grep -q 'Type: symlink' || return 1
  image_stat "${image}" /usr/lib/systemd/system/sysinit.target.wants/systemd-udev-trigger.service |
    grep -q 'Type: symlink' || return 1
  image_cat "${image}" /usr/lib/systemd/system/systemd-udev-trigger.service |
    grep -Eq '^ExecStart=.*udevadm trigger .*--action=add' || return 1
}

if [[ -e "${IMAGE}" ]]; then
  if ! validate_image "${IMAGE}" "${KEY}"; then
    echo "existing usbautopm image failed validation; refusing to overwrite: ${IMAGE}" >&2
    exit 1
  fi
  echo "verified existing usbautopm rootfs; skipping build: ${IMAGE}"
  exit 0
fi
if [[ -e "${KEY}" || -e "${KEY}.pub" ]]; then
  echo "output keys already exist without an image; use an empty output directory" >&2
  exit 1
fi

ROOT=()
if (( EUID != 0 )); then
  ROOT=(sudo)
  sudo -v
fi

# A stale or dead proxy endpoint is worse than none,
# because debootstrap skips its own auto-detection when http_proxy is merely
# set (not unset). Proxy use is therefore opt-in via ROOTFS_USE_PROXY.
unset http_proxy https_proxy all_proxy
unset HTTP_PROXY HTTPS_PROXY ALL_PROXY
if [[ -n "${ROOTFS_USE_PROXY:-}" ]]; then
  export http_proxy="${ROOTFS_USE_PROXY}" https_proxy="${ROOTFS_USE_PROXY}"
fi
PROXY=()
for name in http_proxy https_proxy all_proxy no_proxy; do
  if [[ -n "${!name:-}" ]]; then
    PROXY+=("${name}=${!name}")
  fi
done

TMP="$(mktemp -d "${ROOTFS_DIR}/.build.XXXXXX")"
MNT="${TMP}/mnt"
BUILD_IMAGE="${TMP}/rootfs.img"
LOOPDEV=""
mkdir -p "${MNT}"

release_mounts() {
  local path
  for path in "${MNT}/sys" "${MNT}/proc" "${MNT}/dev/pts" "${MNT}/dev" "${MNT}"; do
    if mountpoint -q "${path}"; then
      "${ROOT[@]}" umount "${path}" || return 1
    fi
  done
  if [[ -n "${LOOPDEV}" ]]; then
    "${ROOT[@]}" losetup -d "${LOOPDEV}" || return 1
    LOOPDEV=""
  fi
}

cleanup() {
  local status=$?
  trap - EXIT
  if ! release_mounts; then
    echo "cleanup failed; build files retained at ${TMP}" >&2
    exit 1
  fi
  if [[ "${TMP}" == "${ROOTFS_DIR}"/.build.* ]]; then
    "${ROOT[@]}" rm -rf -- "${TMP}"
  fi
  exit "${status}"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

cat >"${TMP}/wgetrc" <<'WGET'
timeout = 30
tries = 10
retry_on_http_error = 429,500,502,503,504
wait_retry = 2
WGET

# Verify the target release before allocating or mounting an image. A readable
# host keyring may still be too old (e.g. Ubuntu jammy lacks bookworm keys).
for tool in wget gpgv dpkg-deb sha256sum; do
  if ! command -v "${tool}" >/dev/null; then
    echo "missing required command: ${tool}" >&2
    exit 1
  fi
done
mkdir -m 700 "${TMP}/gnupg"
if ! env WGETRC="${TMP}/wgetrc" wget -nv -O "${TMP}/InRelease" \
  "${MIRROR%/}/dists/${SUITE}/InRelease"; then
  echo "could not download ${SUITE} release metadata from ${MIRROR}" >&2
  exit 1
fi

KEYRING=/usr/share/keyrings/debian-archive-keyring.gpg
verify_release() {
  gpgv --homedir "${TMP}/gnupg" --keyring "${KEYRING}" "${TMP}/InRelease" \
    >"${TMP}/keyring-check.log" 2>&1
}

if [[ ! -r "${KEYRING}" ]] || ! verify_release; then
  echo "host Debian keyring is missing or cannot verify ${SUITE}; downloading an updated keyring"
  # Pin the package and its SHA256, published by Debian at:
  # https://packages.debian.org/trixie/all/debian-archive-keyring/download
  # Extract only; do not install it or change the host's apt sources.
  KEYRING_PACKAGE=debian-archive-keyring_2025.1_all.deb
  KEYRING_SHA256=9ea7778e443144ca490668737a8ab22dd3e748bb99e805e22ec055abeb3c7fac
  if ! env WGETRC="${TMP}/wgetrc" wget --https-only -nv -O "${TMP}/${KEYRING_PACKAGE}" \
    "https://deb.debian.org/debian/pool/main/d/debian-archive-keyring/${KEYRING_PACKAGE}"; then
    echo "could not download the updated Debian keyring" >&2
    exit 1
  fi
  if ! (cd "${TMP}" && printf '%s  %s\n' "${KEYRING_SHA256}" "${KEYRING_PACKAGE}" | sha256sum -c -); then
    echo "Debian keyring package checksum verification failed" >&2
    exit 1
  fi
  dpkg-deb -x "${TMP}/${KEYRING_PACKAGE}" "${TMP}/keyring"
  KEYRING="${TMP}/keyring/usr/share/keyrings/debian-archive-keyring.gpg"
  if ! verify_release; then
    cat "${TMP}/keyring-check.log" >&2
    echo "updated Debian keyring cannot verify ${SUITE}; check the suite and mirror" >&2
    exit 1
  fi
fi
echo "verified ${SUITE} release signature with ${KEYRING}"

truncate -s 8G "${BUILD_IMAGE}"
mkfs.ext4 -F "${BUILD_IMAGE}"
LOOPDEV="$("${ROOT[@]}" losetup --find --show "${BUILD_IMAGE}")"
"${ROOT[@]}" mount "${LOOPDEV}" "${MNT}"
# Install the init system and udev during bootstrap, before mounting the
# private /dev used for the remaining package installation.
"${ROOT[@]}" env "${PROXY[@]}" WGETRC="${TMP}/wgetrc" \
  debootstrap --force-check-gpg --keyring="${KEYRING}" --variant=minbase --arch=amd64 \
  --include=systemd-sysv,udev \
  "${SUITE}" "${MNT}" "${MIRROR}"
rootfs_mount_dev "${MNT}" "${ROOT[@]}"
"${ROOT[@]}" mount -t proc proc "${MNT}/proc"
"${ROOT[@]}" mount -t sysfs sysfs "${MNT}/sys"

# Do not start guest services inside the build chroot.
printf '#!/bin/sh\nexit 101\n' | "${ROOT[@]}" tee "${MNT}/usr/sbin/policy-rc.d" >/dev/null
"${ROOT[@]}" chmod 755 "${MNT}/usr/sbin/policy-rc.d"
"${ROOT[@]}" chroot "${MNT}" env "${PROXY[@]}" DEBIAN_FRONTEND=noninteractive \
  apt-get -o Acquire::Retries=5 -o Acquire::http::Timeout=30 update
# Retry transient proxy errors while keeping this fresh build's package cache.
for attempt in 1 2 3; do
  # shellcheck disable=SC2086
  if "${ROOT[@]}" chroot "${MNT}" env "${PROXY[@]}" DEBIAN_FRONTEND=noninteractive \
    apt-get -o Acquire::Retries=5 -o Acquire::http::Timeout=30 install -y --no-install-recommends ${PACKAGES}; then
    break
  fi
  if (( attempt == 3 )); then exit 1; fi
  sleep 3
done

printf 'root:root\n' | "${ROOT[@]}" chroot "${MNT}" chpasswd
printf 'platform\n' | "${ROOT[@]}" tee "${MNT}/etc/hostname" >/dev/null
printf '127.0.0.1 localhost platform\n' | "${ROOT[@]}" tee "${MNT}/etc/hosts" >/dev/null
printf '/dev/vda / ext4 defaults 0 1\n' | "${ROOT[@]}" tee "${MNT}/etc/fstab" >/dev/null
"${ROOT[@]}" tee "${MNT}/etc/network/interfaces" >/dev/null <<'NETWORK'
auto lo
iface lo inet loopback

auto eth0
iface eth0 inet static
    address 10.0.2.15
    netmask 255.255.255.0
    gateway 10.0.2.2
NETWORK

ssh-keygen -q -t ed25519 -N "" -C rootfs-usbautopm -f "${TMP}/id_rsa"
"${ROOT[@]}" install -d -m 700 "${MNT}/root/.ssh"
"${ROOT[@]}" install -m 600 "${TMP}/id_rsa.pub" "${MNT}/root/.ssh/authorized_keys"
"${ROOT[@]}" chown -R root:root "${MNT}/root/.ssh"
"${ROOT[@]}" sed -i '/^[#[:space:]]*PermitRootLogin[[:space:]]/d' "${MNT}/etc/ssh/sshd_config"
printf '\nPermitRootLogin yes\n' | "${ROOT[@]}" tee -a "${MNT}/etc/ssh/sshd_config" >/dev/null
# Runtime autosuspend must be armed before usbnet_open() drops its PM reference.
"${ROOT[@]}" install -d "${MNT}/etc/udev/rules.d"
printf '%s\n' "${RULE}" | "${ROOT[@]}" tee "${MNT}${RULE_FILE}" >/dev/null
printf '%s\n' "${NET_RULE}" | "${ROOT[@]}" tee "${MNT}${NET_RULE_FILE}" >/dev/null
# udev runs RUN+= helpers synchronously; the interface already exists when the
# net add event fires, so the helper only has to configure it.
"${ROOT[@]}" install -d -m 755 "${MNT}/usr/local/sbin"
printf '%s\n' "${HELPER}" | "${ROOT[@]}" tee "${MNT}${HELPER_PATH}" >/dev/null
"${ROOT[@]}" chmod 755 "${MNT}${HELPER_PATH}"
"${ROOT[@]}" chroot "${MNT}" systemctl enable networking.service ssh.service
"${ROOT[@]}" chroot "${MNT}" systemctl set-default multi-user.target

# The udev package ships this static coldplug dependency; do not enable it.
"${ROOT[@]}" test -L "${MNT}/lib/systemd/system/sysinit.target.wants/systemd-udev-trigger.service"
"${ROOT[@]}" test -e "${MNT}/lib/systemd/system/systemd-udev-trigger.service"
"${ROOT[@]}" rm "${MNT}/usr/sbin/policy-rc.d"
"${ROOT[@]}" chroot "${MNT}" apt-get clean
"${ROOT[@]}" sync
release_mounts

if ! validate_image "${BUILD_IMAGE}" "${TMP}/id_rsa"; then
  echo "created usbautopm image failed static validation" >&2
  exit 1
fi
# Publish the image last, only after unmounting and validating it.
mv "${TMP}/id_rsa" "${KEY}"
mv "${TMP}/id_rsa.pub" "${KEY}.pub"
mv "${BUILD_IMAGE}" "${IMAGE}"
echo "created and statically verified usbautopm rootfs: ${IMAGE}"
echo "ssh key: ${KEY}"
