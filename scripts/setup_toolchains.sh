#!/usr/bin/env bash
set -euo pipefail

PROJECT_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
MANIFEST="${PLATFORM_TOOLCHAIN_MANIFEST:-${PROJECT_ROOT}/configs/toolchains.lock.json}"
TOOLCHAINS_DIR="${PLATFORM_TOOLCHAINS_DIR:-${PROJECT_ROOT}/toolchains}"
DOWNLOAD_DIR="${TOOLCHAINS_DIR}/.downloads"

usage() {
  cat <<'EOF'
Usage:
  ./scripts/setup_toolchains.sh [toolchain-key ...]

Install all toolchains from configs/toolchains.lock.json, or only the specified
keys. Existing installations with matching compiler/binutils versions are
skipped.

Environment:
  PLATFORM_TOOLCHAIN_MANIFEST  Use another lock manifest.
  PLATFORM_TOOLCHAINS_DIR      Override the installation directory.
EOF
}

die() {
  echo "error: $*" >&2
  exit 1
}

for command in python3 curl sha256sum tar; do
  command -v "${command}" >/dev/null 2>&1 || die "required command is not installed: ${command}"
done

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
  usage
  exit 0
fi

[[ -f "${MANIFEST}" ]] || die "toolchain manifest does not exist: ${MANIFEST}"
mkdir -p "${TOOLCHAINS_DIR}" "${DOWNLOAD_DIR}"

REQUESTED_KEYS=("$@")
RECORDS="$(
  python3 - "${MANIFEST}" "${REQUESTED_KEYS[@]}" <<'PY'
import json
import re
import sys
from pathlib import Path

manifest_path = Path(sys.argv[1])
requested = sys.argv[2:]
try:
    data = json.loads(manifest_path.read_text(encoding="utf-8"))
except (OSError, json.JSONDecodeError) as exc:
    raise SystemExit(f"cannot read manifest {manifest_path}: {exc}")

if data.get("schema_version") != 1 or not isinstance(data.get("toolchains"), list):
    raise SystemExit("manifest must contain schema_version 1 and a toolchains array")

entries = {}
for entry in data["toolchains"]:
    if not isinstance(entry, dict):
        raise SystemExit("each toolchain entry must be an object")
    key = entry.get("key")
    if not isinstance(key, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._+-]*", key):
        raise SystemExit(f"invalid toolchain key: {key!r}")
    if key in entries:
        raise SystemExit(f"duplicate toolchain key: {key}")
    entries[key] = entry

selected = requested or list(entries)
unknown = [key for key in selected if key not in entries]
if unknown:
    raise SystemExit(
        "unknown toolchain key(s): "
        + ", ".join(unknown)
        + "; available: "
        + ", ".join(entries)
    )

for key in selected:
    entry = entries[key]
    values = [
        key,
        entry.get("compiler", ""),
        entry.get("compiler_version", ""),
        entry.get("binutils_version", ""),
        entry.get("url", ""),
        entry.get("sha256", ""),
    ]
    if any(not isinstance(value, str) for value in values):
        raise SystemExit(f"manifest fields for {key} must be strings")
    if any("\t" in value or "\n" in value for value in values):
        raise SystemExit(f"manifest fields for {key} cannot contain tabs or newlines")
    print("\t".join(values))
PY
)" || die "failed to parse toolchain manifest"

[[ -n "${RECORDS}" ]] || die "no toolchains are configured in ${MANIFEST}"

install_toolchain() {
  local key="$1"
  local compiler="$2"
  local compiler_version="$3"
  local binutils_version="$4"
  local url="$5"
  local expected_sha256="$6"
  local target="${TOOLCHAINS_DIR}/${key}"
  local compiler_path="${target}/bin/${compiler}"

  [[ -n "${compiler}" && -n "${compiler_version}" ]] ||
    die "manifest entry ${key} is missing compiler or compiler_version"

  if [[ -x "${compiler_path}" ]]; then
    local installed_compiler_version
    installed_compiler_version="$("${compiler_path}" -dumpfullversion 2>/dev/null || true)"
    if [[ "${installed_compiler_version}" == "${compiler_version}" ]]; then
      if [[ -z "${binutils_version}" ]]; then
        echo "already installed: ${key}"
        return
      fi
      local installed_binutils_version
      installed_binutils_version="$(
        "${target}/bin/ld" --version 2>/dev/null |
          head -n 1 |
          grep -oE '[0-9]+\.[0-9]+(\.[0-9]+)?' |
          head -n 1 || true
      )"
      if [[ "${installed_binutils_version}" == "${binutils_version}" ]]; then
        echo "already installed: ${key}"
        return
      fi
    fi
    die "existing directory has a version mismatch: ${target}; move or remove it before reinstalling"
  fi
  [[ ! -e "${target}" ]] ||
    die "existing incomplete toolchain directory: ${target}; move or remove it before reinstalling"

  [[ "${expected_sha256}" =~ ^[0-9a-fA-F]{64}$ ]] ||
    die "manifest entry ${key} has no valid sha256; publish the archive and update ${MANIFEST}"
  case "${url}" in
    https://*|file://*) ;;
    "")
      die "manifest entry ${key} has no URL; publish the archive and update ${MANIFEST}"
      ;;
    *)
      die "manifest entry ${key} uses an unsafe URL (only https:// and file:// are accepted): ${url}"
      ;;
  esac

  local archive_name="${key}.tar"
  case "${url}" in
    *.tar.gz|*.tgz) archive_name="${key}.tar.gz" ;;
    *.tar.xz) archive_name="${key}.tar.xz" ;;
    *.tar.zst) archive_name="${key}.tar.zst" ;;
  esac
  local archive="${DOWNLOAD_DIR}/${archive_name}"
  local partial="${archive}.partial"

  if [[ -f "${archive}" ]] &&
    echo "${expected_sha256}  ${archive}" | sha256sum --check --status; then
    echo "using cached archive: ${archive}"
  else
    rm -f -- "${archive}" "${partial}"
    echo "downloading ${key}"
    curl --fail --location --proto '=https,file' --tlsv1.2 --output "${partial}" "${url}"
    echo "${expected_sha256}  ${partial}" | sha256sum --check --status ||
      die "SHA256 mismatch for ${key}"
    mv -- "${partial}" "${archive}"
  fi

  local staging
  staging="$(mktemp -d "${TOOLCHAINS_DIR}/.${key}.install.XXXXXX")"
  trap 'rm -rf -- "${staging}" "${partial:-}"' RETURN

  local first_component
  first_component="$(
    tar -tf "${archive}" |
      awk -F/ 'NF && $1 != "." && $1 != "" { print $1 }' |
      sort -u
  )"
  [[ "${first_component}" == "${key}" ]] ||
    die "archive ${archive} must contain exactly one top-level directory named ${key}"
  tar -xf "${archive}" -C "${staging}"

  local extracted="${staging}/${key}"
  [[ -x "${extracted}/bin/${compiler}" ]] ||
    die "archive does not contain executable bin/${compiler}: ${archive}"
  local extracted_compiler_version
  extracted_compiler_version="$("${extracted}/bin/${compiler}" -dumpfullversion 2>/dev/null || true)"
  [[ "${extracted_compiler_version}" == "${compiler_version}" ]] ||
    die "compiler version mismatch in archive: expected ${compiler_version}, got ${extracted_compiler_version:-unknown}"

  if [[ -n "${binutils_version}" ]]; then
    local tool
    for tool in ld as ar nm objcopy objdump readelf strip addr2line; do
      [[ -x "${extracted}/bin/${tool}" ]] ||
        die "archive does not contain executable bin/${tool}: ${archive}"
    done
    local extracted_binutils_version
    extracted_binutils_version="$(
      "${extracted}/bin/ld" --version 2>/dev/null |
        head -n 1 |
        grep -oE '[0-9]+\.[0-9]+(\.[0-9]+)?' |
        head -n 1 || true
    )"
    [[ "${extracted_binutils_version}" == "${binutils_version}" ]] ||
      die "binutils version mismatch in archive: expected ${binutils_version}, got ${extracted_binutils_version:-unknown}"
  fi

  mv -- "${extracted}" "${target}"
  rm -rf -- "${staging}"
  trap - RETURN
  echo "installed: ${target}"
}

while IFS=$'\t' read -r key compiler compiler_version binutils_version url sha256; do
  install_toolchain "${key}" "${compiler}" "${compiler_version}" \
    "${binutils_version}" "${url}" "${sha256}"
done <<<"${RECORDS}"

echo "toolchain setup complete"
