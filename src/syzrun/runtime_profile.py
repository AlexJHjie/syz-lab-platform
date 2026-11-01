from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .metadata import Vulnerability
from .repro.verdict import CrashTargetConfig

DEFAULT_RUNTIME_PROFILES = Path(__file__).resolve().parents[2] / "configs" / "vulnerabilities.json"


class RuntimeProfileError(ValueError):
    pass


@dataclass(frozen=True)
class RootfsProfile:
    image: str
    ssh_key: str
    ssh_user: str = "root"
    interface: str = "virtio"
    root_device: str = "/dev/vda"


@dataclass(frozen=True)
class RuntimeProfile:
    kernel_build_image: str | None = None
    build_env: dict[str, str] = field(default_factory=dict)
    make_args: list[str] = field(default_factory=list)
    qemu_append: list[str] = field(default_factory=list)
    qemu_args: list[str] = field(default_factory=list)
    repro_env: dict[str, str] = field(default_factory=dict)
    execprog_args: list[str] = field(default_factory=list)
    rootfs: RootfsProfile | None = None
    repro_timeout: int = 2 * 60
    target_crash: CrashTargetConfig | None = None

    @classmethod
    def empty(cls) -> "RuntimeProfile":
        return cls()


def load_runtime_profile(vuln: Vulnerability, config_path: Path = DEFAULT_RUNTIME_PROFILES) -> RuntimeProfile:
    if not config_path.exists():
        return RuntimeProfile.empty()

    try:
        data = json.loads(config_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise RuntimeProfileError(f"invalid runtime profile JSON: {config_path}: {exc}") from exc

    if not isinstance(data, dict):
        raise RuntimeProfileError(f"runtime profile root must be an object: {config_path}")

    vulnerabilities = data.get("vulnerabilities", {})
    if not isinstance(vulnerabilities, dict):
        raise RuntimeProfileError("runtime profile field 'vulnerabilities' must be an object")

    raw_profile = vulnerabilities.get(vuln.vuln_id)
    if raw_profile is None:
        return RuntimeProfile.empty()
    if not isinstance(raw_profile, dict):
        raise RuntimeProfileError(f"runtime profile for {vuln.vuln_id} must be an object")

    return RuntimeProfile(
        kernel_build_image=_optional_nonempty_string(raw_profile, "kernel-build-image"),
        build_env=_string_map(raw_profile, "build_env"),
        make_args=_string_list(raw_profile, "make_args"),
        qemu_append=_string_list(raw_profile, "qemu_append"),
        qemu_args=_string_list(raw_profile, "qemu_args"),
        repro_env=_string_map(raw_profile, "repro_env"),
        execprog_args=_string_list(raw_profile, "execprog_args"),
        repro_timeout=_positive_int(raw_profile, "repro_timeout", default=2 * 60),
        rootfs=_rootfs_profile(raw_profile),
        target_crash=_target_crash_profile(raw_profile),
    )


def _string_map(raw: dict[str, Any], key: str) -> dict[str, str]:
    value = raw.get(key, {})
    if not isinstance(value, dict):
        raise RuntimeProfileError(f"runtime profile field '{key}' must be an object")
    result: dict[str, str] = {}
    for item_key, item_value in value.items():
        if not isinstance(item_key, str) or not isinstance(item_value, str):
            raise RuntimeProfileError(f"runtime profile field '{key}' must contain string keys and values")
        result[item_key] = item_value
    return result


def _string_list(raw: dict[str, Any], key: str) -> list[str]:
    value = raw.get(key, [])
    if isinstance(value, str):
        return [value]
    if not isinstance(value, list):
        raise RuntimeProfileError(f"runtime profile field '{key}' must be a string or a list")
    if not all(isinstance(item, str) for item in value):
        raise RuntimeProfileError(f"runtime profile field '{key}' must contain only strings")
    return list(value)


def _positive_int(raw: dict[str, Any], key: str, *, default: int) -> int:
    value = raw.get(key, default)
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        raise RuntimeProfileError(f"runtime profile field '{key}' must be a positive integer")
    return value


def _rootfs_profile(raw: dict[str, Any]) -> RootfsProfile | None:
    value = raw.get("rootfs")
    if value is None:
        return None
    if not isinstance(value, dict):
        raise RuntimeProfileError("runtime profile field 'rootfs' must be an object")

    allowed = {"image", "ssh_key", "ssh_user", "interface", "root_device"}
    unknown = sorted(set(value) - allowed)
    if unknown:
        raise RuntimeProfileError(f"runtime profile field 'rootfs' contains unknown fields: {', '.join(unknown)}")

    image = _required_nonempty_string(value, "rootfs.image")
    ssh_key = _required_nonempty_string(value, "rootfs.ssh_key")
    ssh_user = value.get("ssh_user", "root")
    if not isinstance(ssh_user, str) or not ssh_user.strip():
        raise RuntimeProfileError("runtime profile field 'rootfs.ssh_user' must be a non-empty string")
    interface = value.get("interface", "virtio")
    if interface not in {"virtio", "scsi"}:
        raise RuntimeProfileError("runtime profile field 'rootfs.interface' must be 'virtio' or 'scsi'")
    root_device = value.get("root_device", "/dev/vda")
    if not isinstance(root_device, str) or not root_device.strip():
        raise RuntimeProfileError("runtime profile field 'rootfs.root_device' must be a non-empty string")
    return RootfsProfile(
        image=image,
        ssh_key=ssh_key,
        ssh_user=ssh_user,
        interface=interface,
        root_device=root_device,
    )


def _target_crash_profile(raw: dict[str, Any]) -> CrashTargetConfig | None:
    value = raw.get("target_crash")
    if value is None:
        return None
    if not isinstance(value, dict):
        raise RuntimeProfileError("runtime profile field 'target_crash' must be an object")

    allowed = {"report_types", "subtypes", "functions", "match"}
    unknown = sorted(set(value) - allowed)
    if unknown:
        raise RuntimeProfileError(
            "runtime profile field 'target_crash' contains unknown fields: " + ", ".join(unknown)
        )

    report_types = _required_string_list(value, "target_crash.report_types")
    subtypes = _optional_string_list(value, "subtypes")
    functions = _optional_string_list(value, "functions")
    match = value.get("match", "any")
    if match not in {"any", "all"}:
        raise RuntimeProfileError("runtime profile field 'target_crash.match' must be 'any' or 'all'")
    return CrashTargetConfig(
        report_types=tuple(report_types),
        subtypes=tuple(subtypes),
        functions=tuple(functions),
        match_all_functions=match == "all",
    )


def _required_string_list(raw: dict[str, Any], field: str) -> list[str]:
    key = field.rsplit(".", 1)[-1]
    value = raw.get(key)
    if (
        not isinstance(value, list)
        or not value
        or not all(isinstance(item, str) and item.strip() for item in value)
    ):
        raise RuntimeProfileError(f"runtime profile field '{field}' must be a non-empty string list")
    return list(value)


def _optional_string_list(raw: dict[str, Any], key: str) -> list[str]:
    value = raw.get(key, [])
    if not isinstance(value, list) or not all(isinstance(item, str) and item.strip() for item in value):
        raise RuntimeProfileError(f"runtime profile field 'target_crash.{key}' must be a string list")
    return list(value)


def _required_nonempty_string(raw: dict[str, Any], field: str) -> str:
    key = field.rsplit(".", 1)[-1]
    value = raw.get(key)
    if not isinstance(value, str) or not value.strip():
        raise RuntimeProfileError(f"runtime profile field '{field}' must be a non-empty string")
    return value


def _optional_nonempty_string(raw: dict[str, Any], key: str) -> str | None:
    if key not in raw:
        return None
    value = raw[key]
    if not isinstance(value, str) or not value.strip():
        raise RuntimeProfileError(f"runtime profile field '{key}' must be a non-empty string")
    return value
