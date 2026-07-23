from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .metadata import Vulnerability

DEFAULT_RUNTIME_PROFILES = Path(__file__).resolve().parents[2] / "configs" / "vulnerabilities.json"


class RuntimeProfileError(ValueError):
    pass


@dataclass(frozen=True)
class RootfsProfile:
    image: str
    ssh_key: str
    ssh_user: str = "root"


@dataclass(frozen=True)
class RuntimeProfile:
    build_env: dict[str, str] = field(default_factory=dict)
    make_args: list[str] = field(default_factory=list)
    qemu_append: list[str] = field(default_factory=list)
    qemu_args: list[str] = field(default_factory=list)
    repro_env: dict[str, str] = field(default_factory=dict)
    execprog_args: list[str] = field(default_factory=list)
    rootfs: RootfsProfile | None = None

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
        build_env=_string_map(raw_profile, "build_env"),
        make_args=_string_list(raw_profile, "make_args"),
        qemu_append=_string_list(raw_profile, "qemu_append"),
        qemu_args=_string_list(raw_profile, "qemu_args"),
        repro_env=_string_map(raw_profile, "repro_env"),
        execprog_args=_string_list(raw_profile, "execprog_args"),
        rootfs=_rootfs_profile(raw_profile),
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
    if not isinstance(value, list):
        raise RuntimeProfileError(f"runtime profile field '{key}' must be a list")
    if not all(isinstance(item, str) for item in value):
        raise RuntimeProfileError(f"runtime profile field '{key}' must contain only strings")
    return list(value)


def _rootfs_profile(raw: dict[str, Any]) -> RootfsProfile | None:
    value = raw.get("rootfs")
    if value is None:
        return None
    if not isinstance(value, dict):
        raise RuntimeProfileError("runtime profile field 'rootfs' must be an object")

    allowed = {"image", "ssh_key", "ssh_user"}
    unknown = sorted(set(value) - allowed)
    if unknown:
        raise RuntimeProfileError(f"runtime profile field 'rootfs' contains unknown fields: {', '.join(unknown)}")

    image = _required_nonempty_string(value, "rootfs.image")
    ssh_key = _required_nonempty_string(value, "rootfs.ssh_key")
    ssh_user = value.get("ssh_user", "root")
    if not isinstance(ssh_user, str) or not ssh_user.strip():
        raise RuntimeProfileError("runtime profile field 'rootfs.ssh_user' must be a non-empty string")
    return RootfsProfile(image=image, ssh_key=ssh_key, ssh_user=ssh_user)


def _required_nonempty_string(raw: dict[str, Any], field: str) -> str:
    key = field.rsplit(".", 1)[-1]
    value = raw.get(key)
    if not isinstance(value, str) or not value.strip():
        raise RuntimeProfileError(f"runtime profile field '{field}' must be a non-empty string")
    return value
