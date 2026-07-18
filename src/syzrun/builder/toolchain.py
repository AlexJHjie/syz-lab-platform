from __future__ import annotations

import os
import re
import subprocess
from dataclasses import dataclass
from pathlib import Path


VERSION_PATTERN = r"\d+\.\d+(?:\.\d+)?"
KERNEL_BINUTIL_NAMES = ("ld", "as", "ar", "nm", "objcopy", "objdump", "readelf", "strip")
REQUIRED_BINUTIL_NAMES = (*KERNEL_BINUTIL_NAMES, "addr2line")
DEFAULT_TOOLCHAINS_DIR = Path(__file__).resolve().parents[3] / "toolchains"


class ToolchainError(RuntimeError):
    pass


@dataclass(frozen=True)
class BuildTarget:
    kernel_arch: str
    syzkaller_arch: str


@dataclass(frozen=True)
class ToolchainRequirement:
    compiler: str
    version: str
    binutils_version: str | None
    description: str

    @property
    def key(self) -> str:
        key = f"{self.compiler}-{self.version}"
        if self.binutils_version:
            key += f"-binutils-{self.binutils_version}"
        return key


@dataclass(frozen=True)
class Toolchain:
    requirement: ToolchainRequirement
    root: Path
    bin_dir: Path
    library_dir: Path | None
    cc: Path
    tools: dict[str, Path]

    def environment(self) -> dict[str, str]:
        env = {"PATH": os.pathsep.join([str(self.bin_dir), os.environ.get("PATH", "")])}
        if self.library_dir:
            libraries = [str(self.library_dir)]
            existing = os.environ.get("LD_LIBRARY_PATH")
            if existing:
                libraries.append(existing)
            env["LD_LIBRARY_PATH"] = os.pathsep.join(libraries)
        return env

    def tool(self, name: str) -> Path | None:
        return self.tools.get(name)

    def make_variables(self) -> list[str]:
        variables = [f"CC={self.cc}"]
        for name in KERNEL_BINUTIL_NAMES:
            executable = self.tool(name)
            if executable:
                variables.append(f"{name.upper()}={executable}")
        return variables


def target_from_arch(architecture: str) -> BuildTarget:
    arch = architecture.lower()
    if arch in {"amd64", "x86_64"}:
        return BuildTarget(kernel_arch="x86_64", syzkaller_arch="amd64")
    raise ValueError(f"unsupported architecture: {architecture}")


def make_jobs() -> str:
    return str(max(1, os.cpu_count() or 1))


def parse_toolchain_requirement(description: str) -> ToolchainRequirement:
    compiler_match = re.search(rf"\b(gcc|clang)\b.*?\b({VERSION_PATTERN})\b", description, re.IGNORECASE)
    if not compiler_match:
        raise ToolchainError(f"cannot parse compiler and strict version from compiler-description: {description}")
    binutils_match = re.search(
        rf"(?:GNU\s+ld|GNU\s+Binutils).*?\b({VERSION_PATTERN})\b",
        description,
        re.IGNORECASE,
    )
    return ToolchainRequirement(
        compiler=compiler_match.group(1).lower(),
        version=compiler_match.group(2),
        binutils_version=binutils_match.group(1) if binutils_match else None,
        description=description,
    )


def ensure_toolchain(
    description: str,
    *,
    toolchains_dir: Path = DEFAULT_TOOLCHAINS_DIR,
) -> Toolchain:
    requirement = parse_toolchain_requirement(description)
    target = toolchains_dir.resolve() / requirement.key
    if not target.is_dir():
        raise ToolchainError(_missing_toolchain_message(requirement, target))

    bin_dir = target / "bin"
    library_dir = target / "lib"
    compiler = bin_dir / requirement.compiler
    if not compiler.is_file() or not os.access(compiler, os.X_OK):
        raise ToolchainError(
            f"required compiler entry does not exist: {compiler}. "
            f"Please place {requirement.compiler} {requirement.version} at this exact path"
        )
    effective_library_dir = library_dir if library_dir.is_dir() else None
    actual_version = _compiler_version(compiler, effective_library_dir)
    if actual_version != requirement.version:
        raise ToolchainError(
            f"compiler version mismatch at {compiler}: expected {requirement.version}, got {actual_version}"
        )
    tools = _check_binutils(bin_dir, requirement, effective_library_dir)
    return Toolchain(
        requirement=requirement,
        root=target,
        bin_dir=bin_dir,
        library_dir=effective_library_dir,
        cc=compiler,
        tools=tools,
    )


def _missing_toolchain_message(requirement: ToolchainRequirement, target: Path) -> str:
    compiler_entry = target / "bin" / requirement.compiler
    lines = [
        f"required toolchain is not installed: {requirement.key}",
        f"compiler-description: {requirement.description}",
        "Please download and prepare:",
        f"  - {requirement.compiler} {requirement.version}",
    ]
    if requirement.binutils_version:
        lines.append(f"  - GNU binutils {requirement.binutils_version}")
    else:
        lines.append("  - binutils: not versioned by compiler-description; system binutils may be used")
    lines.extend(
        [
            f"target directory: {target}",
            "required layout:",
            f"  {compiler_entry}",
        ]
    )
    if requirement.binutils_version:
        lines.extend(f"  {target / 'bin' / name}" for name in REQUIRED_BINUTIL_NAMES)
    lines.extend(
        [
            f"  {target / 'lib'}  (optional runtime libraries)",
            "Real executables or relative symlinks are both accepted.",
            "If this toolchain is published in configs/toolchains.lock.json, "
            f"run: ./scripts/setup_toolchains.sh {requirement.key}",
            f"Version check: {compiler_entry} -dumpfullversion",
        ]
    )
    if requirement.binutils_version:
        lines.append(f"Version check: {target / 'bin' / 'ld'} --version")
    return "\n".join(lines)


def _check_binutils(
    bin_dir: Path,
    requirement: ToolchainRequirement,
    library_dir: Path | None,
) -> dict[str, Path]:
    tools: dict[str, Path] = {}
    names = REQUIRED_BINUTIL_NAMES if requirement.binutils_version else KERNEL_BINUTIL_NAMES
    for name in names:
        candidate = bin_dir / name
        if candidate.is_file() and os.access(candidate, os.X_OK):
            tools[name] = candidate
        elif requirement.binutils_version:
            raise ToolchainError(
                f"required binutils entry does not exist: {candidate}. "
                f"Please place binutils {requirement.binutils_version} tools in {bin_dir}"
            )
    if requirement.binutils_version:
        actual_version = _program_version(tools["ld"], library_dir)
        if actual_version != requirement.binutils_version:
            raise ToolchainError(
                f"binutils version mismatch at {tools['ld']}: "
                f"expected {requirement.binutils_version}, got {actual_version}"
            )
    return tools


def _compiler_version(executable: Path, library_dir: Path | None) -> str:
    output = _run_version_command(executable, ["-dumpfullversion"], library_dir)
    if re.fullmatch(VERSION_PATTERN, output):
        return output
    output = _run_version_command(executable, ["--version"], library_dir)
    match = re.search(VERSION_PATTERN, output)
    return match.group(0) if match else "unknown"


def _program_version(executable: Path, library_dir: Path | None) -> str:
    output = _run_version_command(executable, ["--version"], library_dir)
    match = re.search(VERSION_PATTERN, output)
    return match.group(0) if match else "unknown"


def _run_version_command(executable: Path, args: list[str], library_dir: Path | None) -> str:
    env = os.environ.copy()
    if library_dir:
        env["LD_LIBRARY_PATH"] = str(library_dir)
    try:
        result = subprocess.run(
            [str(executable), *args],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            env=env,
        )
    except (OSError, subprocess.CalledProcessError):
        return "unknown"
    return result.stdout.strip()
