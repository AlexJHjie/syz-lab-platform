from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

from ..metadata import Vulnerability


@dataclass(frozen=True)
class Verdict:
    status: str
    matched: str | None
    reason: str
    source_log: str | None = None


KERNEL_WARNING_PATTERN = r"WARNING:(?=\s+(?:CPU:\s+\d+(?:\s+PID:\s+\d+)?\s+)?at\b)"

CRASH_PATTERNS = [
    r"BUG:\s+(?:KASAN|KMSAN):",
    KERNEL_WARNING_PATTERN,
    r"kernel BUG",
    r"general protection fault",
    r"INFO: task .* blocked",
    r"INFO: rcu detected stalls",
    r"Kernel panic",
    r"panic:",
    r"Oops:",
    r"BUG:",
]

REPORT_TYPES = {
    "MEMORY_LEAK": r"BUG:\s+memory leak\b",
    "WARNING": KERNEL_WARNING_PATTERN,
    "KASAN": r"(?:BUG:\s+)?KASAN:",
    "KMSAN": r"(?:BUG:\s+)?KMSAN:",
    "BUG": r"(?:kernel )?BUG(?::|\b)",
    "OOPS": r"Oops:",
    "PANIC": r"(?:Kernel panic|panic:)",
    "GPF": r"general protection fault",
}

TITLE_REPORT_TYPES = {
    "MEMORY_LEAK": r"\bmemory leak\b",
    "WARNING": r"\bWARNING\b",
    "KASAN": r"\bKASAN\b",
    "KMSAN": r"\bKMSAN\b",
    "BUG": r"\bBUG\b",
    "OOPS": r"\bOops\b",
    "PANIC": r"\bpanic\b",
    "GPF": r"general protection fault",
}

LOG_NAMES = ("qemu.log", "repro.log")


def classify(vuln: Vulnerability, logs_dir: Path) -> Verdict:
    verdicts = [
        classify_text(vuln, path.read_text(encoding="utf-8", errors="replace"), source_log=name)
        for name in LOG_NAMES
        if (path := logs_dir / name).exists()
    ]
    for status in ("reproduced", "crashed_other"):
        matched = next((verdict for verdict in verdicts if verdict.status == status), None)
        if matched:
            return matched
    return Verdict(status="not_reproduced", matched=None, reason="no known crash signature found")


def classify_text(vuln: Vulnerability, text: str, *, source_log: str | None = None) -> Verdict:
    candidates = [vuln.title, vuln.display_title, vuln.crash.title or ""]
    for candidate in candidates:
        normalized = candidate.strip()
        if normalized and normalized in text:
            return Verdict(
                status="reproduced",
                matched=normalized,
                reason="matched crash title",
                source_log=source_log,
            )

    for candidate in candidates:
        signature = _title_signature(candidate)
        if signature and _matches_signature(text, *signature):
            report_type, function = signature
            return Verdict(
                status="reproduced",
                matched=_format_signature(report_type, function),
                reason="matched crash report type and function",
                source_log=source_log,
            )

    for pattern in CRASH_PATTERNS:
        match = re.search(pattern, text, flags=re.IGNORECASE)
        if match:
            return Verdict(
                status="crashed_other",
                matched=match.group(0),
                reason="kernel crash pattern found",
                source_log=source_log,
            )

    return Verdict(
        status="not_reproduced",
        matched=None,
        reason="no known crash signature found",
        source_log=source_log,
    )


def has_crash(text: str) -> bool:
    return any(re.search(pattern, text, flags=re.IGNORECASE) for pattern in CRASH_PATTERNS)


def _title_signature(title: str) -> tuple[str, str] | None:
    if not title:
        return None
    report_type = next(
        (name for name, pattern in TITLE_REPORT_TYPES.items() if re.search(pattern, title, flags=re.IGNORECASE)),
        None,
    )
    function_match = re.search(r"\bin\s+([A-Za-z_][A-Za-z0-9_.]*)", title, flags=re.IGNORECASE)
    if not report_type or not function_match:
        return None
    return report_type, function_match.group(1)


def _matches_signature(text: str, report_type: str, function: str) -> bool:
    type_pattern = REPORT_TYPES[report_type]
    lines = text.splitlines()
    for index, line in enumerate(lines):
        if not re.search(type_pattern, line, flags=re.IGNORECASE):
            continue
        crash_block = "\n".join(lines[index : index + 120])
        if re.search(rf"\b{re.escape(function)}(?:\+0x[0-9a-f]+)?\b", crash_block, flags=re.IGNORECASE):
            return True
    return False


def _format_signature(report_type: str, function: str) -> str:
    if report_type == "MEMORY_LEAK":
        return f"memory leak in {function}"
    return f"{report_type} in {function}"
