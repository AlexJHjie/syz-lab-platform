from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path


@dataclass(frozen=True)
class CrashFingerprint:
    report_type: str
    subtype: str | None
    functions: tuple[str, ...]


@dataclass(frozen=True)
class CrashReport:
    text: str
    fingerprint: CrashFingerprint


@dataclass(frozen=True)
class Verdict:
    status: str
    matched: str | None
    reason: str
    source_log: str | None = None
    report: str | None = field(default=None, repr=False, compare=False)


PREFIX = r"^\s*(?:\[[^\]\r\n]*\]\s*)*"
REPORT_STARTS = (
    ("MEMORY_LEAK", re.compile(PREFIX + r"BUG:\s+memory leak\b", re.I)),
    ("KASAN", re.compile(PREFIX + r"BUG:\s+KASAN:", re.I)),
    ("KMSAN", re.compile(PREFIX + r"BUG:\s+KMSAN:", re.I)),
    ("WARNING", re.compile(PREFIX + r"WARNING:(?=\s+(?:CPU:\s+\d+(?:\s+PID:\s+\d+)?\s+)?at\b)", re.I)),
    ("GPF", re.compile(PREFIX + r"(?:BUG:\s+GPF\b|general protection fault(?:\b|:))", re.I)),
    ("HUNG_TASK", re.compile(PREFIX + r"INFO:\s+task .+ blocked for more than\b", re.I)),
    ("RCU_STALL", re.compile(PREFIX + r"INFO:\s+rcu(?:_[a-z]+)? detected stalls\b", re.I)),
    ("SOFT_LOCKUP", re.compile(PREFIX + r"(?:watchdog:\s+)?BUG:\s+soft lockup\b", re.I)),
    ("OOPS", re.compile(PREFIX + r"Oops:", re.I)),
    ("PANIC", re.compile(PREFIX + r"(?:Kernel panic - not syncing:|panic:)", re.I)),
    ("BUG", re.compile(PREFIX + r"(?:kernel BUG at\b|BUG:)", re.I)),
)
REPORT_END = re.compile(r"(?:---\[\s*end (?:trace|Kernel panic)\b.*\]---|Rebooting in\b)", re.I)
SEPARATOR = re.compile(PREFIX + r"=+\s*$")
FUNC_OFFSET = re.compile(r"(?<![\w.])([A-Za-z_][\w.]*)\+0x[0-9a-f]+(?:/0x[0-9a-f]+)?", re.I)
FUNC_SOURCE = re.compile(
    r"(?<![\w.])([A-Za-z_][\w.]*)\s+(?:(?:arch|block|crypto|drivers|fs|include|ipc|kernel|lib|mm|net|security|sound)/[\w./-]+):\d+"
)
SANITIZER_SUBTYPE = re.compile(r"BUG:\s+(?:KASAN|KMSAN):\s+([a-z][a-z-]*)", re.I)
REPORTING = {
    "at", "dump_stack", "__dump_stack", "panic", "__warn", "report_bug", "fixup_bug", "do_error_trap",
    "do_invalid_op", "invalid_op", "die", "oops_begin", "oops_end", "warn_slowpath_fmt",
}
GENERIC = {
    "memcpy", "memmove", "memset", "strlen", "kfree", "kmalloc", "copy_from_user", "copy_to_user",
    "copy_user_enhanced_fast_string", "mutex_lock", "spin_lock", "do_syscall_64",
    "entry_SYSCALL_64_after_hwframe", "__vfs_write", "__kernel_write", "write_pipe_buf",
    "__splice_from_pipe", "splice_from_pipe", "default_file_splice_write", "do_splice_from",
    "direct_splice_actor", "splice_direct_to_actor", "do_splice_direct", "do_sendfile",
}
GENERIC_PREFIXES = (
    "kmalloc", "kzalloc", "__kmalloc", "kmem_cache_", "slab_", "kfree", "vfree", "vunmap",
    "splice_", "__splice_", "do_splice", "__do_sys_", "__se_sys_", "__x64_sys_", "__arm64_sys_",
)
COMPILER_SUFFIX = re.compile(r"\.(?:isra|constprop|part|cold)(?:\.\d+)*$")
class ReportStream:
    def __init__(self) -> None:
        self.partial = ""
        self.kind: str | None = None
        self.lines: list[str] = []

    def feed(self, text: str, *, final: bool = False) -> list[CrashReport]:
        lines = (self.partial + text).splitlines(keepends=True)
        self.partial = ""
        if not final and lines and not lines[-1].endswith(("\n", "\r")):
            self.partial = lines.pop()
        reports: list[CrashReport] = []
        for line in lines:
            new_kind = report_type(line)
            continuation = self.kind is not None and (
                new_kind == self.kind and self.kind in {"WARNING", "GPF"}
                and not any("Call Trace:" in item for item in self.lines) or new_kind == "PANIC"
            )
            if new_kind and not continuation:
                self._emit(reports)
                self.kind = new_kind
            if self.kind is not None:
                self.lines.append(line)
                if REPORT_END.search(line) or (
                    self.kind in {"KASAN", "KMSAN"} and len(self.lines) > 1 and SEPARATOR.search(line)
                ):
                    self._emit(reports)
        if final:
            if self.partial:
                self.lines.append(self.partial)
                self.partial = ""
            self._emit(reports)
        return reports

    def _emit(self, reports: list[CrashReport]) -> None:
        if self.kind and self.lines:
            text = "".join(self.lines)
            reports.append(CrashReport(text, fingerprint(text, self.kind)))
        self.kind, self.lines = None, []


class StreamMatcher:
    def __init__(self, target: CrashFingerprint, source_log: str | None = None) -> None:
        self.target = target
        self.source_log = source_log
        self.stream = ReportStream()
        self.saw_crash = False
        self.other: CrashReport | None = None
        self.matched: Verdict | None = None
        self.terminal = False

    def feed(self, text: str, *, final: bool = False) -> Verdict:
        for report in self.stream.feed(text, final=final):
            self.saw_crash = True
            if self.other is None:
                self.other = report
            self.terminal |= "Kernel panic" in report.text or "Rebooting in" in report.text
            common = _matching_functions(self.target, report.fingerprint)
            if common and self.matched is None:
                self.matched = Verdict(
                    "reproduced", f"{self.target.report_type} in {common[0]}",
                    "matched crash fingerprint", self.source_log, report.text,
                )
        return self.result()

    def result(self) -> Verdict:
        if self.matched:
            return self.matched
        if self.other:
            return Verdict(
                "crashed_other", None, "other kernel crash found", self.source_log, self.other.text,
            )
        return Verdict("not_reproduced", None, "no kernel crash report found", self.source_log)


def report_type(line: str) -> str | None:
    return next((kind for kind, pattern in REPORT_STARTS if pattern.search(line)), None)


def split_reports(text: str) -> list[CrashReport]:
    return ReportStream().feed(text, final=True)


def fingerprint(text: str, kind: str) -> CrashFingerprint:
    subtype = None
    if kind in {"KASAN", "KMSAN"}:
        subtype_match = SANITIZER_SUBTYPE.search(text)
        subtype = subtype_match.group(1).lower() if subtype_match else None
        if re.search(r"BUG:\s+KASAN:\s+double-free or invalid-free\b", text, re.I):
            subtype = "invalid-free"
    candidates = (COMPILER_SUFFIX.sub("", fn) for fn in _function_candidates(text, kind))
    specific = tuple(dict.fromkeys(fn for fn in candidates if fn not in REPORTING | GENERIC and not fn.startswith(GENERIC_PREFIXES)))
    functions = specific[-1:] if kind == "WARNING" else specific[:5]
    return CrashFingerprint(kind, subtype, functions)


def target_fingerprint(path: Path) -> CrashFingerprint:
    stream = ReportStream()
    with path.open("rb") as source:
        for line in source:
            for report in stream.feed(line.decode(errors="replace")):
                if report.fingerprint.functions:
                    return report.fingerprint
    reports = stream.feed("", final=True)
    target = next((report.fingerprint for report in reports if report.fingerprint.functions), None)
    if target:
        return target
    raise ValueError(f"target crash report has no usable fingerprint: {path}")


def classify(target: CrashFingerprint, logs_dir: Path, offsets: dict[str, int] | None = None) -> Verdict:
    verdicts = []
    for name in ("qemu.log", "repro.log"):
        path = logs_dir / name
        if path.exists():
            verdicts.append(classify_path(target, path, (offsets or {}).get(name, 0), name))
    return next((item for item in verdicts if item.status == "reproduced"),
                next((item for item in verdicts if item.status == "crashed_other"),
                     Verdict("not_reproduced", None, "no kernel crash report found")))


def classify_text(target: CrashFingerprint, text: str, *, source_log: str | None = None) -> Verdict:
    return StreamMatcher(target, source_log).feed(text, final=True)


def classify_path(
    target: CrashFingerprint, path: Path, offset: int = 0, source_log: str | None = None
) -> Verdict:
    matcher = StreamMatcher(target, source_log)
    with path.open("rb") as stream:
        stream.seek(offset)
        for line in stream:
            matcher.feed(line.decode(errors="replace"))
    return matcher.feed("", final=True)


def _matching_functions(target: CrashFingerprint, observed: CrashFingerprint) -> list[str]:
    if target.report_type != observed.report_type:
        return []
    if target.subtype and observed.subtype and target.subtype != observed.subtype:
        return []
    observed_functions = set(observed.functions)
    return [fn for fn in target.functions if fn in observed_functions]


def _function_candidates(text: str, kind: str) -> list[str]:
    lines = text.splitlines()
    if kind == "WARNING":
        lines = lines[: next((i for i, line in enumerate(lines) if "Code:" in line or "Call Trace:" in line), len(lines))]
    elif kind == "MEMORY_LEAK":
        lines = lines[next((i for i, line in enumerate(lines) if "backtrace:" in line.lower()), 0) :]
    functions: list[str] = []
    for line in lines:
        functions.extend(match.group(1) for match in FUNC_OFFSET.finditer(line))
        functions.extend(match.group(1) for match in FUNC_SOURCE.finditer(line))
    return functions
