from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path


@dataclass(frozen=True)
class CrashFingerprint:
    report_type: str
    subtype: str | None
    functions: tuple[str, ...]
    accepted_report_types: tuple[str, ...] = ()
    accepted_subtypes: tuple[str, ...] = ()
    match_all_functions: bool = False
    # A configured target can be a disjunction of fully independent
    # fingerprints.  The ordinary fields retain the first rule for callers
    # that only need a representative fingerprint; matching always examines
    # every alternative when this tuple is populated.
    alternatives: tuple["CrashFingerprint", ...] = ()


@dataclass(frozen=True)
class CrashTargetConfig:
    """Optional per-case crash selection rules from vulnerabilities.json."""

    report_types: tuple[str, ...] = ()
    subtypes: tuple[str, ...] = ()
    functions: tuple[str, ...] = ()
    match_all_functions: bool = False
    # ``alternatives`` is an OR of complete rules.  It deliberately does not
    # merge their report types, subtypes, or functions: doing so would create
    # false type/function cross-products.
    alternatives: tuple["CrashTargetConfig", ...] = ()


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
WARNING_AT = re.compile(PREFIX + r"WARNING:(?=\s+(?:CPU:\s+\d+(?:\s+PID:\s+\d+)?\s+)?at\b)", re.I)
UBSAN_START = re.compile(PREFIX + r"(?:BUG:\s+)?UBSAN:\s+[a-z][a-z0-9-]*", re.I)
REPORT_STARTS = (
    ("MEMORY_LEAK", re.compile(PREFIX + r"BUG:\s+memory leak\b", re.I)),
    ("KASAN", re.compile(PREFIX + r"BUG:\s+KASAN:", re.I)),
    ("KMSAN", re.compile(PREFIX + r"BUG:\s+KMSAN:", re.I)),
    ("WARNING", re.compile(PREFIX + r"WARNING:", re.I)),
    ("GPF", re.compile(PREFIX + r"(?:BUG:\s+GPF\b|general protection fault(?:\b|:))", re.I)),
    ("DIVIDE_ERROR", re.compile(PREFIX + r"divide error:", re.I)),
    ("HUNG_TASK", re.compile(PREFIX + r"INFO:\s+task .+ blocked for more than\b", re.I)),
    ("RCU_STALL", re.compile(PREFIX + r"(?:rcu:\s*)?INFO:\s+rcu(?:_[a-z]+)?\s+(?:self-)?detected stalls?\b", re.I)),
    ("SOFT_LOCKUP", re.compile(PREFIX + r"(?:watchdog:\s+)?BUG:\s+soft lockup\b", re.I)),
    ("OOPS", re.compile(PREFIX + r"Oops:", re.I)),
    ("PANIC", re.compile(PREFIX + r"(?:Kernel panic - not syncing:|panic:)", re.I)),
    ("BUG", re.compile(PREFIX + r"(?:kernel BUG at\b|BUG:)", re.I)),
    ("UBSAN", UBSAN_START),
    ("LOCKDEP", re.compile(PREFIX + r"INFO:\s+trying to register non-static key\.", re.I)),
    ("NETDEV_WAIT", re.compile(PREFIX + r"unregister_netdevice:\s+waiting for \S+ to become free\.\s+Usage count\s*=\s*\d+\b", re.I)),
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
    "ubsan_epilogue", "__ubsan_handle_builtin_unreachable",
}
GENERIC = {
    "in", "memcpy", "memmove", "memset", "strlen", "kfree", "kmalloc", "copy_from_user", "copy_to_user",
    "copy_user_enhanced_fast_string", "mutex_lock", "spin_lock", "do_syscall_64",
    "entry_SYSCALL_64_after_hwframe", "__vfs_write", "__kernel_write", "write_pipe_buf",
    "__splice_from_pipe", "splice_from_pipe", "default_file_splice_write", "do_splice_from",
    "direct_splice_actor", "splice_direct_to_actor", "do_splice_direct", "do_sendfile",
    "asm_sysvec_apic_timer_interrupt", "do_syscall_x64",
}
GENERIC_PREFIXES = (
    "kmalloc", "kzalloc", "__kmalloc", "kmem_cache_", "slab_", "kfree", "vfree", "vunmap",
    "splice_", "__splice_", "do_splice", "__do_sys_", "__se_sys_", "__x64_sys_", "__arm64_sys_",
    "__ubsan_handle",
)
COMPILER_SUFFIX = re.compile(r"\.(?:isra|constprop|part|cold)(?:\.\d+)*$")
LOCK_HELPERS = ("dump_stack", "__dump_stack", "lock_acquire", "__lock_acquire",
                "register_lock_class", "lockdep_rcu_suspicious", "_raw_")


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
                and not any("Call Trace:" in item for item in self.lines)
                and (self.kind != "WARNING" or WARNING_AT.match(line) and WARNING_AT.match(self.lines[0]))
                or new_kind == "PANIC"
            )
            # syz-symbolize (and KASAN itself) can print one BUG header for
            # every inline frame before the actual outer frame.  Those
            # headers are one report; splitting them makes target_fingerprint
            # select an inner helper and causes a false crashed_other result.
            if new_kind == "KASAN" and self.kind == "KASAN":
                continuation = continuation or all(report_type(item) == "KASAN" for item in self.lines)
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
            fp = fingerprint(text, self.kind)
            if self.kind != "WARNING" or WARNING_AT.match(text) or fp.functions:
                reports.append(CrashReport(text, fp))
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
                    "reproduced", f"{report.fingerprint.report_type} in {common[0]}",
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
    if kind == "NETDEV_WAIT":
        return CrashFingerprint(kind, None, ("unregister_netdevice",))
    structured = kind == "LOCKDEP" or kind == "WARNING" and not WARNING_AT.match(text)
    lines = text.splitlines()
    subtype = None
    if structured:
        lines = [re.sub(PREFIX, "", line) for line in lines]
        text = "\n".join(lines)
        primary = re.split(r"other info|the existing dependency chain|state was registered at:|Call Trace:|which would create a new lock dependency:", text, maxsplit=1)[0]
        locks = list(dict.fromkeys(re.findall(r"\((.+)\)\{([.+?\-]+)\}", primary)))
        irq = re.search(r"(HARDIRQ|SOFTIRQ)-(?:un)?safe", primary)
        locks = [(name, irq[1], flags[2:4] if irq[1] == "SOFTIRQ" else flags[:2]) for name, flags in locks] if irq else [name for name, _ in locks]
        # Lockdep appends "#N" to a lock class name when the same lock is
        # registered at several sites.  The suffix differs between machines
        # for the same lock, so normalize it for the subtype only; "locks"
        # itself stays untouched for the record lookup below.  The version
        # precedes the subclass when both are printed ("#3/4"), so match it
        # before either a "/" or the end of the name.
        norm_locks = [(re.sub(r"#\d+(?=/|$)", "", n[0]), *n[1:]) if isinstance(n, tuple) else re.sub(r"#\d+(?=/|$)", "", n) for n in locks]
        states = re.search(r"inconsistent \{([^}]+)\} -> \{([^}]+)\}", primary)
        subtype = re.sub(r"^(?:WARNING|INFO):\s*", "", lines[0], flags=re.I).strip().lower()
        subtype += f"; locks={sorted(norm_locks) if 'irq lock inversion' in subtype else norm_locks}; states={sorted(states.groups()) if states else []}"
        unsafe = re.search(r"but this lock took another, (HARDIRQ|SOFTIRQ)-unsafe lock", primary)
        record = re.search(r"-> \(" + re.escape(locks[-1][0]) + r"\).*?(?=\n\s*->|\Z)", text, re.S) if unsafe and locks else None
        usage = re.search(unsafe[1] + r"-ON-[WR] at:\s*\n(.*)", record[0], re.S) if record else None
        lines = (usage[1] if usage else primary).splitlines()
        if not usage and not any(FUNC_OFFSET.search(line) and "[inline]" not in line for line in lines):
            lines = text.rsplit("Call Trace:", 1)[-1].splitlines()
    elif kind == "WARNING":
        lines = lines[: next((i for i, line in enumerate(lines) if "Code:" in line or "Call Trace:" in line), len(lines))]
    elif kind == "RCU_STALL" and "<TASK>" in text:
        lines = text.rsplit("<TASK>", 1)[1].splitlines()
    elif kind == "MEMORY_LEAK":
        lines = lines[next((i for i, line in enumerate(lines) if "backtrace:" in line.lower()), 0) :]
    if kind in {"KASAN", "KMSAN"}:
        subtype_match = SANITIZER_SUBTYPE.search(text)
        subtype = subtype_match.group(1).lower() if subtype_match else None
        if re.search(r"BUG:\s+KASAN:\s+double-free or invalid-free\b", text, re.I):
            subtype = "invalid-free"
    functions: list[str] = []
    for line in lines:
        if structured and ("[inline]" in line or re.match(PREFIX + r"\?", line)):
            continue
        functions.extend(match.group(1) for match in FUNC_OFFSET.finditer(line))
        functions.extend(match.group(1) for match in FUNC_SOURCE.finditer(line))
    candidates = (COMPILER_SUFFIX.sub("", fn) for fn in functions)
    excluded = REPORTING | ({"flush_work"} if structured else GENERIC)
    prefixes = LOCK_HELPERS if structured else GENERIC_PREFIXES
    specific = tuple(dict.fromkeys(fn for fn in candidates if fn not in excluded and not fn.startswith(prefixes)))
    limit = 2 if kind == "LOCKDEP" else 1 if structured else 8 if kind in {"KASAN", "KMSAN"} else 5
    functions = specific[-1:] if kind == "WARNING" and not structured else specific[:limit]
    return CrashFingerprint(kind, subtype, functions)


def target_fingerprint(path: Path, override: CrashTargetConfig | None = None) -> CrashFingerprint:
    if override is not None:
        if override.alternatives:
            if (
                override.report_types
                or override.subtypes
                or override.functions
                or override.match_all_functions
            ):
                raise ValueError("target crash alternatives cannot be combined with a direct target rule")
            alternatives = tuple(_configured_fingerprint(rule) for rule in override.alternatives)
            if not alternatives:
                raise ValueError("target crash alternatives must contain at least one rule")
            first = alternatives[0]
            return CrashFingerprint(
                report_type=first.report_type,
                subtype=first.subtype,
                functions=first.functions,
                accepted_report_types=first.accepted_report_types,
                accepted_subtypes=first.accepted_subtypes,
                match_all_functions=first.match_all_functions,
                alternatives=alternatives,
            )
        return _configured_fingerprint(override)

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


def _configured_fingerprint(config: CrashTargetConfig) -> CrashFingerprint:
    if config.alternatives:
        raise ValueError("target crash alternatives must contain direct rules only")
    if not config.report_types:
        raise ValueError("target crash configuration must contain at least one report type")
    return CrashFingerprint(
        report_type=config.report_types[0],
        subtype=config.subtypes[0] if len(config.subtypes) == 1 else None,
        functions=config.functions,
        accepted_report_types=config.report_types,
        accepted_subtypes=config.subtypes,
        match_all_functions=config.match_all_functions,
    )


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
    if target.alternatives:
        for alternative in target.alternatives:
            common = _matching_functions(alternative, observed)
            if common:
                return common
        return []
    accepted_types = target.accepted_report_types or (target.report_type,)
    if observed.report_type not in accepted_types:
        return []
    accepted_subtypes = target.accepted_subtypes
    if accepted_subtypes and observed.subtype not in accepted_subtypes:
        return []
    # An explicit target configuration with no subtype intentionally accepts
    # any subtype of the selected report type.  Inferred targets retain the
    # historical subtype check for WARNING reports.
    if not accepted_subtypes and not target.accepted_report_types and target.subtype != observed.subtype and (
        target.report_type == "WARNING" or target.subtype and observed.subtype
    ):
        return []
    if target.report_type == "LOCKDEP":
        return list(target.functions) if len(target.functions) == 2 and target.functions == observed.functions else []
    observed_functions = set(observed.functions)
    common = [fn for fn in target.functions if fn in observed_functions]
    if target.match_all_functions and len(common) != len(target.functions):
        return []
    return common


def same_crash_kind(target: CrashFingerprint, observed: CrashFingerprint) -> bool:
    """Whether an observed report is compatible enough to symbolize for target."""

    if target.alternatives:
        return any(same_crash_kind(alternative, observed) for alternative in target.alternatives)
    accepted_types = target.accepted_report_types or (target.report_type,)
    if observed.report_type not in accepted_types:
        return False
    if target.accepted_subtypes:
        return observed.subtype in target.accepted_subtypes
    return not target.subtype or not observed.subtype or target.subtype == observed.subtype
