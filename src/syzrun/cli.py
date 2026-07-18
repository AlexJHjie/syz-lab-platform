from __future__ import annotations

import argparse
import logging
import sys
from pathlib import Path

from .api import RunOptions, run_vulnerability
from .repro.verdict import Verdict


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="syzrun", description="Build Linux kernels and run syz reproducers")
    sub = parser.add_subparsers(dest="command", required=True)

    run_parser = sub.add_parser("run", help="build the kernel and run the syz reproducer")
    run_parser.add_argument("metadata", type=Path, help="path to one vulnerability JSON file")
    run_parser.add_argument("--patch", type=Path, default=None, help="optional external patch applied before build")
    run_parser.add_argument("--work-dir", type=Path, default=Path("work"), help="workspace/cache directory")
    run_parser.add_argument("--timeout", default="30m", help="timeout for long-running steps, e.g. 30m, 2h")
    run_parser.add_argument("--verbose", action="store_true", help=argparse.SUPPRESS)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    configure_logging(verbose=getattr(args, "verbose", False))

    if args.command == "run":
        return run_command(args)
    parser.error(f"unknown command: {args.command}")
    return 2


def run_command(args: argparse.Namespace) -> int:
    result = run_vulnerability(
        RunOptions(
            metadata=args.metadata,
            patch=args.patch,
            work_dir=args.work_dir,
            timeout=args.timeout,
        )
    )
    if result.report:
        _print_success(
            Verdict(result.report.verdict_status, result.report.verdict_matched, result.report.verdict_reason),
            result.report_json,
            result.report_markdown,
        )
    elif result.failure_json:
        print(f"failure report: {result.failure_json}", file=sys.stderr)
    return result.exit_code


def _print_success(verdict: Verdict, json_report: Path | None, md_report: Path | None) -> None:
    print(f"verdict: {verdict.status} ({verdict.reason})")
    if verdict.matched:
        print(f"matched: {verdict.matched}")
    print(f"report: {json_report}")
    print(f"summary: {md_report}")


def configure_logging(verbose: bool = False) -> None:
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s %(levelname)-8s %(message)s",
        datefmt="%H:%M:%S",
    )


if __name__ == "__main__":
    raise SystemExit(main())
