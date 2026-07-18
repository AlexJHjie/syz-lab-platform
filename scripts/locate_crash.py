#!/usr/bin/env python3
"""Ask the OpenAI Responses API to analyze a syzkaller kernel crash."""

from __future__ import annotations

import argparse
import json
import os
import sys
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any, Sequence


DEFAULT_MODEL = "gpt-5.6"
DEFAULT_BASE_URL = "http://10.249.185.212:8080/v1"
OPENAI_API_KEY = "sk-49371a28a7800fee7faf2432e7ae2deeb04e3986c93a73387d3c68ffb15a7a98"

INSTRUCTIONS = """\
You are a Linux kernel vulnerability analyst. Based on the crash report and
repro.syz provided by the user, determine the most likely root cause and propose
a concrete fix.

Write the response in Chinese and use the following order:

1. Root cause analysis: state the conclusion directly and explain the key
   evidence. Focus on the incorrect state or code logic instead of merely
   repeating the call stack.
2. Fix proposal: explain what should change, why it fixes the root cause, and
   any important side effects or regression risks.
3. Patch: provide a minimal Linux-kernel-style unified diff implementing the
   proposed fix. Put the diff in a fenced `diff` code block and make it as
   directly applicable as the available evidence permits.

If the available information is insufficient, state the most likely hypothesis
and its uncertainties. Do not invent source code, line numbers, or runtime facts
that are not supported by reliable evidence. Clearly label any best-effort or
non-directly-applicable part of the patch.
"""


class AnalysisError(RuntimeError):
    """A user-facing failure while preparing or making the API request."""


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Use GPT to locate the likely cause of a syzkaller kernel crash."
    )
    parser.add_argument("crash_report", type=Path, help="path to the crash report text")
    parser.add_argument("repro_syz", type=Path, help="path to repro.syz")
    parser.add_argument("-o", "--output", type=Path, help="also write the Markdown result to this file")
    parser.add_argument("--model", default=os.environ.get("OPENAI_MODEL", DEFAULT_MODEL))
    parser.add_argument(
        "--reasoning-effort",
        choices=("none", "low", "medium", "high", "xhigh"),
        default="high",
        help="reasoning effort sent to the model (default: high)",
    )
    parser.add_argument("--timeout", type=float, default=180.0, help="HTTP timeout in seconds")
    parser.add_argument(
        "--base-url",
        default=os.environ.get("OPENAI_BASE_URL", DEFAULT_BASE_URL),
        help="API base URL (default: OPENAI_BASE_URL or the OpenAI API)",
    )
    return parser


def read_input(path: Path, label: str) -> str:
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        raise AnalysisError(f"cannot read {label} {path}: {exc}") from exc
    if not text.strip():
        raise AnalysisError(f"{label} is empty: {path}")
    return text


def build_input(crash_report: str, repro_syz: str) -> str:
    return f"""\
Determine the most likely root cause of the following crash. Respond in Chinese.

<crash_report>
{crash_report}
</crash_report>

<repro_syz>
{repro_syz}
</repro_syz>
"""


def responses_url(base_url: str) -> str:
    url = base_url.rstrip("/")
    if url.endswith("/responses"):
        return url
    if url.endswith("/chat/completions"):
        return f"{url.removesuffix('/chat/completions')}/responses"
    if url.endswith("/v1"):
        return f"{url}/responses"
    return f"{url}/v1/responses"


def create_response(
    *,
    api_key: str,
    base_url: str,
    model: str,
    reasoning_effort: str,
    user_input: str,
    timeout: float,
) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "model": model,
        "instructions": INSTRUCTIONS,
        "input": user_input,
        "reasoning": {"effort": reasoning_effort},
        "max_output_tokens": 6000,
    }
    request = urllib.request.Request(
        responses_url(base_url),
        data=json.dumps(payload).encode("utf-8"),
        headers={
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            body = response.read().decode("utf-8")
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace")
        try:
            message = json.loads(detail).get("error", {}).get("message", detail)
        except json.JSONDecodeError:
            message = detail
        raise AnalysisError(f"OpenAI API returned HTTP {exc.code}: {message}") from exc
    except urllib.error.URLError as exc:
        raise AnalysisError(f"cannot reach OpenAI API: {exc.reason}") from exc
    except TimeoutError as exc:
        raise AnalysisError(f"OpenAI API request timed out after {timeout:g}s") from exc

    try:
        result = json.loads(body)
    except json.JSONDecodeError as exc:
        preview = body[:500].replace("\n", "\\n")
        raise AnalysisError(f"OpenAI API returned invalid JSON: {preview}") from exc
    if not isinstance(result, dict):
        raise AnalysisError("OpenAI API returned an unexpected response")
    return result


def extract_output_text(response: dict[str, Any]) -> str:
    chunks: list[str] = []
    for item in response.get("output", []):
        if not isinstance(item, dict) or item.get("type") != "message":
            continue
        for content in item.get("content", []):
            if isinstance(content, dict) and content.get("type") == "output_text":
                text = content.get("text")
                if isinstance(text, str):
                    chunks.append(text)
    if chunks:
        return "\n".join(chunks).strip()

    error = response.get("error")
    if isinstance(error, dict) and error.get("message"):
        raise AnalysisError(f"OpenAI API error: {error['message']}")
    incomplete = response.get("incomplete_details")
    if incomplete:
        raise AnalysisError(f"model response was incomplete: {incomplete}")
    raise AnalysisError("OpenAI API response contains no output text")


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        api_key = OPENAI_API_KEY
        if not api_key:
            raise AnalysisError("OPENAI_API_KEY is not set")
        crash_report = read_input(args.crash_report, "crash report")
        repro_syz = read_input(args.repro_syz, "repro.syz")
        response = create_response(
            api_key=api_key,
            base_url=args.base_url,
            model=args.model,
            reasoning_effort=args.reasoning_effort,
            user_input=build_input(crash_report, repro_syz),
            timeout=args.timeout,
        )
        result = extract_output_text(response)
        print(result)
        if args.output:
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(result + "\n", encoding="utf-8")
        return 0
    except AnalysisError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    except OSError as exc:
        print(f"error: cannot write output: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
