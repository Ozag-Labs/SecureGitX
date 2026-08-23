"""
Report formatting — text, JSON, and SARIF output.
No scanning logic here. Pure presentation.

Formats:
  text   human-readable terminal output with color
  json   structured {findings, summary} — consumed by CI and the VS Code extension
  sarif  SARIF 2.1.0 — consumed by GitHub Code Scanning and VS Code SARIF Viewer
"""

from __future__ import annotations

import json
import sys
from typing import TextIO

from securegitx.scanner import Finding

_SEVERITY_ORDER: dict[str, int] = {
    "critical": 0,
    "high": 1,
    "medium": 2,
    "low": 3,
}

_SEVERITY_ICONS: dict[str, str] = {
    "critical": "✖",
    "high": "✖",
    "medium": "⚠",
    "low": "ℹ",
}

_SEVERITY_COLORS: dict[str, str] = {
    "critical": "31",  # red
    "high": "31",
    "medium": "33",  # yellow
    "low": "36",  # cyan
}

# SARIF level and rank per severity
_SARIF_LEVEL: dict[str, str] = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
}

_SARIF_RANK: dict[str, float] = {
    "critical": 90.0,
    "high": 70.0,
    "medium": 50.0,
    "low": 30.0,
}


# Helpers


def _supports_color(stream: TextIO) -> bool:
    return hasattr(stream, "isatty") and stream.isatty()


def _color(text: str, code: str, stream: TextIO) -> str:
    if not _supports_color(stream):
        return text
    return f"\033[{code}m{text}\033[0m"


def _redact(value: str, keep: int = 4) -> str:
    if len(value) <= keep:
        return "***"
    return value[:keep] + "***"


def _count_by_severity(findings: list[Finding]) -> dict[str, int]:
    """
    Return a complete severity breakdown — all four keys always present.
    The extension and SARIF consumers can rely on these keys without null-checks.
    """
    counts: dict[str, int] = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for f in findings:
        if f.severity in counts:
            counts[f.severity] += 1
    return counts


# Text output


def format_text(
    findings: list[Finding],
    stream: TextIO = sys.stdout,
    show_remediation: bool = True,
) -> None:
    if not findings:
        _print_clean(stream)
        return

    sorted_findings = sorted(findings, key=lambda f: _SEVERITY_ORDER.get(f.severity, 9))
    counts: dict[str, int] = {}

    stream.write("\n")
    for f in sorted_findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1
        icon = _SEVERITY_ICONS.get(f.severity, "?")
        sev = _color(
            f.severity.upper(),
            _SEVERITY_COLORS.get(f.severity, "0"),
            stream,
        )
        stream.write(f"  {icon} [{sev}] {f.rule_name} ({f.rule_id})\n")
        stream.write(f"    File : {f.file}")
        if f.line_number:
            stream.write(f":{f.line_number}")
        stream.write("\n")
        stream.write(f"    Match: {_redact(f.matched_text)}\n")
        stream.write(f"    Why  : {f.reason}\n")
        if show_remediation and f.remediation:
            stream.write(f"    Fix  : {f.remediation}\n")
        if f.confidence != "high":
            stream.write(f"    Conf : {f.confidence}\n")
        stream.write("\n")

    _print_summary(counts, stream)


def _print_clean(stream: TextIO) -> None:
    ok = _color("✔", "32", stream)
    stream.write(f"\n  {ok} No secrets detected\n\n")


def _print_summary(counts: dict[str, int], stream: TextIO) -> None:
    total = sum(counts.values())
    stream.write("  " + "─" * 48 + "\n")
    stream.write(f"  {total} finding(s): ")
    parts = []
    for sev in ("critical", "high", "medium", "low"):
        if sev in counts:
            c = _color(f"{counts[sev]} {sev}", _SEVERITY_COLORS[sev], stream)
            parts.append(c)
    stream.write(", ".join(parts) + "\n\n")


# JSON output  (consumed by CI pipelines andVS Code extension)


def format_json(findings: list[Finding], stream: TextIO = sys.stdout) -> None:
    """
    Emit structured JSON.

    Summary always contains all four severity keys so consumers
    never need null-checks, plus a convenience 'clean' boolean.
    """
    by_sev = _count_by_severity(findings)
    payload = {
        "findings": [f.as_dict() for f in findings],
        "summary": {
            "total": len(findings),
            "clean": len(findings) == 0,
            "by_severity": by_sev,
        },
    }
    json.dump(payload, stream, indent=2)
    stream.write("\n")


# SARIF output  (GitHub Code Scanning, VS Code SARIF Viewer)


def format_sarif(
    findings: list[Finding],
    stream: TextIO = sys.stdout,
    version: str = "",
) -> None:
    """
    Emit SARIF 2.1.0.

    Compatible with:
      - GitHub Code Scanning  (upload-sarif action)
      - VS Code SARIF Viewer  (no extension config needed)
      - Any SARIF-aware tool

    `version` defaults to the installed package version when omitted.
    """
    if not version:
        try:
            from importlib.metadata import version as pkg_version

            version = pkg_version("securegitx")
        except Exception:
            version = "dev"

    # Build the rules table — one entry per unique rule_id
    rules_seen: dict[str, dict] = {}
    for f in findings:
        if f.rule_id not in rules_seen:
            rules_seen[f.rule_id] = {
                "id": f.rule_id,
                "name": f.rule_name,
                "shortDescription": {"text": f.reason},
                "fullDescription": {"text": f.reason},
                "help": {
                    "text": f.remediation,
                    "markdown": f.remediation,
                },
                "defaultConfiguration": {
                    "level": _SARIF_LEVEL.get(f.severity, "warning"),
                    "rank": _SARIF_RANK.get(f.severity, 50.0),
                },
                "properties": {"tags": ["security", "secret-detection"]},
            }

    results = []
    for f in findings:
        results.append(
            {
                "ruleId": f.rule_id,
                "level": _SARIF_LEVEL.get(f.severity, "warning"),
                "message": {"text": f"{f.reason} — {f.remediation}"},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {
                                "uri": f.file.replace("\\", "/"),
                                "uriBaseId": "%SRCROOT%",
                            },
                            "region": {
                                "startLine": max(1, f.line_number),
                                "startColumn": 1,
                            },
                        }
                    }
                ],
                "properties": {
                    "confidence": f.confidence,
                    "matched": _redact(f.matched_text),
                },
            }
        )

    # Deduplicated artifact list
    seen_files: dict[str, dict] = {}
    for f in findings:
        uri = f.file.replace("\\", "/")
        if uri not in seen_files:
            seen_files[uri] = {"location": {"uri": uri, "uriBaseId": "%SRCROOT%"}}

    sarif = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "SecureGitX",
                        "version": version,
                        "informationUri": "https://github.com/Ozag-Labs/SecureGitX",
                        "rules": list(rules_seen.values()),
                    }
                },
                "results": results,
                "artifacts": list(seen_files.values()),
            }
        ],
    }
    json.dump(sarif, stream, indent=2)
    stream.write("\n")


# Threshold check


def exceeds_threshold(findings: list[Finding], fail_on: str) -> bool:
    """Return True if any finding is at or above the fail_on severity."""
    threshold = _SEVERITY_ORDER.get(fail_on, 1)
    return any(_SEVERITY_ORDER.get(f.severity, 9) <= threshold for f in findings)
