"""
Rule update pipeline.

Acceptance rule: if any step fails, the active rules.json is never modified.

Write order:
  1. Download to memory          — network failure  → nothing written
  2. Parse JSON                  — parse failure    → nothing written
  3. Validate entries            — schema failure   → nothing written
  4. Checksum verify             — mismatch         → nothing written
  5. Write content to .tmp       — disk failure     → .tmp only, active intact
  6. Backup active → .bak        — crash here       → both files intact
  7. os.replace .tmp → active    — atomic on POSIX
  8. Write .meta

Rollback: validates .bak before replacing active, then removes .bak and .meta.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import urllib.error
import urllib.request
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from securegitx.rules import _RULES_DIR as _DEFAULT_RULES_DIR

DEFAULT_SOURCE_URL = (
    "https://raw.githubusercontent.com/Ozag-Labs/SecureGitX/main"
    "/src/securegitx/rules/rules.json"
)

# Module-level Path variables — monkeypatched in tests via _patch_rules_dir
_RULES_DIR = _DEFAULT_RULES_DIR
_RULES_FILE = _DEFAULT_RULES_DIR / "rules.json"
_BACKUP_FILE = _DEFAULT_RULES_DIR / "rules.json.bak"
_META_FILE = _DEFAULT_RULES_DIR / "rules.json.meta"
_TMP_SUFFIX = ".tmp"

_FETCH_TIMEOUT = 30
_REQUIRED_RULE_FIELDS = {"id", "name", "severity", "type", "pattern"}


class UpdateError(Exception):
    pass


@dataclass
class UpdateResult:
    previous_version: str
    new_version: str
    rule_count: int
    checksum: str
    skipped: bool = False
    skip_reason: str = ""


# Validation


def _validate_entries(entries: list, source: str) -> None:
    """
    Validate a list of rule entry dicts.
    Raises UpdateError (not RuleLoadError) so callers get a unified error type.
    """
    for i, entry in enumerate(entries):
        if not isinstance(entry, dict):
            raise UpdateError(f"Rule #{i} in {source} is not an object")
        missing = _REQUIRED_RULE_FIELDS - set(entry)
        if missing:
            raise UpdateError(
                f"Rule #{i} in {source} missing fields: {sorted(missing)}"
            )
        try:
            re.compile(entry["pattern"])
        except re.error as exc:
            raise UpdateError(
                f"Rule {entry.get('id', f'#{i}')} in {source} has invalid regex: {exc}"
            ) from exc


# Version helpers


def rule_version() -> str:
    """
    Return the 'version' field from the active rules.json.
    Returns 'unknown' if the file is missing, is a bare array, or has no version field.
    Never raises.
    """
    try:
        data = json.loads(_RULES_FILE.read_text(encoding="utf-8"))
    except (FileNotFoundError, json.JSONDecodeError, OSError):
        return "unknown"
    if isinstance(data, dict):
        v = data.get("version")
        if v is not None:
            return str(v)
    return "unknown"


def _parse_version(v: str) -> tuple:
    """Parse 'major.minor.patch' → int tuple. Returns (0,) for non-numeric strings."""
    try:
        return tuple(int(x) for x in v.split("."))
    except ValueError:
        return (0,)


def _is_newer(remote: str, current: str) -> bool:
    """True if remote is strictly newer than current. False when equal or unparseable."""
    if remote == "unknown" or current == "unknown":
        # If either side is unknown but both are the same token, not newer
        if remote == current:
            return False
        return True
    return _parse_version(remote) > _parse_version(current)


# Network


def _fetch(url: str) -> bytes:
    try:
        with urllib.request.urlopen(url, timeout=_FETCH_TIMEOUT) as resp:
            return resp.read()
    except urllib.error.URLError as exc:
        raise UpdateError(f"Network error fetching {url}: {exc}") from exc
    except OSError as exc:
        raise UpdateError(f"Network error fetching {url}: {exc}") from exc


# Checksum


def _sha256(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


def _verify_remote_checksum(url: str, content: bytes) -> None:
    """
    Fetch <url>.sha256 and compare. Silently skips if companion file absent.
    Raises UpdateError on mismatch.
    """
    computed = _sha256(content)
    try:
        raw = _fetch(url + ".sha256")
        expected = raw.decode(errors="replace").strip().split()[0].lower()
        if computed != expected:
            raise UpdateError(
                f"Checksum mismatch\n"
                f"  expected : {expected}\n"
                f"  computed : {computed}"
            )
    except UpdateError as exc:
        if "Checksum mismatch" in str(exc):
            raise
        # No companion .sha256 file — skip


# Meta file


def _write_meta(
    version: str,
    previous_version: str,
    rule_count: int,
    checksum: str,
) -> None:
    meta = {
        "version": version,
        "previous_version": previous_version,
        "rule_count": rule_count,
        "checksum": checksum,
        "updated_at": datetime.now(timezone.utc).isoformat(),
    }
    _META_FILE.write_text(json.dumps(meta, indent=2), encoding="utf-8")


# Core update


def update(
    source_url: str = DEFAULT_SOURCE_URL,
    verify_checksum: bool = True,
    dry_run: bool = False,
    force: bool = False,
) -> UpdateResult:
    """
    Download, validate, and install a new rules.json.
    Active rules.json is never modified until all validation passes.
    """
    tmp = _RULES_FILE.with_suffix(_TMP_SUFFIX)

    current_version = rule_version()

    # 1. Download
    content = _fetch(source_url)

    # 2. Parse JSON
    try:
        data = json.loads(content)
    except json.JSONDecodeError as exc:
        raise UpdateError(f"Remote rules.json is not valid JSON: {exc}") from exc

    # 3. Extract version
    new_version = "unknown"
    if isinstance(data, dict):
        v = data.get("version")
        if v is not None:
            new_version = str(v)

    # 4. Version check
    if not force and not _is_newer(new_version, current_version):
        return UpdateResult(
            previous_version=current_version,
            new_version=new_version,
            rule_count=0,
            checksum="",
            skipped=True,
            skip_reason=f"Already up to date (version {current_version})",
        )

    # 5. Extract entries list
    if isinstance(data, list):
        entries = data
    elif isinstance(data, dict) and "rules" in data:
        entries = data["rules"]
    else:
        raise UpdateError(
            "Remote rules.json must be an array or object with a 'rules' key"
        )

    # 6. Validate entries
    _validate_entries(entries, source_url)

    rule_count = len(entries)

    # 7. Checksum
    checksum = _sha256(content)
    if verify_checksum:
        _verify_remote_checksum(source_url, content)

    # 8. Dry-run exit
    if dry_run:
        return UpdateResult(
            previous_version=current_version,
            new_version=new_version,
            rule_count=rule_count,
            checksum=checksum,
            skipped=True,
            skip_reason="dry-run — no files written",
        )

    # 9. Write to .tmp (active not yet touched)
    try:
        tmp.write_bytes(content)
    except OSError as exc:
        raise UpdateError(f"Cannot write temporary file: {exc}") from exc

    # 10. Backup + atomic replace
    try:
        if _RULES_FILE.exists():
            shutil.copy2(_RULES_FILE, _BACKUP_FILE)
        os.replace(tmp, _RULES_FILE)
    except OSError as exc:
        try:
            tmp.unlink(missing_ok=True)
        except OSError:
            pass
        raise UpdateError(f"Failed to install rules: {exc}") from exc

    # 11. Write meta (non-critical — failure does not undo the install)
    try:
        _write_meta(new_version, current_version, rule_count, checksum)
    except OSError:
        pass

    return UpdateResult(
        previous_version=current_version,
        new_version=new_version,
        rule_count=rule_count,
        checksum=checksum,
    )


# Rollback


def rollback() -> str:
    """
    Restore rules.json.bak over rules.json.
    Validates the backup first. Removes .bak and .meta after successful restore.
    """
    if not _BACKUP_FILE.exists():
        raise UpdateError(
            "No backup found (rules.json.bak) — nothing to rollback to.\n"
            "Run 'securegitx rules update' first to create a backup."
        )

    try:
        raw = _BACKUP_FILE.read_bytes()
        data = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise UpdateError(f"Backup is not valid JSON: {exc}") from exc
    except OSError as exc:
        raise UpdateError(f"Cannot read backup: {exc}") from exc

    if isinstance(data, list):
        entries = data
    elif isinstance(data, dict) and "rules" in data:
        entries = data["rules"]
    else:
        raise UpdateError("Backup does not contain a valid rules structure")

    _validate_entries(entries, "rules.json.bak")

    restored_version = "unknown"
    if isinstance(data, dict):
        v = data.get("version")
        if v is not None:
            restored_version = str(v)

    try:
        os.replace(_BACKUP_FILE, _RULES_FILE)
    except OSError as exc:
        raise UpdateError(f"Failed to restore backup: {exc}") from exc

    # Clean up meta — it no longer reflects the active file
    try:
        _META_FILE.unlink(missing_ok=True)
    except OSError:
        pass

    return f"Rolled back to version {restored_version}"


# Remote version check


def check(source_url: str = DEFAULT_SOURCE_URL) -> str:
    """Compare installed version with remote. Never writes files."""
    current = rule_version()

    try:
        content = _fetch(source_url)
        data = json.loads(content)
        remote = "unknown"
        if isinstance(data, dict):
            v = data.get("version")
            if v is not None:
                remote = str(v)
    except (UpdateError, json.JSONDecodeError):
        return f"Check failed — remote unavailable. Installed: {current}"

    if not _is_newer(remote, current):
        return f"Up to date (version {current})"
    return f"Update available: {current} → {remote}"


# Public wrappers (root accepted for CLI/API consistency)


def update_rules(
    root: Path,
    source_url: str = DEFAULT_SOURCE_URL,
    verify_checksum: bool = True,
    dry_run: bool = False,
    force: bool = False,
) -> UpdateResult:
    return update(
        source_url=source_url,
        verify_checksum=verify_checksum,
        dry_run=dry_run,
        force=force,
    )


def rollback_rules(root: Path) -> str:
    return rollback()
