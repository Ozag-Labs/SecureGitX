"""
An optional background process that watch git index for changes.
"""

from __future__ import annotations

import json
import logging
import os
import subprocess
import sys
import threading
import time
from pathlib import Path

_LOG = logging.getLogger("securegitx.daemon")

_DEFAULT_INTERVAL: float = 2.0

_STATE_DIR = ".securegitx"
_PID_FILE = "daemon.pid"
_CACHE_FILE = "cache/scan_result.json"
_SUGGESTIONS_FILE = "cache/gitignore_suggestions.json"


class DaemonError(Exception):
    pass


# State-dir helpers


def _state(root: Path) -> Path:
    return root / _STATE_DIR


def _ensure_dirs(root: Path) -> None:
    state = _state(root)
    (state / "cache").mkdir(parents=True, exist_ok=True)
    (state / "logs").mkdir(parents=True, exist_ok=True)


def _pid_path(root: Path) -> Path:
    return _state(root) / _PID_FILE


def _cache_path(root: Path) -> Path:
    return _state(root) / _CACHE_FILE


def _suggestions_path(root: Path) -> Path:
    return _state(root) / _SUGGESTIONS_FILE


def _write_pid(root: Path) -> None:
    _pid_path(root).write_text(str(os.getpid()), encoding="utf-8")


def _clear_pid(root: Path) -> None:
    _pid_path(root).unlink(missing_ok=True)


def _read_pid(root: Path) -> int | None:
    path = _pid_path(root)
    if not path.exists():
        return None
    try:
        return int(path.read_text(encoding="utf-8").strip())
    except (ValueError, OSError):
        return None


def is_running(root: Path) -> bool:
    """Return True if a daemon process for this repo is alive."""
    pid = _read_pid(root)
    if pid is None:
        return False
    try:
        os.kill(pid, 0)
        return True
    except (ProcessLookupError, PermissionError):
        _clear_pid(root)
        return False


# Worker entry point (runs inside the spawned subprocess)

def _run_worker(root_str: str, interval: float = _DEFAULT_INTERVAL) -> None:
    """
    Called by the background subprocess spawned from start().
    Blocks until the daemon is stopped via stop() or SIGTERM.
    """
    root = Path(root_str)
    d = SecureGitXDaemon(root, interval=interval)
    d.start()
    d.join()


# Daemon class


class SecureGitXDaemon:
    """
    Thread-based polling watcher.

    Polls .git/index mtime to detect staging changes.
    Also scans for newly created untracked files matching sensitive patterns.
    """

    def __init__(self, root: Path, interval: float = _DEFAULT_INTERVAL) -> None:
        self._root = root
        self._interval = interval
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._index = root / ".git" / "index"
        self._last_mtime: float = 0.0
        self._project_type = "generic"

    def start(self) -> None:
        _ensure_dirs(self._root)
        self._configure_logging()
        self._detect_project()

        self._stop.clear()
        self._thread = threading.Thread(
            target=self._watch_loop,
            name="securegitx-daemon",
            daemon=False,  # non-daemon so process stays alive
        )
        self._thread.start()
        _write_pid(self._root)
        _LOG.info(
            "Started (pid=%d, interval=%.1fs, project=%s)",
            os.getpid(),
            self._interval,
            self._project_type,
        )

    def stop(self) -> None:
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=self._interval * 2)
        _clear_pid(self._root)
        _LOG.info("Stopped")

    def join(self) -> None:
        """Block until the watch loop exits."""
        if self._thread:
            self._thread.join()

    # Setup

    def _configure_logging(self) -> None:
        log_path = _state(self._root) / "logs" / "daemon.log"
        if not _LOG.handlers:
            handler = logging.FileHandler(log_path, encoding="utf-8")
            handler.setFormatter(
                logging.Formatter(
                    "%(asctime)s %(levelname)-8s %(message)s",
                    datefmt="%Y-%m-%dT%H:%M:%S",
                )
            )
            _LOG.addHandler(handler)
            _LOG.setLevel(logging.INFO)

    def _detect_project(self) -> None:
        try:
            from securegitx.project_detect import detect

            info = detect(self._root)
            self._project_type = info.type
            _LOG.info("Project type: %s (confidence=%s)", info.type, info.confidence)
        except Exception as exc:
            _LOG.warning("Project detection failed: %s", exc)

    # Watch loop

    def _watch_loop(self) -> None:
        _LOG.info("Watch loop running (polling every %.1fs)", self._interval)

        # Handle SIGTERM gracefully
        import signal

        def _handle_sigterm(signum, frame):
            _LOG.info("SIGTERM received — stopping")
            self._stop.set()

        try:
            signal.signal(signal.SIGTERM, _handle_sigterm)
        except (OSError, ValueError):
            pass  # Not on main thread — signal handling unavailable

        while not self._stop.is_set():
            try:
                self._tick()
            except Exception as exc:
                _LOG.error("Tick error: %s", exc)
            self._stop.wait(self._interval)

        _LOG.info("Watch loop exited")

    def _tick(self) -> None:
        mtime = self._index_mtime()
        if mtime is not None and mtime != self._last_mtime:
            self._last_mtime = mtime
            _LOG.info("git index changed — running background scan")
            self._run_scan()
        self._check_untracked_sensitive()

    def _index_mtime(self) -> float | None:
        try:
            return self._index.stat().st_mtime
        except FileNotFoundError:
            return None

    # Scan

    def _run_scan(self) -> None:
        _ensure_dirs(self._root)
        try:
            from securegitx import gitops, scanner
            from securegitx.config import load_config
            from securegitx.rules import load_rules, load_allowlist

            config = load_config(cwd=self._root)
            rules = load_rules()
            allowlist = load_allowlist()
            staged = gitops.staged_files(cwd=self._root)
            diff = gitops.staged_diff(cwd=self._root)

            findings = scanner.scan_filenames(staged, rules, allowlist)
            findings += scanner.scan_diff(
                diff, rules, allowlist, config.entropy_threshold
            )

            self._write_cache(staged, findings)

            if findings:
                _LOG.warning(
                    "%d finding(s) in staged files — commit will be blocked",
                    len(findings),
                )
            else:
                _LOG.info("Staged files clean (%d file(s))", len(staged))

        except Exception as exc:
            _LOG.error("Background scan failed: %s", exc)

    def _check_untracked_sensitive(self) -> None:
        try:
            from securegitx.rules import load_rules, load_allowlist
            from securegitx import scanner

            result = subprocess.run(
                ["git", "ls-files", "--others", "--exclude-standard"],
                cwd=self._root,
                capture_output=True,
                text=True,
            )
            untracked = [
                line.strip() for line in result.stdout.splitlines() if line.strip()
            ]
            if not untracked:
                return

            rules = load_rules()
            allowlist = load_allowlist()
            sensitive = scanner.scan_filenames(untracked, rules, allowlist)

            for finding in sensitive:
                _LOG.warning(
                    "Sensitive untracked file: %s [%s]",
                    finding.file,
                    finding.rule_id,
                )
                self._queue_suggestion(finding.file)

        except Exception as exc:
            _LOG.debug("Untracked check failed: %s", exc)

    def _queue_suggestion(self, filepath: str) -> None:
        _ensure_dirs(self._root)
        path = _suggestions_path(self._root)
        suggestions: list[str] = []
        if path.exists():
            try:
                suggestions = json.loads(path.read_text(encoding="utf-8"))
            except (json.JSONDecodeError, OSError):
                pass
        if filepath not in suggestions:
            suggestions.append(filepath)
            path.write_text(json.dumps(suggestions, indent=2), encoding="utf-8")
            _LOG.info("Queued .gitignore suggestion: %s", filepath)

    def _write_cache(self, staged: list[str], findings: list) -> None:
        _ensure_dirs(self._root)
        cache = {
            "timestamp": time.time(),
            "staged_count": len(staged),
            "staged_files": staged,
            "finding_count": len(findings),
            "clean": len(findings) == 0,
            "findings": [f.as_dict() for f in findings],
        }
        try:
            _cache_path(self._root).write_text(
                json.dumps(cache, indent=2), encoding="utf-8"
            )
        except OSError as exc:
            _LOG.error("Failed to write cache: %s", exc)


# CLI-facing functions


def start(root: Path, interval: float = _DEFAULT_INTERVAL) -> str:
    """
    Spawn a background subprocess that runs the daemon worker.
    Returns immediately; the worker process writes its own PID.
    """
    if is_running(root):
        return f"Daemon already running (pid={_read_pid(root)})"

    _ensure_dirs(root)

    # Spawn a detached subprocess running _run_worker
    proc = subprocess.Popen(
        [
            sys.executable,
            "-c",
            (
                "import sys; from pathlib import Path; "
                "from securegitx.daemon import _run_worker; "
                f"_run_worker({str(root)!r}, {interval})"
            ),
        ],
        start_new_session=True,  # detach from parent's process group
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        cwd=str(root),
    )

    # Wait briefly for the worker to write its PID file
    deadline = time.monotonic() + 3.0
    while time.monotonic() < deadline:
        if is_running(root):
            return f"Daemon started (pid={_read_pid(root)})"
        time.sleep(0.1)

    # Fallback: process launched but PID not yet written
    if proc.poll() is None:
        return f"Daemon starting (pid={proc.pid}) — check .securegitx/logs/daemon.log"
    return "Daemon failed to start — check .securegitx/logs/daemon.log"


def stop(root: Path) -> str:
    """Send SIGTERM to the running daemon process."""
    pid = _read_pid(root)
    if pid is None or not is_running(root):
        _clear_pid(root)
        return "No daemon running"
    try:
        import signal

        os.kill(pid, signal.SIGTERM)
        for _ in range(20):
            time.sleep(0.2)
            if not is_running(root):
                break
        _clear_pid(root)
        return f"Daemon stopped (pid={pid})"
    except (ProcessLookupError, PermissionError) as exc:
        raise DaemonError(f"Could not stop daemon (pid={pid}): {exc}") from exc


def status(root: Path) -> str:
    """Return a human-readable daemon status string."""
    pid = _read_pid(root)
    running = is_running(root)

    if not running:
        return "Daemon: not running"

    lines = [f"Daemon: running (pid={pid})"]
    cache = _cache_path(root)
    if cache.exists():
        try:
            data = json.loads(cache.read_text(encoding="utf-8"))
            age = time.time() - data.get("timestamp", 0)
            staged = data.get("staged_count", 0)
            clean = data.get("clean", True)
            n_finds = data.get("finding_count", 0)
            lines.append(f"Last scan: {age:.0f}s ago — {staged} staged file(s)")
            lines.append(
                "Findings: none"
                if clean
                else f"Findings: {n_finds} (commit will be blocked)"
            )
        except (json.JSONDecodeError, OSError):
            lines.append("Cache: unreadable")

    suggestions = read_suggestions(root)
    if suggestions:
        lines.append(f"Pending .gitignore suggestions: {len(suggestions)}")
        lines.append("  Run: securegitx init  to apply")

    return "\n".join(lines)


# .gitignore suggestion queue


def read_suggestions(root: Path) -> list[str]:
    """Return pending .gitignore suggestions from the daemon cache."""
    path = _suggestions_path(root)
    if not path.exists():
        return []
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return []


def apply_suggestions(root: Path, project_type: str) -> str:
    """Write queued suggestions into .gitignore and clear the queue."""
    _ensure_dirs(root)
    suggestions = read_suggestions(root)
    if not suggestions:
        return "No pending .gitignore suggestions"
    from securegitx.gitignore_build import ensure_gitignore

    msg = ensure_gitignore(root, project_type, extra_entries=suggestions)
    _suggestions_path(root).write_text("[]", encoding="utf-8")
    return f"{msg} — {len(suggestions)} suggestion(s) applied"
