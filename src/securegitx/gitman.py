"""
Gitman: git process
"""

from __future__ import annotations

import subprocess
from pathlib import Path


class GitError(Exception):
    pass


def _run(args: list[str], cwd: Path | None = None) -> str:
    """Run a git command, return stdout. Raise GitError on non-zero exit."""
    try:
        result = subprocess.run(
            args,
            capture_output=True,
            text=True,
            cwd=cwd,
        )
    except FileNotFoundError:
        raise GitError("git executable not found")

    if result.returncode != 0:
        raise GitError(result.stderr.strip() or f"git command failed: {' '.join(args)}")

    return result.stdout


def repo_root(path: Path | None = None) -> Path:
    """Return the absolute path to the repository root."""
    out = _run(["git", "rev-parse", "--show-toplevel"], cwd=path)
    return Path(out.strip())


def is_git_repo(path: Path | None = None) -> bool:
    try:
        repo_root(path)
        return True
    except GitError:
        return False


def current_branch(cwd: Path | None = None) -> str:
    """Return current branch name. Raises GitError if in detached HEAD."""
    try:
        out = _run(["git", "symbolic-ref", "--short", "HEAD"], cwd=cwd)
        return out.strip()
    except GitError:
        raise GitError("Detached HEAD state — checkout a branch before committing")


def staged_files(cwd: Path | None = None) -> list[str]:
    """Return list of filenames currently staged."""
    out = _run(["git", "diff", "--cached", "--name-only"], cwd=cwd)
    return [line for line in out.splitlines() if line.strip()]


def staged_diff(cwd: Path | None = None) -> str:
    """Return the full unified diff of staged changes."""
    return _run(["git", "diff", "--cached"], cwd=cwd)


def tracked_files(cwd: Path | None = None) -> list[str]:
    """Return all files tracked by git."""
    out = _run(["git", "ls-files"], cwd=cwd)
    return [line for line in out.splitlines() if line.strip()]


def read_tracked_file(filename: str, cwd: Path | None = None) -> str | None:
    """Read a tracked file's content via git show.
    Returns None for binary or undecodable files.
    """
    try:
        result = subprocess.run(
            ["git", "show", f":{filename}"],
            capture_output=True,
            cwd=cwd,
        )
    except FileNotFoundError:
        raise GitError("git executable not found")

    stderr = result.stderr
    if isinstance(stderr, bytes):
        stderr_text = stderr.decode("utf-8", errors="replace").strip()
    else:
        stderr_text = str(stderr).strip()

    if result.returncode != 0:
        raise GitError(stderr_text or f"git show failed: {filename}")

    data = result.stdout

    if isinstance(data, bytes):
        if b"\x00" in data:
            return None
        try:
            return data.decode("utf-8")
        except UnicodeDecodeError:
            return None

    # test doubles may return str
    if "\x00" in data:
        return None
    return data


def user_email(cwd: Path | None = None) -> str:
    out = _run(["git", "config", "user.email"], cwd=cwd)
    return out.strip()


def user_name(cwd: Path | None = None) -> str:
    out = _run(["git", "config", "user.name"], cwd=cwd)
    return out.strip()
