"""Test for securegitx.gitman."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from securegitx.gitops import (
    GitError,
    _run,
    current_branch,
    is_git_repo,
    read_tracked_file,
    repo_root,
    staged_diff,
    staged_files,
    tracked_files,
    user_email,
    user_name,
)


# Helpers


def _proc(returncode: int = 0, stdout: str = "", stderr: str = "") -> MagicMock:
    m = MagicMock()
    m.returncode = returncode
    m.stdout = stdout
    m.stderr = stderr
    return m


def _patch(stdout: str = "", returncode: int = 0, stderr: str = ""):
    """Return a context manager that patches subprocess.run."""
    return patch(
        "securegitx.gitops.subprocess.run",
        return_value=_proc(returncode, stdout, stderr),
    )


# _run


def test_run_returns_stdout():
    with _patch(stdout="/repo/path\n"):
        result = _run(["git", "rev-parse", "--show-toplevel"])
    assert result == "/repo/path\n"


def test_run_raises_on_nonzero_with_stderr():
    with patch(
        "securegitx.gitops.subprocess.run",
        return_value=_proc(returncode=128, stderr="not a git repo"),
    ):
        with pytest.raises(GitError, match="not a git repo"):
            _run(["git", "rev-parse", "--show-toplevel"])


def test_run_raises_on_nonzero_no_stderr():
    with patch(
        "securegitx.gitops.subprocess.run", return_value=_proc(returncode=1, stderr="")
    ):
        with pytest.raises(GitError, match="git command failed"):
            _run(["git", "status"])


def test_run_raises_when_git_not_found():
    with patch("securegitx.gitops.subprocess.run", side_effect=FileNotFoundError):
        with pytest.raises(GitError, match="git executable not found"):
            _run(["git", "status"])


def test_run_passes_cwd():
    with patch(
        "securegitx.gitops.subprocess.run", return_value=_proc(stdout="ok")
    ) as mock:
        _run(["git", "status"], cwd=Path("/some/path"))
    mock.assert_called_once()
    _, kwargs = mock.call_args
    assert kwargs["cwd"] == Path("/some/path")


# repo_root


def test_repo_root_returns_path():
    with _patch(stdout="/home/user/project\n"):
        result = repo_root()
    assert result == Path("/home/user/project")


def test_repo_root_strips_whitespace():
    with _patch(stdout="  /home/user/project  \n"):
        result = repo_root()
    assert result == Path("/home/user/project")


def test_repo_root_raises_git_error():
    with patch(
        "securegitx.gitops.subprocess.run",
        return_value=_proc(returncode=128, stderr="not a repo"),
    ):
        with pytest.raises(GitError):
            repo_root()


# is_git_repo


def test_is_git_repo_true():
    with _patch(stdout="/repo\n"):
        assert is_git_repo() is True


def test_is_git_repo_false():
    with patch(
        "securegitx.gitops.subprocess.run",
        return_value=_proc(returncode=128, stderr="not a repo"),
    ):
        assert is_git_repo() is False


# current_branch


def test_current_branch_returns_name():
    with _patch(stdout="main\n"):
        assert current_branch() == "main"


def test_current_branch_strips_whitespace():
    with _patch(stdout="  feature/my-branch  \n"):
        assert current_branch() == "feature/my-branch"


def test_current_branch_raises_on_detached_head():
    with patch(
        "securegitx.gitops.subprocess.run",
        return_value=_proc(returncode=128, stderr="HEAD is detached"),
    ):
        with pytest.raises(GitError, match="Detached HEAD"):
            current_branch()


# staged_files


def test_staged_files_returns_list():
    with _patch(stdout="src/main.py\nsrc/utils.py\n"):
        result = staged_files()
    assert result == ["src/main.py", "src/utils.py"]


def test_staged_files_empty():
    with _patch(stdout=""):
        assert staged_files() == []


def test_staged_files_filters_blank_lines():
    with _patch(stdout="src/main.py\n\nsrc/utils.py\n"):
        result = staged_files()
    assert result == ["src/main.py", "src/utils.py"]


def test_staged_files_raises_git_error():
    with patch(
        "securegitx.gitops.subprocess.run",
        return_value=_proc(returncode=1, stderr="not a repo"),
    ):
        with pytest.raises(GitError):
            staged_files()


# staged_diff


def test_staged_diff_returns_string():
    diff = "diff --git a/f.py b/f.py\n+added line\n"
    with _patch(stdout=diff):
        assert staged_diff() == diff


def test_staged_diff_empty():
    with _patch(stdout=""):
        assert staged_diff() == ""


def test_staged_diff_raises_git_error():
    with patch(
        "securegitx.gitops.subprocess.run",
        return_value=_proc(returncode=1, stderr="error"),
    ):
        with pytest.raises(GitError):
            staged_diff()


# tracked_files


def test_tracked_files_returns_list():
    with _patch(stdout="README.md\nsrc/main.py\n"):
        result = tracked_files()
    assert result == ["README.md", "src/main.py"]


def test_tracked_files_empty_repo():
    with _patch(stdout=""):
        assert tracked_files() == []


def test_tracked_files_filters_blank_lines():
    with _patch(stdout="a.py\n\nb.py\n"):
        assert tracked_files() == ["a.py", "b.py"]


def test_tracked_files_raises_git_error():
    with patch(
        "securegitx.gitops.subprocess.run",
        return_value=_proc(returncode=128, stderr="not a repo"),
    ):
        with pytest.raises(GitError):
            tracked_files()


# read_tracked_file


def test_read_tracked_file_returns_content():
    with _patch(stdout="file content here\n"):
        result = read_tracked_file("src/main.py")
    assert result == "file content here\n"


def test_read_tracked_file_passes_correct_args():
    with patch(
        "securegitx.gitops.subprocess.run", return_value=_proc(stdout="content")
    ) as mock:
        read_tracked_file("src/main.py")
    args = mock.call_args[0][0]
    assert ":src/main.py" in args


def test_read_tracked_file_raises_on_missing():
    with patch(
        "securegitx.gitops.subprocess.run",
        return_value=_proc(returncode=128, stderr="path not in index"),
    ):
        with pytest.raises(GitError):
            read_tracked_file("nonexistent.py")


# user_email


def test_user_email_returns_stripped():
    with _patch(stdout="user@example.com\n"):
        assert user_email() == "user@example.com"


def test_user_email_raises_when_not_set():
    with patch(
        "securegitx.gitops.subprocess.run", return_value=_proc(returncode=1, stderr="")
    ):
        with pytest.raises(GitError):
            user_email()


# user_name


def test_user_name_returns_stripped():
    with _patch(stdout="Alice Smith\n"):
        assert user_name() == "Alice Smith"


def test_user_name_raises_when_not_set():
    with patch(
        "securegitx.gitops.subprocess.run", return_value=_proc(returncode=1, stderr="")
    ):
        with pytest.raises(GitError):
            user_name()
