"""poleface: visual display for icons, color, banner and separators."""

from __future__ import annotations

import os
import shutil
import sys


def _is_tty() -> bool:
    return sys.stdout.isatty()


def _use_unicode() -> bool:
    return _is_tty() and (
        "UTF-8" in os.environ.get("LANG", "") or "UTF-8" in os.environ.get("LC_ALL", "")
    )


def _term_width() -> int:
    try:
        return shutil.get_terminal_size(fallback=(80, 20)).columns
    except Exception:
        return 80


if _use_unicode():
    RED = "\033[0;31m"
    GREEN = "\033[0;32m"
    YELLOW = "\033[1;33m"
    BLUE = "\033[0;34m"
    CYAN = "\033[0;36m"
    NC = "\033[0m"
    OK, WARN, ERR, INFO, STEP = "✓", "⚠", "✗", "ℹ", "▶"
else:
    RED = GREEN = YELLOW = BLUE = CYAN = NC = ""
    OK, WARN, ERR, INFO, STEP = "[OK]", "[WARN]", "[ERR]", "[INFO]", ">"


SEP = "──────────────────────────────────────────────────"


def separator() -> None:
    if not sys.stdout.isatty():
        return
    print(SEP)


def log_success(msg: str) -> None:
    print(f" {GREEN}{OK}{NC} {msg}")


def log_info(msg: str) -> None:
    print(f" {BLUE}{INFO}{NC} {msg}")


def log_warning(msg: str) -> None:
    print(f" {YELLOW}{WARN}{NC} {msg}")


def log_error(msg: str) -> None:
    print(f" {RED}{ERR}{NC} {msg}", file=sys.stderr)


def log_step(msg: str) -> None:
    print(f" {CYAN}{STEP}{NC} {msg}")


_BANNER_FULL_UNICODE = r"""
 ███████╗███████╗ ██████╗██╗   ██╗██████╗ ███████╗ ██████╗ ██╗████████╗██╗  ██╗
 ██╔════╝██╔════╝██╔════╝██║   ██║██╔══██╗██╔════╝██╔════╝ ██║╚══██╔══╝╚██╗██╔╝
 ███████╗█████╗  ██║     ██║   ██║██████╔╝█████╗  ██║  ███╗██║   ██║    ╚███╔╝ 
 ╚════██║██╔══╝  ██║     ██║   ██║██╔══██╗██╔══╝  ██║   ██║██║   ██║    ██╔██╗ 
 ███████║███████╗╚██████╗╚██████╔╝██║  ██║███████╗╚██████╔╝██║   ██║   ██╔╝ ██╗
 ╚══════╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═╝   ╚═╝   ╚═╝  ╚═╝
"""

_BANNER_COMPACT_UNICODE = r"""
 ███████╗ ██████╗ ██╗  ██╗
 ██╔════╝██╔════╝ ╚██╗██╔╝
 ███████╗██║  ███╗ ╚███╔╝
 ╚════██║██║   ██║ ██╔██╗
 ███████║╚██████╔╝██╔╝ ██╗
 ╚══════╝ ╚═════╝ ╚═╝  ╚═╝
"""

_BANNER_FULL_MIN_WIDTH = 80


def show_banner(version: str) -> None:
    """Print the SGX logo + info box. No-op when stdout is not a TTY."""
    if not _is_tty():
        return

    v = version.lstrip("v")
    width = _term_width()

    if _use_unicode():
        banner = (
            _BANNER_FULL_UNICODE
            if width >= _BANNER_FULL_MIN_WIDTH
            else _BANNER_COMPACT_UNICODE
        )
        print(f"{CYAN}{banner}{NC}")

        l1_plain = f" SecureGitX v{v}"
        l2_plain = " Auth → Scan → Secure Commit"
        l1_color = f" {CYAN}SecureGitX{NC} {YELLOW}v{v}{NC}"
        l2_color = f" {CYAN}Auth{NC} → {CYAN}Scan{NC} → {CYAN}Secure Commit{NC}"

        box_w = max(len(l1_plain), len(l2_plain), 24)
        max_box = max(24, width - 6)
        box_w = min(box_w, max_box)

        print(f"  ╭{'─' * box_w}╮")
        print(f"  │{l1_color}{' ' * max(0, box_w - len(l1_plain))}│")
        print(f"  │{l2_color}{' ' * max(0, box_w - len(l2_plain))}│")
        print(f"  ╰{'─' * box_w}╯")

    print()
