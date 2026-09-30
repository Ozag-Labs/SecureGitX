"""
.gitignore maker.
"""

from __future__ import annotations

from pathlib import Path

SECTION_START = "# >>> SecureGitX managed — do not edit this block manually"
SECTION_END = "# <<< SecureGitX"

# Always present regardless of project type
_SGX_ALWAYS: list[str] = [
    "# SecureGitX local state",
    ".securegitx/",
    ".securegitx.config",
]

# Security patterns always included
_SECURITY_ALWAYS: list[str] = [
    "# Security — credentials and keys",
    "*.env",
    ".env.*",
    ".env.local",
    "*.pem",
    "*.key",
    "*.p12",
    "*.pfx",
    "*.ppk",
    "id_rsa",
    "id_dsa",
    "id_ecdsa",
    "id_ed25519",
    "secrets/",
    "credentials/",
    ".secrets/",
]

# Per-project entries — only added when the project type matches
_PROJECT_ENTRIES: dict[str, list[str]] = {
    "python": [
        "# Python",
        "__pycache__/",
        "*.py[cod]",
        "*$py.class",
        "*.so",
        ".venv/",
        "venv/",
        "env/",
        "ENV/",
        "*.egg-info/",
        "dist/",
        "build/",
        ".pytest_cache/",
        ".mypy_cache/",
        ".tox/",
        "*.log",
        "*.db",
        "*.sqlite",
    ],
    "node": [
        "# Node",
        "node_modules/",
        "npm-debug.log*",
        "yarn-debug.log*",
        "yarn-error.log*",
        ".npm/",
        ".eslintcache/",
        ".yarn-integrity",
        "dist/",
        "build/",
        ".next/",
        "out/",
        "*.json.key",
    ],
    "go": [
        "# Go",
        "*.exe",
        "*.exe~",
        "*.dll",
        "*.so",
        "*.dylib",
        "*.test",
        "*.out",
        "vendor/",
    ],
    "rust": [
        "# Rust",
        "target/",
        "**/*.rs.bk",
        "*.pdb",
    ],
    "java": [
        "# Java",
        "*.class",
        "*.jar",
        "*.war",
        "*.ear",
        "target/",
        ".gradle/",
        "build/",
        "*.log",
        "*.keystore",
        "*.p12",
        "*.pfx",
        "credentials.*",
    ],
    "php": [
        "# PHP",
        "vendor/",
        "*.log",
        ".phpunit.result.cache",
        "composer.lock",
    ],
    "generic": [
        "# Build output",
        "dist/",
        "build/",
        "target/",
        "node_modules/",
        "vendor/",
    ],
}


def build_section(
    project_type: str,
    extra_entries: list[str] | None = None,
) -> str:
    """
    Return the full managed-section text for a given project type.

    `extra_entries` allows callers (e.g. daemon) to inject additional
    entries discovered at runtime without changing the templates.
    """
    lines: list[str] = [SECTION_START, ""]
    lines.extend(_SGX_ALWAYS)
    lines.append("")
    lines.extend(_SECURITY_ALWAYS)

    project_lines = _PROJECT_ENTRIES.get(project_type, _PROJECT_ENTRIES["generic"])
    if project_lines:
        lines.append("")
        lines.extend(project_lines)

    if extra_entries:
        lines.append("")
        lines.append("# Detected by SecureGitX daemon")
        lines.extend(extra_entries)

    lines.append("")
    lines.append(SECTION_END)
    return "\n".join(lines)


def _strip_managed_section(text: str) -> str:
    """Remove the managed section from text; preserve everything else."""
    result: list[str] = []
    inside = False

    for line in text.splitlines():
        if line.rstrip() == SECTION_START:
            inside = True
            continue
        if line.rstrip() == SECTION_END:
            inside = False
            continue
        if not inside:
            result.append(line)

    # Trim trailing blank lines that surrounded the section
    while result and not result[-1].strip():
        result.pop()

    return "\n".join(result)


def ensure_gitignore(
    root: Path,
    project_type: str,
    extra_entries: list[str] | None = None,
) -> str:
    """
    Create or update .gitignore with a SecureGitX managed section.

    Rules:
      - User content outside the section is never touched.
      - If no section exists, one is appended.
      - If a section exists, it is replaced in-place.
      - Returns a human-readable description of what changed.
    """
    gitignore = root / ".gitignore"
    section = build_section(project_type, extra_entries)

    if not gitignore.exists():
        gitignore.write_text(section + "\n", encoding="utf-8")
        return f"Created .gitignore ({project_type} project)"

    existing = gitignore.read_text(encoding="utf-8")

    if SECTION_START in existing:
        user_content = _strip_managed_section(existing)
        separator = "\n\n" if user_content.strip() else ""
        new_content = (
            (user_content + separator + section + "\n")
            if user_content.strip()
            else (section + "\n")
        )
        if new_content == existing:
            return ".gitignore is already up to date"
        gitignore.write_text(new_content, encoding="utf-8")
        return f"Updated SecureGitX section in .gitignore ({project_type})"

    # Append to a user-managed file
    separator = "\n" if existing.endswith("\n") else "\n\n"
    gitignore.write_text(existing + separator + section + "\n", encoding="utf-8")
    return f"Appended SecureGitX section to .gitignore ({project_type})"


def add_entry(root: Path, entry: str, project_type: str) -> str:
    """
    Add a single entry to the managed section.
    Called by the daemon when a new sensitive file is discovered.
    No-op if the entry is already present anywhere in .gitignore.
    """
    gitignore = root / ".gitignore"

    if gitignore.exists() and entry in gitignore.read_text(encoding="utf-8"):
        return f"Already in .gitignore: {entry}"

    existing_extras: list[str] = []

    # Preserve any entries previously injected by the daemon
    if gitignore.exists():
        content = gitignore.read_text(encoding="utf-8")
        in_daemon_block = False
        for line in content.splitlines():
            if line.strip() == "# Detected by SecureGitX daemon":
                in_daemon_block = True
                continue
            if in_daemon_block:
                if line.strip() == SECTION_END:
                    break
                if line.strip() and not line.startswith("#"):
                    existing_extras.append(line.strip())

    existing_extras.append(entry)
    return ensure_gitignore(root, project_type, extra_entries=existing_extras)
