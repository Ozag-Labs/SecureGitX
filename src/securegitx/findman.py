"""
Findman: discover files types for workspace projects
"""

from __future__ import annotations

import subprocess
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class ProjectInfo:
    type: str  # see _MARKERS keys + "generic"
    markers: list[str] = field(default_factory=list)  # files that triggered detection
    confidence: str = "high"  # "high" = marker-based, "low" = heuristic


# Ordered: first match wins when multiple types share a root
_MARKERS: dict[str, list[str]] = {
    "python": [
        "pyproject.toml",
        "requirements.txt",
        "setup.py",
        "setup.cfg",
        "Pipfile",
        "poetry.lock",
    ],
    "node": [
        "package.json",
        "tsconfig.json",
        "yarn.lock",
        "pnpm-lock.yaml",
        ".nvmrc",
        ".node-version",
    ],
    "go": ["go.mod"],
    "rust": ["Cargo.toml"],
    "java": ["pom.xml", "build.gradle", "build.gradle.kts", "gradlew"],
    "php": ["composer.json"],
}

# Extension → project type for heuristic fallback
_EXT_MAP: dict[str, str] = {
    "py": "python",
    "pyx": "python",
    "pyi": "python",
    "js": "node",
    "ts": "node",
    "jsx": "node",
    "tsx": "node",
    "mjs": "node",
    "cjs": "node",
    "go": "go",
    "rs": "rust",
    "java": "java",
    "kt": "java",
    "kts": "java",
    "groovy": "java",
    "php": "php",
}


def detect(root: Path) -> ProjectInfo:
    """
    Detect the primary project type for the repository at `root`.

    Strategy:
      1. Check for known manifest files (high confidence).
      2. Count tracked file extensions via git ls-files (low confidence).
      3. Fall back to "generic".
    """
    hit_markers: list[str] = []
    hit_type: str | None = None

    for project_type, markers in _MARKERS.items():
        for marker in markers:
            if (root / marker).exists():
                hit_markers.append(marker)
                if hit_type is None:
                    hit_type = project_type

    if hit_type:
        return ProjectInfo(type=hit_type, markers=hit_markers, confidence="high")

    # Heuristic — count file extensions from git ls-files
    ext_counts = _count_extensions(root)
    if ext_counts:
        dominant_ext = max(ext_counts, key=lambda e: ext_counts[e])
        if dominant_ext in _EXT_MAP:
            return ProjectInfo(
                type=_EXT_MAP[dominant_ext],
                markers=[f"*.{dominant_ext} ({ext_counts[dominant_ext]} files)"],
                confidence="low",
            )

    return ProjectInfo(type="generic", markers=[], confidence="low")


def _count_extensions(root: Path) -> dict[str, int]:
    """Return {extension: count} for all tracked files."""
    try:
        result = subprocess.run(
            ["git", "ls-files"],
            cwd=root,
            capture_output=True,
            text=True,
        )
        counts: dict[str, int] = {}
        for line in result.stdout.splitlines():
            ext = Path(line.strip()).suffix.lstrip(".")
            if ext:
                counts[ext] = counts.get(ext, 0) + 1
        return counts
    except Exception:
        return {}
