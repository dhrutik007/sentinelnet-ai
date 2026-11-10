"""File path containment for log access and imports."""

from __future__ import annotations

from pathlib import Path


class PathContainmentError(ValueError):
    """Requested path escapes the approved root directory."""


def resolve_contained(root: Path, name: str | Path) -> Path:
    """Resolve ``name`` under ``root`` and refuse anything that escapes it.

    Symlinks are resolved before the check, so a symlink inside the root that
    points outside is rejected. Raises FileNotFoundError if the file is absent.
    """
    root_resolved = root.resolve(strict=True)
    candidate = (root_resolved / name).resolve(strict=True)
    if not candidate.is_relative_to(root_resolved):
        raise PathContainmentError(f"path escapes approved root: {name!s}")
    if not candidate.is_file():
        raise PathContainmentError(f"not a regular file: {name!s}")
    return candidate
