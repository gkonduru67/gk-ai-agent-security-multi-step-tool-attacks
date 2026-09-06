"""Canonical source-path helper v1. Performs no filesystem reads."""
from __future__ import annotations
from pathlib import Path

def canonical_source_path_v1(filesystem_root: Path, requested_path: str, resolved_path: Path) -> str:
    root = filesystem_root.resolve(strict=False)
    resolved = resolved_path.resolve(strict=False)
    try:
        relative = resolved.relative_to(root)
    except ValueError as exc:
        raise ValueError("resolved path is outside filesystem root") from exc
    if not isinstance(requested_path, str) or not requested_path:
        raise ValueError("requested_path must be a nonempty string")
    text = relative.as_posix()
    if text in {"", "."}:
        raise ValueError("canonical source path must identify a file below root")
    return "/" + text
