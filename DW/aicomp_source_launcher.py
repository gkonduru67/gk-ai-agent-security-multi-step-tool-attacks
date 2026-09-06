from __future__ import annotations

import importlib.metadata as metadata
import sys
from pathlib import Path


def main() -> int:
    if len(sys.argv) < 2:
        print("usage: python aicomp_source_launcher.py <aicomp arguments>", file=sys.stderr)
        return 2

    project_root = Path(__file__).resolve().parent
    if str(project_root) not in sys.path:
        sys.path.insert(0, str(project_root))

    matches = [
        ep for ep in metadata.entry_points(group="console_scripts")
        if ep.name == "aicomp"
    ]
    if not matches:
        dist_info = sorted(project_root.glob("aicomp_sdk-*.dist-info"))
        details = ", ".join(path.name for path in dist_info) or "none"
        raise SystemExit(
            "The source tree is importable, but no 'aicomp' console_scripts entry point "
            f"was found. Nearby dist-info directories: {details}."
        )

    entry = matches[0]
    command = entry.load()
    # Console entry points read their arguments from sys.argv.
    sys.argv = ["aicomp", *sys.argv[1:]]
    result = command()
    return int(result) if isinstance(result, int) else 0


if __name__ == "__main__":
    raise SystemExit(main())
