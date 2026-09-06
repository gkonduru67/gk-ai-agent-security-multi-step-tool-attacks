from __future__ import annotations

import argparse
import csv
import hashlib
import json
import os
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

VERSION = "4.70.01"


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def snapshot(root: Path) -> dict[str, dict[str, Any]]:
    if not root.exists():
        return {}
    result = {}
    for path in sorted(p for p in root.rglob("*") if p.is_file()):
        try:
            rel = str(path.relative_to(root))
            result[rel] = {"bytes": path.stat().st_size, "sha256": sha256(path)}
        except OSError:
            pass
    return result


def execute(name: str, command: list[str], cwd: Path, out: Path, env: dict[str, str]) -> dict[str, Any]:
    started = datetime.now(timezone.utc).isoformat()
    process = subprocess.run(
        command,
        cwd=cwd,
        env=env,
        text=True,
        encoding="utf-8",
        errors="replace",
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    stdout_file = out / f"{name}.stdout.txt"
    stderr_file = out / f"{name}.stderr.txt"
    stdout_file.write_text(process.stdout, encoding="utf-8")
    stderr_file.write_text(process.stderr, encoding="utf-8")
    return {
        "name": name,
        "command": command,
        "started_utc": started,
        "finished_utc": datetime.now(timezone.utc).isoformat(),
        "returncode": process.returncode,
        "stdout_file": stdout_file.name,
        "stderr_file": stderr_file.name,
    }


def main() -> int:
    parser = argparse.ArgumentParser(
        description="DESTRUCTIVE_WRITE v4.70.01 source-tree CLI/Gym parity runner"
    )
    parser.add_argument("--project-root", type=Path, required=True)
    parser.add_argument("--attack-file", type=Path, default=None)
    parser.add_argument("--launcher-file", type=Path, default=None)
    parser.add_argument("--out-dir", type=Path, required=True)
    parser.add_argument("--skip-sandbox", action="store_true")
    parser.add_argument("--skip-gym", action="store_true")
    args = parser.parse_args()

    root = args.project_root.expanduser().resolve()
    attack = (args.attack_file or root / "dw_frozen_candidates_v4_70_attack.py").expanduser().resolve()
    launcher = (args.launcher_file or root / "aicomp_source_launcher.py").expanduser().resolve()
    out = args.out_dir.expanduser().resolve()
    out.mkdir(parents=True, exist_ok=True)

    for label, path in (("project root", root), ("attack file", attack), ("launcher", launcher)):
        if not path.exists():
            parser.error(f"{label} not found: {path}")

    env = os.environ.copy()
    env["PYTHONUTF8"] = "1"
    env["PYTHONIOENCODING"] = "utf-8"
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    env["PYTHONPATH"] = str(root) + os.pathsep + env.get("PYTHONPATH", "")

    # Verify source-tree entry-point discovery before running either layer.
    preflight = execute(
        "preflight",
        [sys.executable, "-B", str(launcher), "--help"],
        root,
        out,
        env,
    )
    if preflight["returncode"] != 0:
        manifest = {
            "version": VERSION,
            "status": "SOURCE_TREE_CLI_PREFLIGHT_FAILED",
            "attack_file": str(attack),
            "attack_sha256": sha256(attack),
            "launcher_file": str(launcher),
            "launcher_sha256": sha256(launcher),
            "preflight": preflight,
            "sandbox_started": False,
            "gym_started": False,
        }
        (out / "dw_cli_gym_parity_v4_70_01_manifest.json").write_text(
            json.dumps(manifest, indent=2), encoding="utf-8"
        )
        print(json.dumps(manifest, indent=2))
        return 3

    history = root / ".aicomp" / "history"
    before = snapshot(history)
    commands: list[tuple[str, list[str]]] = []
    prefix = [sys.executable, "-B", str(launcher)]
    if not args.skip_sandbox:
        commands.append((
            "sandbox",
            prefix + ["test", "redteam", str(attack), "--env", "sandbox", "--verbosity", "debug"],
        ))
    if not args.skip_gym:
        commands.append((
            "gym",
            prefix + ["evaluate", "redteam", str(attack), "--env", "gym"],
        ))

    results = [execute(name, command, root, out, env) for name, command in commands]
    after = snapshot(history)
    changed = {rel: meta for rel, meta in after.items() if rel not in before or before[rel] != meta}

    manifest = {
        "version": VERSION,
        "status": "COMPLETED" if all(item["returncode"] == 0 for item in results) else "COMMAND_FAILURE",
        "execution_mode": "source-tree console entry point via importlib.metadata",
        "python_executable": sys.executable,
        "attack_file": str(attack),
        "attack_sha256": sha256(attack),
        "launcher_file": str(launcher),
        "launcher_sha256": sha256(launcher),
        "preflight": preflight,
        "commands": results,
        "history_root": str(history),
        "history_files_new_or_changed": changed,
        "all_commands_succeeded": all(item["returncode"] == 0 for item in results),
        "parity_claim": "identical frozen candidate messages in separate Sandbox and Gym executions",
        "not_claimed": "byte-identical frozen-trace replay",
    }
    (out / "dw_cli_gym_parity_v4_70_01_manifest.json").write_text(
        json.dumps(manifest, indent=2), encoding="utf-8"
    )

    with (out / "dw_cli_gym_parity_v4_70_01_commands.csv").open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=["name", "returncode", "stdout_file", "stderr_file", "command"])
        writer.writeheader()
        for item in [preflight, *results]:
            writer.writerow({
                "name": item["name"],
                "returncode": item["returncode"],
                "stdout_file": item["stdout_file"],
                "stderr_file": item["stderr_file"],
                "command": json.dumps(item["command"]),
            })

    print(json.dumps({"status": manifest["status"], "commands": results, "history_files": len(changed)}, indent=2))
    return 0 if manifest["all_commands_succeeded"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
