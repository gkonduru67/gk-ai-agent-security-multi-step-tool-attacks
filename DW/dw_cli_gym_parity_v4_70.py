from __future__ import annotations

import argparse
import csv
import hashlib
import json
import os
import shutil
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

VERSION = "4.70.00"


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def snapshot(root: Path) -> dict[str, dict[str, Any]]:
    if not root.exists():
        return {}
    out: dict[str, dict[str, Any]] = {}
    for path in sorted(p for p in root.rglob("*") if p.is_file()):
        try:
            rel = str(path.relative_to(root))
            out[rel] = {"bytes": path.stat().st_size, "sha256": sha256(path)}
        except OSError:
            continue
    return out


def run_command(name: str, command: list[str], cwd: Path, logs: Path, env: dict[str, str]) -> dict[str, Any]:
    started = datetime.now(timezone.utc).isoformat()
    proc = subprocess.run(command, cwd=cwd, env=env, text=True, encoding="utf-8", errors="replace",
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
    stdout_path = logs / f"{name}.stdout.txt"
    stderr_path = logs / f"{name}.stderr.txt"
    stdout_path.write_text(proc.stdout, encoding="utf-8")
    stderr_path.write_text(proc.stderr, encoding="utf-8")
    return {
        "name": name,
        "command": command,
        "started_utc": started,
        "finished_utc": datetime.now(timezone.utc).isoformat(),
        "returncode": proc.returncode,
        "stdout_file": stdout_path.name,
        "stderr_file": stderr_path.name,
    }


def main() -> int:
    p = argparse.ArgumentParser(description="DESTRUCTIVE_WRITE v4.70 CLI/Gym execution-parity runner")
    p.add_argument("--project-root", type=Path, required=True)
    p.add_argument("--attack-file", type=Path, default=None)
    p.add_argument("--out-dir", type=Path, required=True)
    p.add_argument("--aicomp-executable", default="aicomp")
    p.add_argument("--skip-sandbox", action="store_true")
    p.add_argument("--skip-gym", action="store_true")
    args = p.parse_args()

    root = args.project_root.expanduser().resolve()
    attack = (args.attack_file or (root / "dw_frozen_candidates_v4_70_attack.py")).expanduser().resolve()
    out = args.out_dir.expanduser().resolve()
    out.mkdir(parents=True, exist_ok=True)
    if not root.is_dir():
        p.error(f"Project root not found: {root}")
    if not attack.is_file():
        p.error(f"Attack file not found: {attack}")

    executable = shutil.which(args.aicomp_executable)
    if not executable:
        p.error(f"aicomp executable not found on PATH: {args.aicomp_executable}")

    env = os.environ.copy()
    env["PYTHONUTF8"] = "1"
    env["PYTHONIOENCODING"] = "utf-8"
    history = root / ".aicomp" / "history"
    before = snapshot(history)

    commands: list[tuple[str, list[str]]] = []
    # These are the two documented SDK interfaces already frozen in project notes.
    if not args.skip_sandbox:
        commands.append(("sandbox", [executable, "test", "redteam", str(attack), "--env", "sandbox", "--verbosity", "debug"]))
    if not args.skip_gym:
        commands.append(("gym", [executable, "evaluate", "redteam", str(attack), "--env", "gym"]))

    results = [run_command(name, cmd, root, out, env) for name, cmd in commands]
    after = snapshot(history)
    new_or_changed = {
        rel: meta for rel, meta in after.items()
        if rel not in before or before[rel] != meta
    }

    candidate_manifest = {
        "version": VERSION,
        "attack_file": str(attack),
        "attack_sha256": sha256(attack),
        "parity_kind": "execution parity from identical frozen candidate messages",
        "not_claimed": "byte-identical trace replay",
        "commands": results,
        "history_root": str(history),
        "history_files_new_or_changed": new_or_changed,
        "all_commands_succeeded": all(item["returncode"] == 0 for item in results),
        "interpretation": {
            "same_candidate_set": True,
            "same_agent_trace": False,
            "sandbox_and_gym_are_separate_executions": True,
        },
    }
    (out / "dw_cli_gym_parity_v4_70_manifest.json").write_text(
        json.dumps(candidate_manifest, indent=2), encoding="utf-8"
    )

    with (out / "dw_cli_gym_parity_v4_70_commands.csv").open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=["name", "returncode", "stdout_file", "stderr_file", "command"])
        writer.writeheader()
        for item in results:
            writer.writerow({
                "name": item["name"], "returncode": item["returncode"],
                "stdout_file": item["stdout_file"], "stderr_file": item["stderr_file"],
                "command": json.dumps(item["command"]),
            })

    print(json.dumps({"commands": results, "new_or_changed_history_files": len(new_or_changed)}, indent=2))
    return 0 if all(item["returncode"] == 0 for item in results) else 2


if __name__ == "__main__":
    raise SystemExit(main())
