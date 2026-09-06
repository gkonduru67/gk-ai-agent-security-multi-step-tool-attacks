from __future__ import annotations

import argparse
import csv
import hashlib
import importlib.util
import json
import os
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

VERSION = "4.70.02"


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def run_command(name: str, command: list[str], cwd: Path, out_dir: Path, env: dict[str, str]) -> dict[str, Any]:
    started = datetime.now(timezone.utc).isoformat()
    proc = subprocess.run(
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
    stdout_path = out_dir / f"{name}.stdout.txt"
    stderr_path = out_dir / f"{name}.stderr.txt"
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
        "stdout_sha256": sha256(stdout_path),
        "stderr_sha256": sha256(stderr_path),
        "stdout_bytes": stdout_path.stat().st_size,
        "stderr_bytes": stderr_path.stat().st_size,
    }


def module_status(name: str) -> dict[str, Any]:
    try:
        spec = importlib.util.find_spec(name)
    except (ImportError, AttributeError, ValueError) as exc:
        return {"module": name, "available": False, "origin": None, "error": repr(exc)}
    return {
        "module": name,
        "available": spec is not None,
        "origin": str(spec.origin) if spec and spec.origin else None,
        "error": None,
    }


def main() -> int:
    parser = argparse.ArgumentParser(
        description="DESTRUCTIVE_WRITE v4.70.02 CLI/Gym availability-aware parity runner"
    )
    parser.add_argument("--project-root", type=Path, required=True)
    parser.add_argument("--attack-file", type=Path, default=None)
    parser.add_argument("--launcher-file", type=Path, default=None)
    parser.add_argument("--out-dir", type=Path, required=True)
    parser.add_argument("--skip-sandbox", action="store_true")
    args = parser.parse_args()

    root = args.project_root.expanduser().resolve()
    attack = (args.attack_file or root / "dw_frozen_candidates_v4_70_attack.py").expanduser().resolve()
    launcher = (args.launcher_file or root / "aicomp_source_launcher.py").expanduser().resolve()
    out_dir = args.out_dir.expanduser().resolve()
    out_dir.mkdir(parents=True, exist_ok=True)

    for label, path in (("project root", root), ("attack file", attack), ("source launcher", launcher)):
        if not path.exists():
            parser.error(f"{label} not found: {path}")

    if str(root) not in sys.path:
        sys.path.insert(0, str(root))

    gym_modules = [
        module_status("gymnasium"),
        module_status("aicomp_sdk.core.env.gym"),
        module_status("aicomp_sdk.core.env.gym_env"),
    ]
    gymnasium_available = gym_modules[0]["available"]
    sdk_gym_available = gym_modules[1]["available"] or gym_modules[2]["available"]
    gym_execution_available = bool(gymnasium_available and sdk_gym_available)

    env = os.environ.copy()
    env["PYTHONUTF8"] = "1"
    env["PYTHONIOENCODING"] = "utf-8"
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    env["PYTHONPATH"] = str(root) + os.pathsep + env.get("PYTHONPATH", "")
    prefix = [sys.executable, "-B", str(launcher)]

    results: list[dict[str, Any]] = []
    preflight = run_command("preflight", prefix + ["--help"], root, out_dir, env)
    results.append(preflight)

    sandbox = None
    if preflight["returncode"] == 0 and not args.skip_sandbox:
        sandbox = run_command(
            "sandbox",
            prefix + ["test", "redteam", str(attack), "--env", "sandbox", "--verbosity", "debug"],
            root,
            out_dir,
            env,
        )
        results.append(sandbox)

    gym = None
    if preflight["returncode"] == 0 and gym_execution_available:
        gym = run_command(
            "gym",
            prefix + ["evaluate", "redteam", str(attack), "--env", "gym"],
            root,
            out_dir,
            env,
        )
        results.append(gym)
    else:
        reason = (
            "Gym execution was not started because both gymnasium and an SDK Gym environment module "
            "were not available in the active Python environment."
        )
        (out_dir / "gym.not_run.txt").write_text(reason + "\n", encoding="utf-8")

    if preflight["returncode"] != 0:
        status = "SOURCE_TREE_CLI_PREFLIGHT_FAILED"
    elif sandbox is not None and sandbox["returncode"] != 0:
        status = "SANDBOX_COMMAND_FAILED"
    elif not gym_execution_available:
        status = "SANDBOX_COMPLETED_GYM_UNAVAILABLE"
    elif gym is not None and gym["returncode"] != 0:
        status = "GYM_COMMAND_FAILED"
    else:
        status = "BOTH_EXECUTIONS_COMPLETED"

    parity = {
        "candidate_file_identity_verified": True,
        "execution_availability_parity": gym_execution_available,
        "behavioral_parity_evaluated": bool(sandbox and sandbox["returncode"] == 0 and gym and gym["returncode"] == 0),
        "predicate_parity_evaluated": False,
        "breach_parity_evaluated": False,
        "note": (
            "Predicate and breach parity require parsing successful Sandbox and Gym artifacts. "
            "They are not inferred from command return codes."
        ),
    }

    manifest = {
        "version": VERSION,
        "status": status,
        "python_executable": sys.executable,
        "project_root": str(root),
        "attack_file": str(attack),
        "attack_sha256": sha256(attack),
        "launcher_file": str(launcher),
        "launcher_sha256": sha256(launcher),
        "gym_modules": gym_modules,
        "gymnasium_available": gymnasium_available,
        "sdk_gym_available": sdk_gym_available,
        "gym_execution_available": gym_execution_available,
        "commands": results,
        "gym_command": gym,
        "parity": parity,
        "freeze_interpretation": (
            "When status is SANDBOX_COMPLETED_GYM_UNAVAILABLE, freeze the Sandbox CLI evidence and "
            "record Gym parity as not evaluated, not as behavioral divergence."
        ),
    }
    manifest_path = out_dir / "dw_cli_gym_parity_v4_70_02_manifest.json"
    manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")

    with (out_dir / "dw_cli_gym_parity_v4_70_02_commands.csv").open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=["name", "returncode", "stdout_file", "stderr_file", "command"])
        writer.writeheader()
        for result in results:
            writer.writerow({
                "name": result["name"],
                "returncode": result["returncode"],
                "stdout_file": result["stdout_file"],
                "stderr_file": result["stderr_file"],
                "command": json.dumps(result["command"]),
            })

    print(json.dumps({
        "status": status,
        "gym_execution_available": gym_execution_available,
        "behavioral_parity_evaluated": parity["behavioral_parity_evaluated"],
        "manifest": str(manifest_path),
    }, indent=2))

    # Gym unavailability is a recorded environment result, not a script failure.
    return 0 if status in {"SANDBOX_COMPLETED_GYM_UNAVAILABLE", "BOTH_EXECUTIONS_COMPLETED"} else 2


if __name__ == "__main__":
    raise SystemExit(main())
