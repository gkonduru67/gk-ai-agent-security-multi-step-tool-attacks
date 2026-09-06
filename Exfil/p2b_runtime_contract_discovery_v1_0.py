#!/usr/bin/env python3
"""P2B read-only runtime-contract discovery.

Searches frozen textual artifacts for candidate runtime-contract evidence and
records raw matches plus file identities. It DOES NOT import inspected Python,
execute SDK/model/Sandbox/Gym/tools/guardrails/predicates/breach logic, mutate
fixtures, or automatically resolve conflicting/default configuration values.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

VERSION = "P2B_RUNTIME_CONTRACT_DISCOVERY_v1.0"
SEARCH_TERMS = (
    "max_tool_hops", "max-tool-hops", "tool_choice", "temperature",
    "max_new_tokens", "max-new-tokens", "server_url", "server-url",
    "127.0.0.1:8080", "EX5_PROMPT", "EX5_PROMPT_SHA", "PROTECTED_PATH",
    "model_path", "model-path", "seed", "seeds",
)
TEXT_SUFFIXES = {".json", ".csv", ".txt", ".py", ".md", ".log", ".yaml", ".yml"}


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest().upper()


def identity(path: Path) -> dict:
    return {
        "artifact": path.name,
        "path": str(path.resolve()),
        "size_bytes": path.stat().st_size,
        "sha256": sha256_file(path),
    }


def inspect_file(path: Path) -> list[dict]:
    try:
        text = path.read_text(encoding="utf-8-sig", errors="replace")
    except Exception as exc:
        return [{"read_error": f"{type(exc).__name__}: {exc}"}]
    matches = []
    for n, line in enumerate(text.splitlines(), 1):
        low = line.lower()
        terms = [t for t in SEARCH_TERMS if t.lower() in low]
        if terms:
            matches.append({"line_number": n, "matched_terms": terms, "raw_line": line})
    return matches


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--v1-2-dir", required=True, type=Path)
    ap.add_argument("--experiment-runner", required=True, type=Path)
    ap.add_argument("--output-dir", required=True, type=Path)
    a = ap.parse_args()

    v12 = a.v1_2_dir.resolve()
    runner = a.experiment_runner.resolve()
    out = a.output_dir.resolve()
    if not v12.is_dir():
        raise SystemExit(f"FAILED: v1.2 directory not found: {v12}")
    if not runner.is_file():
        raise SystemExit(f"FAILED: experiment runner not found: {runner}")
    if out.exists():
        raise SystemExit(f"FAILED: refusing to overwrite existing output directory: {out}")
    out.mkdir(parents=True)

    candidates = [p for p in sorted(v12.rglob("*")) if p.is_file() and p.suffix.lower() in TEXT_SUFFIXES]
    candidates.append(runner)
    unique, seen = [], set()
    for p in candidates:
        key = str(p.resolve()).casefold()
        if key not in seen:
            seen.add(key); unique.append(p)

    evidence, read_errors = [], []
    for p in unique:
        matches = inspect_file(p)
        if matches and "read_error" in matches[0]:
            read_errors.append({**identity(p), **matches[0]})
        elif matches:
            evidence.append({**identity(p), "matches": matches})

    report = {
        "version": VERSION,
        "created_at_utc": datetime.now(timezone.utc).isoformat(),
        "status": "DISCOVERY_COMPLETE" if not read_errors else "DISCOVERY_COMPLETE_WITH_READ_ERRORS",
        "sources": {"v1_2_directory": str(v12), "experiment_runner": str(runner)},
        "search_terms": list(SEARCH_TERMS),
        "matched_artifact_count": len(evidence),
        "read_error_count": len(read_errors),
        "evidence": evidence,
        "read_errors": read_errors,
        "interpretation": {
            "actual_v1_2_max_tool_hops": "NOT_ESTABLISHED_AUTOMATICALLY",
            "actual_v1_2_model_path": "NOT_ESTABLISHED_AUTOMATICALLY",
            "rule": "Raw discovery only. Defaults, prose, and conflicting values are not promoted to effective runtime values automatically."
        },
        "execution_boundary": {
            "read_only_inputs": True, "inspected_python_imported": False,
            "inspected_files_executed": False, "model_executed": False,
            "sdk_executed": False, "sandbox_executed": False, "gym_executed": False,
            "tool_executed": False, "guardrail_executed": False,
            "predicate_executed": False, "breach_executed": False,
            "fixture_modified": False, "attack_optimization": False,
        },
        "claim_boundary": {
            "allowed": ["identify candidate runtime-contract evidence", "record exact raw matching lines", "record identities of matched artifacts"],
            "prohibited": ["infer effective runtime value from a default alone", "claim runtime behavior", "claim treatment behavior", "claim harness trick", "claim robust security", "claim hosted parity"]
        },
        "next_gate": "P2B_RUNTIME_CONTRACT_DISCOVERY_REVIEW",
    }

    result = out / "p2b_runtime_contract_discovery_result_v1_0.json"
    result.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    runner_id = identity(Path(__file__).resolve())
    manifest = {
        "version": VERSION,
        "result": identity(result),
        "runner": runner_id,
        "source_count_scanned": len(unique),
        "matched_artifact_count": len(evidence),
        "read_error_count": len(read_errors),
    }
    manifest_path = out / "p2b_runtime_contract_discovery_manifest_v1_0.json"
    manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    binding = {
        "version": VERSION,
        "manifest_filename": manifest_path.name,
        "manifest_sha256": sha256_file(manifest_path),
        "runner_sha256": runner_id["sha256"],
        "status": report["status"],
        "next_gate": report["next_gate"],
    }
    binding_path = out / "p2b_runtime_contract_discovery_manifest_external_binding_v1_0.json"
    binding_path.write_text(json.dumps(binding, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    print(json.dumps({
        "status": report["status"],
        "source_count_scanned": len(unique),
        "matched_artifact_count": len(evidence),
        "read_error_count": len(read_errors),
        "result_sha256": sha256_file(result),
        "manifest_sha256": sha256_file(manifest_path),
        "runner_sha256": runner_id["sha256"],
        "next_gate": report["next_gate"],
    }, indent=2))


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        print(f"FAILED: {type(exc).__name__}: {exc}", file=sys.stderr)
        raise SystemExit(1)
