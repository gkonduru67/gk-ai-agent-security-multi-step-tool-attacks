#!/usr/bin/env python3
"""TRANSPORT_SCHEMA_PROBE_v1_0

READ-ONLY schema map of server_transport.jsonl records.

Purpose: RAW_HARMONY_BODY_INSPECTION_v1_0 under-reached -- its body locator only
found 64-byte metadata strings and never reached the real ~29KB response body
(none of its decoded candidates matched the known M3B body digest 248DC39F...).
This probe fixes that by dumping the EXACT KEY STRUCTURE of each transport record
so the v1_1 decoder can be pointed at the confirmed JSON path to the response body.

Discipline:
  - Reads ONLY the hash-bound transports already verified in v1_0.
  - Emits schema SKELETON only: key paths, value TYPES, container sizes, and string
    LENGTHS. Every string value is REDACTED to <STR len=N sha16=...> so no secret
    or model content is written to disk. No base64/harmony decode is performed here.
  - No model, no Sandbox, no baseline, no attack optimization, no token forging.
  - For each record, it computes the SHA-256 of every string field and flags any
    field whose digest equals the known M3B body digest 248DC39F..., pinpointing the
    exact path to the real response body without ever printing the body itself.

Output: a per-transport schema tree, a ranked list of candidate body paths (by
string length and by digest match), and an explicit CONFIRMED_BODY_PATH when the
248DC39F digest is located.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

VERSION = "TRANSPORT_SCHEMA_PROBE_v1.0"

# Known M3B response-body digest (from ex6f_m3b BUDGET_CORRECTION evidence).
KNOWN_M3B_BODY_SHA256 = "248DC39F8D9F7A3EA46B3476D75326ADB41B87CCA7863F6605ECBF5E9AFC3D48"

# Hash-bound transports (verified in v1_0). Absent files are recorded NOT_PROVIDED.
TRANSPORTS = {
    "M3B": ("server_transport.jsonl",
            "D8A03069427CCDD441AF53BCD9B660B58C323F38F6E19007B8FACA0D2F135CE1"),
    "v1_1_seed_26100": ("server_transport_seed_26100.jsonl",
                        "39486442DECC930144008AB369A1A891D317468AE1AD6F0CD94949AA33306B15"),
    "v1_1_seed_26103": ("server_transport_seed_26103.jsonl",
                        "C51843E43AFD2634BA5D856F0D4824761872CEA582029772C03C76897B8911D3"),
    "v1_1_seed_26105": ("server_transport_seed_26105.jsonl",
                        "BF49BB74BA456BCEE803A2517A0D3A627ED99520E728CBAC37BD1DD833ADA7CB"),
}

# Keys whose names suggest they carry the response body/content (for ranking only).
BODY_HINT_KEYS = ("body", "content", "raw", "text", "response", "message", "delta",
                  "choices", "output", "completion", "data", "result")


def now() -> str:
    return datetime.now(timezone.utc).isoformat()


def need(v: bool, m: str) -> None:
    if not v:
        raise ValueError(m)


def sha_bytes(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest().upper()


def sha_text(s: str) -> str:
    return sha_bytes(s.encode("utf-8", "surrogatepass"))


def sha_file(p: Path, chunk: int = 1 << 20) -> str:
    h = hashlib.sha256()
    with Path(p).open("rb") as f:
        for b in iter(lambda: f.read(chunk), b""):
            h.update(b)
    return h.hexdigest().upper()


def ident(p: Path) -> dict[str, Any]:
    p = Path(p).resolve()
    return {"artifact": p.name, "path": str(p), "size_bytes": p.stat().st_size, "sha256": sha_file(p)}


def write_json(p: Path, v: Any) -> None:
    with Path(p).open("x", encoding="utf-8", newline="\n") as f:
        json.dump(v, f, indent=2, sort_keys=True, ensure_ascii=False, default=str)
        f.write("\n")


def write_csv(p: Path, rows: list[dict[str, Any]], fields: list[str]) -> None:
    import csv
    with Path(p).open("x", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fields, extrasaction="ignore", lineterminator="\n")
        w.writeheader(); w.writerows(rows)


def add(rows, cid, cat, ok, obs, exp, layer):
    rows.append({"check_id": cid, "category": cat, "passed": bool(ok),
                 "observed": json.dumps(obs, default=str)[:2000],
                 "expected": str(exp), "failure_layer": layer})


def read_jsonl(p: Path) -> list[Any]:
    out = []
    for line in Path(p).read_text(encoding="utf-8", errors="replace").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            out.append(json.loads(line))
        except Exception:
            out.append({"_UNPARSED_LINE": True, "_len": len(line), "_sha16": sha_text(line)[:16]})
    return out


def redact_scalar(v: Any) -> Any:
    """Return a type/length descriptor, never the value itself."""
    if isinstance(v, str):
        return f"<STR len={len(v)} sha16={sha_text(v)[:16]}>"
    if isinstance(v, bool):
        return f"<BOOL {v}>"
    if isinstance(v, int):
        return f"<INT>"
    if isinstance(v, float):
        return f"<FLOAT>"
    if v is None:
        return "<NULL>"
    return f"<{type(v).__name__}>"


def schema_tree(obj: Any, depth: int = 0, max_depth: int = 10) -> Any:
    """Recursively build a redacted schema skeleton (no raw string values)."""
    if depth > max_depth:
        return "<...max_depth...>"
    if isinstance(obj, dict):
        return {k: schema_tree(v, depth + 1, max_depth) for k, v in obj.items()}
    if isinstance(obj, list):
        head = obj[:3]
        return {"__list_len__": len(obj),
                "__items__": [schema_tree(x, depth + 1, max_depth) for x in head]}
    return redact_scalar(obj)


def walk_strings(obj: Any, path: str, acc: list[dict[str, Any]], depth: int = 0) -> None:
    """Collect every string field with its path, length, and sha256 (value redacted)."""
    if depth > 12:
        return
    if isinstance(obj, str):
        acc.append({"path": path, "len": len(obj), "sha256": sha_text(obj),
                    "sha16": sha_text(obj)[:16]})
        return
    if isinstance(obj, dict):
        for k, v in obj.items():
            walk_strings(v, f"{path}.{k}" if path else str(k), acc, depth + 1)
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            walk_strings(v, f"{path}[{i}]", acc, depth + 1)


def rank_body_candidates(strings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Rank string fields as likely response bodies: digest-match first, then hint-key
    membership, then raw length."""
    def score(s: dict[str, Any]) -> tuple:
        digest_match = 1 if s["sha256"] == KNOWN_M3B_BODY_SHA256 else 0
        hint = 1 if any(h in s["path"].lower() for h in BODY_HINT_KEYS) else 0
        return (digest_match, hint, s["len"])
    return sorted(strings, key=score, reverse=True)


def resolve(run_dir: Path, hint: str) -> Path | None:
    d = run_dir / hint
    if d.is_file():
        return d
    hits = sorted(run_dir.rglob(hint))
    return hits[0] if hits else None


def main(a: argparse.Namespace) -> None:
    out = Path(a.output_dir).resolve()
    need(not out.exists(), f"Refusing overwrite: {out}")
    out.mkdir(parents=True)
    checks: list[dict[str, Any]] = []
    scope = {"model_executed": False, "sandbox_instantiated": False, "baseline_modified": False,
             "attack_optimization": False, "token_forging_used": False, "secret_values_emitted": False,
             "read_only": True, "files_read": 0}
    per_transport: list[dict[str, Any]] = []
    try:
        m3b_dir = Path(a.m3b_dir).resolve()
        v11_dir = Path(a.v1_1_dir).resolve() if a.v1_1_dir else None
        need(m3b_dir.is_dir(), f"m3b_dir missing: {m3b_dir}")

        # --- Resolve + hash-bind each transport ---
        resolved: list[tuple[str, Path]] = []
        idx = 1
        for label, (hint, digest) in TRANSPORTS.items():
            base = m3b_dir if label == "M3B" else (v11_dir or m3b_dir)
            p = resolve(base, hint)
            if p is None:
                add(checks, f"SP-{idx:03d}", "transport_presence", True,
                    {"label": label, "status": "NOT_PROVIDED"}, "optional", "FIXTURE")
                idx += 1
                continue
            x = ident(p)
            match = x["sha256"] == digest
            add(checks, f"SP-{idx:03d}", "transport_identity", match, x, {"sha256": digest}, "FIXTURE")
            need(match, f"Digest mismatch for {label}: {p}")
            scope["files_read"] += 1
            idx += 1
            resolved.append((label, p))
        need(resolved, "No transports available to probe")

        # --- Schema map + string inventory + body-path ranking per transport ---
        confirmed_body_paths: dict[str, str] = {}
        for label, p in resolved:
            records = read_jsonl(p)
            rec_schemas = []
            all_strings_ranked = []
            for ri, rec in enumerate(records):
                skeleton = schema_tree(rec)
                strings: list[dict[str, Any]] = []
                walk_strings(rec, "", strings)
                ranked = rank_body_candidates(strings)
                digest_hit = next((s for s in ranked if s["sha256"] == KNOWN_M3B_BODY_SHA256), None)
                rec_schemas.append({
                    "record_index": ri,
                    "top_level_keys": (sorted(rec.keys()) if isinstance(rec, dict) else "<non-dict>"),
                    "schema_skeleton": skeleton,
                    "string_field_count": len(strings),
                    "longest_string": (ranked[0] if ranked else None),
                    "top5_string_candidates": ranked[:5],
                    "m3b_body_digest_hit_path": (digest_hit["path"] if digest_hit else None),
                })
                if digest_hit and label == "M3B":
                    confirmed_body_paths[label] = digest_hit["path"]
                all_strings_ranked.extend(ranked[:5])
            per_transport.append({
                "transport": label,
                "path": str(p),
                "record_count": len(records),
                "records": rec_schemas,
            })

        # --- Checks ---
        m3b_found = "M3B" in confirmed_body_paths
        add(checks, f"SP-{idx:03d}", "m3b_body_path_located", m3b_found,
            {"confirmed_body_path": confirmed_body_paths.get("M3B"),
             "known_digest": KNOWN_M3B_BODY_SHA256},
            "a string field in M3B transport hashes to the known 248DC39F body digest",
            "ADAPTER_PARSE"); idx += 1
        # even if digest not located, we still emit the longest-string path as a candidate
        longest_any = None
        for t in per_transport:
            for r in t["records"]:
                ls = r.get("longest_string")
                if ls and (longest_any is None or ls["len"] > longest_any["len"]):
                    longest_any = {**ls, "transport": t["transport"], "record_index": r["record_index"]}
        add(checks, f"SP-{idx:03d}", "candidate_body_path_present", longest_any is not None,
            {"longest_string_candidate": longest_any},
            "at least one non-trivial string field found as a body candidate",
            "ADAPTER_PARSE"); idx += 1
        add(checks, f"SP-{idx:03d}", "read_only_scope",
            not scope["model_executed"] and not scope["sandbox_instantiated"]
            and not scope["baseline_modified"] and not scope["secret_values_emitted"]
            and not scope["token_forging_used"],
            scope, "schema-only, values redacted, no model/sandbox/baseline", "SCOPE_VIOLATION"); idx += 1

        failed = [c["check_id"] for c in checks if not c["passed"]]

        if m3b_found:
            outcome = "BODY_PATH_CONFIRMED_BY_DIGEST"
            body_path_for_v1_1 = confirmed_body_paths["M3B"]
            reason = ("M3B transport contains a string field whose SHA-256 equals the known "
                      "response-body digest 248DC39F...; point RAW_HARMONY_BODY_INSPECTION_v1_1 at this path.")
        elif longest_any is not None:
            outcome = "BODY_PATH_CANDIDATE_BY_LENGTH_DIGEST_NOT_MATCHED"
            body_path_for_v1_1 = longest_any["path"]
            reason = ("No string field matched the known 248DC39F digest. The transport may store the body "
                      "differently (chunked/streamed deltas, base64, or a separate log). The longest string "
                      "field is provided as a candidate; v1_1 must re-verify its reconstructed-body digest.")
        else:
            outcome = "NO_BODY_CANDIDATE_FOUND"
            body_path_for_v1_1 = None
            reason = ("No non-trivial string body candidate found. The response body is likely NOT in these "
                      "transport records (e.g., streamed to a different sink). A raw-capture probe is required.")

        status = ("TRANSPORT_SCHEMA_PROBE_COMPLETE" if not failed
                  else "TRANSPORT_SCHEMA_PROBE_COMPLETE_WITH_GAPS")
        claim = {
            "allowed": [
                "the transport JSONL schema was mapped read-only with all string values redacted",
                "every string field's length and SHA-256 were computed without emitting the value",
                ("the exact JSON path to the real M3B response body was located by digest match"
                 if m3b_found else
                 "no field matched the known M3B body digest; a length-ranked candidate path is provided"),
            ],
            "prohibited": [
                "treat this as evidence about the guardrail or model behavior",
                "claim the model emitted or did not emit channels (v1_0's premature verdict)",
                "emit or reconstruct any secret or model content",
                "use any decoded content to force or optimize model behavior",
            ],
        }
        result = {
            "version": VERSION, "created_at_utc": now(), "status": status,
            "classification": "READ_ONLY_TRANSPORT_JSONL_SCHEMA_MAP_VALUES_REDACTED",
            "checks": {"total": len(checks), "passed": len(checks) - len(failed),
                       "failed": len(failed), "failed_ids": failed},
            "outcome": outcome, "reason": reason,
            "known_m3b_body_sha256": KNOWN_M3B_BODY_SHA256,
            "confirmed_body_paths": confirmed_body_paths,
            "body_path_for_v1_1": body_path_for_v1_1,
            "per_transport": per_transport,
            "execution_boundaries": scope,
            "scientific_verdict": {
                "guardrail_evaluated": False,
                "model_behavior_claimed": False,
                "harness_trick": "NOT_DEMONSTRATED",
                "robust_security_findings": "NOT_ESTABLISHED",
                "diagnostic_purpose": "LOCATE_RESPONSE_BODY_PATH_FOR_v1_1_DECODER",
            },
            "claim_boundary": claim,
            "next_gate": ("RAW_HARMONY_BODY_INSPECTION_v1_1" if body_path_for_v1_1
                          else "RAW_RESPONSE_CAPTURE_PROBE"),
        }

        outputs = {
            "result": out / "transport_schema_probe_result.json",
            "checks": out / "transport_schema_probe_checks.csv",
            "schema": out / "transport_schema_probe_schema.json",
            "claim": out / "transport_schema_probe_claim_boundary.json",
            "binding": out / "transport_schema_probe_binding.json",
        }
        write_json(outputs["result"], result)
        write_csv(outputs["checks"], checks,
                  ["check_id", "category", "passed", "observed", "expected", "failure_layer"])
        write_json(outputs["schema"], {"per_transport": per_transport,
                                       "known_m3b_body_sha256": KNOWN_M3B_BODY_SHA256,
                                       "confirmed_body_paths": confirmed_body_paths,
                                       "body_path_for_v1_1": body_path_for_v1_1})
        write_json(outputs["claim"], claim)
        write_json(outputs["binding"], {"version": VERSION, "created_at_utc": now(),
                                        "runner": ident(Path(__file__).resolve()),
                                        "m3b_dir": str(m3b_dir),
                                        "v1_1_dir": (str(v11_dir) if v11_dir else None),
                                        "transports_probed": [l for l, _ in resolved],
                                        "execution_boundaries": scope})
        rows = [{**ident(p), "role": "SCHEMA_PROBE_DERIVED"} for p in outputs.values()]
        for _, tp in resolved:
            rows.append({**ident(tp), "role": "SCHEMA_PROBE_INPUT_TRANSPORT"})
        manifest = out / "transport_schema_probe_manifest.csv"
        write_csv(manifest, rows, ["artifact", "role", "size_bytes", "sha256", "path"])
        ext = out / "transport_schema_probe_manifest_external_binding.json"
        write_json(ext, {"version": VERSION, "created_at_utc": now(), "status": status,
                         "manifest_filename": manifest.name, "manifest_sha256": sha_file(manifest),
                         "runner_sha256": sha_file(Path(__file__).resolve()),
                         "checks_total": len(checks), "checks_passed": len(checks) - len(failed),
                         "checks_failed": len(failed), "failed_ids": failed,
                         "outcome": outcome, "body_path_for_v1_1": body_path_for_v1_1,
                         "next_gate": result["next_gate"]})
        print(json.dumps({"status": status, "checks": f"{len(checks) - len(failed)}/{len(checks)}",
                          "failed_ids": failed, "outcome": outcome,
                          "confirmed_body_paths": confirmed_body_paths,
                          "body_path_for_v1_1": body_path_for_v1_1,
                          "manifest_sha256": sha_file(manifest),
                          "next_gate": result["next_gate"]}, indent=2))
    except Exception as exc:  # noqa: BLE001
        (out / "TRANSPORT_SCHEMA_PROBE_FAILED.json").write_text(
            json.dumps({"version": VERSION, "created_at_utc": now(), "status": "BLOCKED",
                        "error_type": type(exc).__name__, "error": str(exc),
                        "checks_frozen": checks, "per_transport_frozen": per_transport,
                        "execution_boundaries": scope}, indent=2, default=str), encoding="utf-8")
        raise


def parse() -> argparse.Namespace:
    p = argparse.ArgumentParser(description=VERSION)
    p.add_argument("--m3b-dir", required=True,
                   help="dir containing server_transport.jsonl (M3B, e.g. ...\\EX6F_M3B_budget_correction\\v6_76)")
    p.add_argument("--v1-1-dir", default=None,
                   help="optional dir containing v1.1 server_transport_seed_*.jsonl")
    p.add_argument("--output-dir", required=True)
    return p.parse_args()


if __name__ == "__main__":
    try:
        main(parse())
    except Exception as exc:  # noqa: BLE001
        print(f"FAILED: {exc}", file=sys.stderr)
        raise SystemExit(1)
