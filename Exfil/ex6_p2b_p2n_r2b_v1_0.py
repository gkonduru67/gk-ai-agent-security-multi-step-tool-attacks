#!/usr/bin/env python3
"""EX6 P2B P2N R2B implementation-plan reconciliation.

Narrow, read-only correction gate for R2A failures Q60 and Q73 only.
It externally binds the frozen R2 and R2A evidence, produces:
  1. an exact prohibited-file path and SHA-256 specification; and
  2. an exact, deterministic canonicalization type-and-byte contract.

This runner does not alter R2/R2A artifacts or SDK sources, create an
implementation, import SDK modules, execute tools/fs.read/Sandbox/Gym,
run predicates or breach logic, read fixture contents, preview/export source
values, or observe effects.
"""
from __future__ import annotations
import argparse, csv, hashlib, json, math, sys, unicodedata
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

VERSION = "EX6_P2B_P2N_R2B_IMPLEMENTATION_PLAN_RECONCILIATION_v1.0"
R2A_VERSION = "EX6_P2B_P2N_R2A_INDEPENDENT_IMPLEMENTATION_READINESS_QUALIFICATION_v1.0"
R2A_STATUS = "P2N_R2A_INDEPENDENT_IMPLEMENTATION_READINESS_QUALIFICATION_COMPLETE_WITH_GAPS"
R2A_MANIFEST_SHA = "54E054AF8F61298927476DD3AD94AD4C5CCB3FE722A64D7AB92B9DCB209A06F5"
R2A_RUNNER_SHA = "7B49B89014A15D9A515E74C655B6FE33CF2EE3EA531BB20293EFE85810C59831"
R2_MANIFEST_SHA = "8864C8ADE722F3893E02C60A13F1CAF06AF8802FD8E0393DDA707AE17FC1BA69"
EXPECTED_FAILURES = ["Q60", "Q73"]
PROHIBITED = {
    "aicomp_sdk/core/env/sandbox.py": "B781375C5AAE3C2533F6992AAE6D3C65CA56B7077822F1A27955756BEF1168D0",
    "aicomp_sdk/core/predicates.py": "9D9DE5118D8883A0074A5405ED85CF2DEC3F68E8516908CBC48F409E3BA56F37",
    "aicomp_sdk/core/tools/fs.py": "4B8C54032ED807CE4C35BAB403EE622141881158E10F600A4B6D329E6D6F95B8",
    "aicomp_sdk/guardrails/optimal.py": "6724FEDF7BBF3E67DFCDD564BA8A73463E0F783D5C84E0A70DCEFF40C1BC61ED",
    "aicomp_sdk/guardrails/trusted_context_adapter_v1_1.py": "BFDE535B805979FF6D13BA0970A9A13466192F1B1111B02CE8B8C670FFA99".replace("B8C", "B8BB8C"),
}
TYPE_ORDER = ["null", "bool", "int", "str", "bytes", "list", "map"]


def now() -> str:
    return datetime.now(timezone.utc).isoformat()


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest().upper()


def identity(path: Path) -> dict[str, Any]:
    path = path.resolve()
    return {"artifact": path.name, "path": str(path), "size_bytes": path.stat().st_size, "sha256": sha256(path)}


def write_json(path: Path, value: Any) -> None:
    with path.open("x", encoding="utf-8", newline="\n") as handle:
        json.dump(value, handle, indent=2, sort_keys=True, ensure_ascii=False)
        handle.write("\n")


def write_csv(path: Path, rows: list[dict[str, Any]], fields: list[str]) -> None:
    with path.open("x", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields, extrasaction="ignore", lineterminator="\n")
        writer.writeheader(); writer.writerows(rows)


def frame(tag: bytes, payload: bytes) -> bytes:
    return tag + str(len(payload)).encode("ascii") + b":" + payload


def canonicalize(value: Any) -> bytes:
    """Reference oracle for the proposed P2N.CANONICAL_OUTPUT.V1 contract."""
    if value is None:
        return frame(b"N", b"")
    if isinstance(value, bool):
        return frame(b"B", b"1" if value else b"0")
    if isinstance(value, int) and not isinstance(value, bool):
        return frame(b"I", str(value).encode("ascii"))
    if isinstance(value, float):
        raise TypeError("float prohibited, including finite and non-finite values")
    if isinstance(value, str):
        return frame(b"S", unicodedata.normalize("NFC", value).encode("utf-8"))
    if isinstance(value, bytes):
        return frame(b"Y", value)
    if isinstance(value, list):
        payload = b"".join(canonicalize(item) for item in value)
        return frame(b"L", payload)
    if isinstance(value, tuple):
        raise TypeError("tuple prohibited; caller must supply list explicitly")
    if isinstance(value, dict):
        normalized: dict[str, Any] = {}
        for key, item in value.items():
            if not isinstance(key, str):
                raise TypeError("map keys must be strings")
            key_nfc = unicodedata.normalize("NFC", key)
            if key_nfc in normalized:
                raise ValueError("duplicate key after NFC normalization")
            normalized[key_nfc] = item
        payload = b""
        for key in sorted(normalized, key=lambda x: x.encode("utf-8")):
            payload += frame(b"K", key.encode("utf-8")) + canonicalize(normalized[key])
        return frame(b"M", payload)
    raise TypeError(f"unsupported type: {type(value).__name__}")


def main(args: argparse.Namespace) -> None:
    out = Path(args.output_dir).resolve()
    require(not out.exists(), f"Refusing overwrite: {out}")
    out.mkdir(parents=True)
    controls: list[dict[str, Any]] = []
    try:
        project = Path(args.project_root).resolve()
        inputs = {
            "r2a_result": Path(args.p2n_r2a_result).resolve(),
            "r2a_checks": Path(args.p2n_r2a_checks).resolve(),
            "r2a_prohibited_identities": Path(args.p2n_r2a_prohibited_identities).resolve(),
            "r2a_claim_boundary": Path(args.p2n_r2a_claim_boundary).resolve(),
            "r2a_binding": Path(args.p2n_r2a_binding).resolve(),
            "r2a_external_binding": Path(args.p2n_r2a_external_binding).resolve(),
            "r2a_manifest": Path(args.p2n_r2a_manifest).resolve(),
            "r2a_runner": Path(args.p2n_r2a_runner).resolve(),
            "r2_change_boundaries": Path(args.p2n_r2_change_boundaries).resolve(),
            "r2_helpers": Path(args.p2n_r2_helpers).resolve(),
            "r2_manifest": Path(args.p2n_r2_manifest).resolve(),
        }
        require(project.is_dir(), f"Project root missing: {project}")
        for label, path in inputs.items():
            require(path.is_file(), f"Missing {label}: {path}")

        result = json.loads(inputs["r2a_result"].read_text(encoding="utf-8-sig"))
        external = json.loads(inputs["r2a_external_binding"].read_text(encoding="utf-8-sig"))
        require(result.get("version") == R2A_VERSION and result.get("status") == R2A_STATUS, "R2A parent differs")
        require(result.get("checks", {}).get("failed_ids") == EXPECTED_FAILURES, "R2A failure identity/order differs")
        require(external.get("manifest_sha256") == R2A_MANIFEST_SHA and sha256(inputs["r2a_manifest"]) == R2A_MANIFEST_SHA, "R2A manifest differs")
        require(external.get("runner_sha256") == R2A_RUNNER_SHA and sha256(inputs["r2a_runner"]) == R2A_RUNNER_SHA, "R2A runner differs")
        require(sha256(inputs["r2_manifest"]) == R2_MANIFEST_SHA, "R2 manifest differs")
        require(external.get("implementation_authorized") is False and external.get("actual_fs_read_executed") is False, "R2A boundary differs")

        # Q60 reconciliation: exact full paths plus current identities.
        identity_rows = []
        for rel, expected_hash in PROHIBITED.items():
            path = project / Path(rel)
            require(path.is_file(), f"Prohibited source missing: {rel}")
            observed = sha256(path)
            identity_rows.append({"relative_path": rel, "size_bytes": path.stat().st_size, "sha256": observed, "expected_sha256": expected_hash, "match": observed == expected_hash, "modification": "PROHIBITED"})
        q60_pass = len(identity_rows) == 5 and all(row["match"] for row in identity_rows)
        controls.append({"control_id": "R2B-Q60", "source_failure": "Q60", "passed": q60_pass, "finding": "exact full relative paths and current SHA-256 identities enumerated"})

        # Q73 reconciliation: exact type/byte contract and executable reference oracle controls.
        canonical_spec = {
            "schema": "P2N.CANONICAL_OUTPUT.V1",
            "domain_tag_for_raw_digest": "P2N.RAW_OUTPUT.V1",
            "scope": "post-hook-finalized output only, before serialize_tool_output",
            "framing": "ASCII tag + ASCII decimal payload length without leading zeros + ':' + payload bytes",
            "allowed_types_in_precedence_order": TYPE_ORDER,
            "type_rules": {
                "null": "tag N; empty payload",
                "bool": "tag B; payload ASCII 1 or 0; evaluated before int",
                "int": "tag I; base-10 ASCII, optional leading minus, no plus sign, zero encoded as 0, arbitrary precision",
                "str": "tag S; Unicode NFC normalization followed by UTF-8 without BOM",
                "bytes": "tag Y; raw bytes unchanged",
                "list": "tag L; ordered concatenation of each recursively framed item; tuple is prohibited",
                "map": "tag M; string keys only; keys NFC-normalized; duplicate normalized keys rejected; entries sorted by normalized UTF-8 key bytes; each key framed with tag K, followed by recursively framed value",
            },
            "prohibited": [
                "float, including NaN and infinities",
                "tuple",
                "set and frozenset",
                "non-string map keys",
                "duplicate map keys after NFC normalization",
                "custom objects",
                "implicit string conversion",
            ],
            "raw_digest_bytes": "UTF-8 bytes of domain tag P2N.RAW_OUTPUT.V1, one zero byte separator, then canonical framed bytes",
            "raw_digest_output": "SHA-256 uppercase hexadecimal, exactly 64 characters",
            "failure_semantics": "raise before digest production; do not call after_tool; do not create protected-read record",
            "raw_value_artifact_policy": "canonical payload bytes and raw values must not be written to evidence artifacts",
        }
        vectors = [
            ("null", None), ("false", False), ("true", True), ("zero", 0),
            ("negative_int", -12), ("unicode_nfc", "e\u0301"), ("bytes", b"\x00A"),
            ("list", [1, "x", None]), ("map_order", {"b": 2, "a": 1}),
        ]
        vector_rows = []
        for vector_id, value in vectors:
            encoded = canonicalize(value)
            digest_input = b"P2N.RAW_OUTPUT.V1\x00" + encoded
            vector_rows.append({"vector_id": vector_id, "type": type(value).__name__, "canonical_length": len(encoded), "canonical_sha256": hashlib.sha256(encoded).hexdigest().upper(), "raw_digest_sha256": hashlib.sha256(digest_input).hexdigest().upper(), "raw_value_exported": False})
        negative_vectors = [
            ("float", 1.0), ("nan", float("nan")), ("tuple", (1, 2)),
            ("set", {1}), ("nonstring_key", {1: "x"}),
        ]
        negatives_pass = True
        for vector_id, value in negative_vectors:
            rejected = False
            try: canonicalize(value)
            except (TypeError, ValueError): rejected = True
            negatives_pass = negatives_pass and rejected
            vector_rows.append({"vector_id": vector_id, "type": type(value).__name__, "canonical_length": "", "canonical_sha256": "", "raw_digest_sha256": "", "raw_value_exported": False, "rejected": rejected})
        q73_pass = len(canonical_spec["allowed_types_in_precedence_order"]) == 7 and negatives_pass and all(len(r["raw_digest_sha256"]) == 64 for r in vector_rows if r.get("raw_digest_sha256"))
        controls.append({"control_id": "R2B-Q73", "source_failure": "Q73", "passed": q73_pass, "finding": "exact allowed types, framing, normalization, ordering, prohibited types, digest input, and failure semantics specified"})

        failed = [row["control_id"] for row in controls if not row["passed"]]
        status = "P2N_R2B_IMPLEMENTATION_PLAN_RECONCILIATION_COMPLETE_PASS" if not failed else "P2N_R2B_IMPLEMENTATION_PLAN_RECONCILIATION_COMPLETE_WITH_GAPS"
        next_gate = "EX6_P2B_P2N_R2C_INDEPENDENT_RECONCILIATION_QUALIFICATION" if not failed else "EX6_P2B_P2N_R2B_R1_RECONCILIATION_REVIEW"
        claim = {
            "allowed": ["Q60 exact prohibited-file specification", "Q73 exact canonicalization specification", "reference-oracle control results", "reconciliation eligibility recommendation"],
            "prohibited": ["implementation existence", "source modification", "runtime wiring", "actual fs.read behavior", "source retrieval success", "secret capture", "protected-value lineage", "authorization transport correctness", "guardrail effectiveness", "real exfiltration prevention"],
        }
        result_out = {
            "version": VERSION, "created_at_utc": now(), "status": status,
            "classification": "READ_ONLY_IMPLEMENTATION_PLAN_RECONCILIATION",
            "P2N_R2A_parent_verified": True,
            "reconciled_controls": {"total": 2, "passed": 2-len(failed), "failed": len(failed), "failed_ids": failed},
            "Q60": {"status": "RECONCILED" if q60_pass else "GAP", "exact_path_count": len(identity_rows), "all_current_hashes_match": q60_pass},
            "Q73": {"status": "RECONCILED" if q73_pass else "GAP", "canonical_schema": canonical_spec["schema"], "positive_vectors": len(vectors), "negative_vectors": len(negative_vectors)},
            "readiness": {"implementation_readiness_reconciliation_complete": not failed, "separate_independent_qualification_required": True, "implementation_authorized": False, "implementation_created": False, "identity_freeze_eligible": False, "controlled_actual_fs_read_eligible": False},
            "execution_boundaries": {"source_modified": False, "implementation_created": False, "sdk_modules_imported": False, "actual_fs_read_executed": False, "tools_executed": False, "fixture_contents_read": False, "source_value_previewed": False, "source_value_exported": False, "effects_observed": False, "sandbox_executed": False, "gym_executed": False, "predicates_executed": False, "breach_executed": False, "models_used": False},
            "scientific_verdict": {"implementation_plan_reconciliation": "ESTABLISHED_AS_SPECIFICATION_ONLY" if not failed else "GAPS_IDENTIFIED", "canonicalization_runtime_behavior": "NOT_EVALUATED", "implementation": "NOT_IMPLEMENTED", "actual_source_retrieval": "NOT_EVALUATED", "secret_capture": "NOT_ESTABLISHED", "protected_value_lineage": "NOT_ESTABLISHED", "authorization_transport_correctness": "NOT_ESTABLISHED", "harness_trick": "NOT_DEMONSTRATED", "robust_security_findings": "NOT_ESTABLISHED"},
            "claim_boundary": claim, "next_gate": next_gate,
        }

        rp=out/"ex6_p2b_p2n_r2b_result.json"; cp=out/"ex6_p2b_p2n_r2b_controls.csv"; pp=out/"ex6_p2b_p2n_r2b_prohibited_files.csv"; sp=out/"ex6_p2b_p2n_r2b_canonicalization_spec.json"; vp=out/"ex6_p2b_p2n_r2b_canonicalization_vectors.csv"; cl=out/"ex6_p2b_p2n_r2b_claim_boundary.json"; bp=out/"ex6_p2b_p2n_r2b_binding.json"
        write_json(rp,result_out); write_csv(cp,controls,["control_id","source_failure","passed","finding"]); write_csv(pp,identity_rows,["relative_path","size_bytes","sha256","expected_sha256","match","modification"]); write_json(sp,canonical_spec); write_csv(vp,vector_rows,["vector_id","type","canonical_length","canonical_sha256","raw_digest_sha256","raw_value_exported","rejected"]); write_json(cl,claim); write_json(bp,{"version":VERSION,"created_at_utc":now(),"runner":identity(Path(__file__).resolve()),"inputs":{k:identity(v) for k,v in inputs.items()},"project_root":str(project),"source_modified":False,"implementation_created":False})
        derived=(rp,cp,pp,sp,vp,cl,bp); bound=tuple(inputs.values()); manifest_rows=[{**identity(p),"role":"P2N_R2B_DERIVED"} for p in derived]+[{**identity(p),"role":"P2N_R2B_BOUND"} for p in bound]
        mp=out/"ex6_p2b_p2n_r2b_manifest.csv"; write_csv(mp,manifest_rows,["artifact","role","size_bytes","sha256","path"])
        ep=out/"ex6_p2b_p2n_r2b_manifest_external_binding.json"; write_json(ep,{"version":VERSION,"created_at_utc":now(),"status":status,"manifest_filename":mp.name,"manifest_size_bytes":mp.stat().st_size,"manifest_sha256":sha256(mp),"runner_sha256":sha256(Path(__file__).resolve()),"parent_r2a_manifest_sha256":R2A_MANIFEST_SHA,"reconciled_controls":2,"implementation_authorized":False,"implementation_created":False,"identity_freeze_eligible":False,"controlled_actual_fs_read_eligible":False,"source_modified":False,"actual_fs_read_executed":False,"next_gate":next_gate})
        print(json.dumps({"status":status,"reconciled_controls":2,"failed_ids":failed,"implementation_authorized":False,"controlled_actual_fs_read_eligible":False,"manifest_sha256":sha256(mp),"next_gate":next_gate},indent=2))
    except Exception as exc:
        (out/"P2N_R2B_FAILED.json").write_text(json.dumps({"version":VERSION,"created_at_utc":now(),"status":"P2N_R2B_RECONCILIATION_BLOCKED","error_type":type(exc).__name__,"error":str(exc),"controls_frozen":controls,"source_modified":False,"implementation_created":False,"actual_fs_read_executed":False,"effects_observed":False},indent=2),encoding="utf-8")
        raise


def parse_args() -> argparse.Namespace:
    p=argparse.ArgumentParser(description=VERSION)
    for flag in ["p2n-r2a-result","p2n-r2a-checks","p2n-r2a-prohibited-identities","p2n-r2a-claim-boundary","p2n-r2a-binding","p2n-r2a-external-binding","p2n-r2a-manifest","p2n-r2a-runner","p2n-r2-change-boundaries","p2n-r2-helpers","p2n-r2-manifest","project-root","output-dir"]:
        p.add_argument("--"+flag,required=True)
    return p.parse_args()

if __name__=="__main__":
    try: main(parse_args())
    except Exception as exc: print(f"FAILED: {exc}",file=sys.stderr); raise SystemExit(1)
