#!/usr/bin/env python3
"""EX6 P2B P2N R2C independent reconciliation qualification.

Read-only independent qualification of R2B corrections for Q60 and Q73.
Verifies parent identity/binding, exact protected-file enumeration, current
source hashes, canonicalization specification completeness, independently
recomputed positive/negative vectors, claim boundaries, and freeze readiness.

Does not modify source, create implementation, import SDK modules, execute
fs.read/tools/Sandbox/Gym/predicates/breach/models, read fixture contents,
preview/export protected values, or observe effects.
"""
from __future__ import annotations
import argparse, csv, hashlib, json, sys, unicodedata
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

VERSION = "EX6_P2B_P2N_R2C_INDEPENDENT_RECONCILIATION_QUALIFICATION_v1.0"
PARENT_VERSION = "EX6_P2B_P2N_R2B_IMPLEMENTATION_PLAN_RECONCILIATION_v1.0"
PARENT_STATUS = "P2N_R2B_IMPLEMENTATION_PLAN_RECONCILIATION_COMPLETE_PASS"
PARENT_MANIFEST_SHA = "437C04FB241546A1AB94FA39FBC531E403B490174A1E092FBA6114B8C3B98BD0"
PARENT_RUNNER_SHA = "9ED6824309D83AD8668CE82B8E53E43DC4164A98532AF4EFD2235D391CF05DDD"
R2A_MANIFEST_SHA = "54E054AF8F61298927476DD3AD94AD4C5CCB3FE722A64D7AB92B9DCB209A06F5"
EXPECTED_PATHS = {
    "aicomp_sdk/core/env/sandbox.py": "B781375C5AAE3C2533F6992AAE6D3C65CA56B7077822F1A27955756BEF1168D0",
    "aicomp_sdk/core/predicates.py": "9D9DE5118D8883A0074A5405ED85CF2DEC3F68E8516908CBC48F409E3BA56F37",
    "aicomp_sdk/core/tools/fs.py": "4B8C54032ED807CE4C35BAB403EE622141881158E10F600A4B6D329E6D6F95B8",
    "aicomp_sdk/guardrails/optimal.py": "6724FEDF7BBF3E67DFCDD564BA8A73463E0F783D5C84E0A70DCEFF40C1BC61ED",
    "aicomp_sdk/guardrails/trusted_context_adapter_v1_1.py": "BFDE535B805979FF6D13BA0970A9A13466192F1B1111B02CE8B8BB8C670FFA99",
}
EXPECTED_TYPES = ["null", "bool", "int", "str", "bytes", "list", "map"]
POSITIVE = {
    "null": None, "false": False, "true": True, "zero": 0,
    "negative_int": -12, "unicode_nfc": "e\u0301", "bytes": b"\x00A",
    "list": [1, "x", None], "map_order": {"b": 2, "a": 1},
}
NEGATIVE = {
    "float": 1.0, "nan": float("nan"), "tuple": (1, 2),
    "set": {1}, "nonstring_key": {1: "x"},
}


def now(): return datetime.now(timezone.utc).isoformat()
def require(c, m):
    if not c: raise ValueError(m)
def digest(path: Path):
    h = hashlib.sha256()
    with path.open("rb") as f:
        for block in iter(lambda: f.read(1024 * 1024), b""): h.update(block)
    return h.hexdigest().upper()
def identity(path: Path):
    path = path.resolve()
    return {"artifact": path.name, "path": str(path), "size_bytes": path.stat().st_size, "sha256": digest(path)}
def write_json(path, obj):
    with path.open("x", encoding="utf-8", newline="\n") as f:
        json.dump(obj, f, indent=2, sort_keys=True, ensure_ascii=False); f.write("\n")
def write_csv(path, rows, fields):
    with path.open("x", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fields, extrasaction="ignore", lineterminator="\n"); w.writeheader(); w.writerows(rows)
def add(rows, cid, category, passed, observed, expected, layer):
    rows.append({"check_id": cid, "category": category, "passed": bool(passed), "observed": str(observed), "expected": str(expected), "failure_layer": layer})
def frame(tag: bytes, payload: bytes):
    return tag + str(len(payload)).encode("ascii") + b":" + payload
def canonicalize(value: Any) -> bytes:
    if value is None: return frame(b"N", b"")
    if isinstance(value, bool): return frame(b"B", b"1" if value else b"0")
    if isinstance(value, int) and not isinstance(value, bool): return frame(b"I", str(value).encode("ascii"))
    if isinstance(value, float): raise TypeError("float prohibited")
    if isinstance(value, str): return frame(b"S", unicodedata.normalize("NFC", value).encode("utf-8"))
    if isinstance(value, bytes): return frame(b"Y", value)
    if isinstance(value, list): return frame(b"L", b"".join(canonicalize(x) for x in value))
    if isinstance(value, tuple): raise TypeError("tuple prohibited")
    if isinstance(value, dict):
        normalized = {}
        for key, item in value.items():
            if not isinstance(key, str): raise TypeError("string keys only")
            k = unicodedata.normalize("NFC", key)
            if k in normalized: raise ValueError("duplicate NFC key")
            normalized[k] = item
        payload = b"".join(frame(b"K", k.encode("utf-8")) + canonicalize(normalized[k]) for k in sorted(normalized, key=lambda x: x.encode("utf-8")))
        return frame(b"M", payload)
    raise TypeError("unsupported type")


def main(a):
    out = Path(a.output_dir).resolve(); require(not out.exists(), f"Refusing overwrite: {out}"); out.mkdir(parents=True)
    checks = []
    try:
        project = Path(a.project_root).resolve(); require(project.is_dir(), f"Missing project root: {project}")
        inputs = {
            "result": Path(a.p2n_r2b_result).resolve(),
            "controls": Path(a.p2n_r2b_controls).resolve(),
            "prohibited_files": Path(a.p2n_r2b_prohibited_files).resolve(),
            "canonicalization_spec": Path(a.p2n_r2b_canonicalization_spec).resolve(),
            "canonicalization_vectors": Path(a.p2n_r2b_canonicalization_vectors).resolve(),
            "claim_boundary": Path(a.p2n_r2b_claim_boundary).resolve(),
            "binding": Path(a.p2n_r2b_binding).resolve(),
            "external_binding": Path(a.p2n_r2b_external_binding).resolve(),
            "manifest": Path(a.p2n_r2b_manifest).resolve(),
            "runner": Path(a.p2n_r2b_runner).resolve(),
        }
        for name, path in inputs.items(): require(path.is_file(), f"Missing R2B {name}: {path}")
        result = json.loads(inputs["result"].read_text(encoding="utf-8-sig"))
        spec = json.loads(inputs["canonicalization_spec"].read_text(encoding="utf-8-sig"))
        claim = json.loads(inputs["claim_boundary"].read_text(encoding="utf-8-sig"))
        binding = json.loads(inputs["binding"].read_text(encoding="utf-8-sig"))
        external = json.loads(inputs["external_binding"].read_text(encoding="utf-8-sig"))
        control_rows = list(csv.DictReader(inputs["controls"].open(encoding="utf-8-sig", newline="")))
        file_rows = list(csv.DictReader(inputs["prohibited_files"].open(encoding="utf-8-sig", newline="")))
        vector_rows = list(csv.DictReader(inputs["canonicalization_vectors"].open(encoding="utf-8-sig", newline="")))

        add(checks, "Q01", "parent_binding", result.get("version") == PARENT_VERSION and result.get("status") == PARENT_STATUS, result.get("status"), PARENT_STATUS, "FIXTURE")
        add(checks, "Q02", "parent_binding", digest(inputs["manifest"]) == PARENT_MANIFEST_SHA and external.get("manifest_sha256") == PARENT_MANIFEST_SHA, digest(inputs["manifest"]), PARENT_MANIFEST_SHA, "FIXTURE")
        add(checks, "Q03", "parent_binding", digest(inputs["runner"]) == PARENT_RUNNER_SHA and external.get("runner_sha256") == PARENT_RUNNER_SHA, digest(inputs["runner"]), PARENT_RUNNER_SHA, "FIXTURE")
        add(checks, "Q04", "parent_binding", external.get("parent_r2a_manifest_sha256") == R2A_MANIFEST_SHA, external.get("parent_r2a_manifest_sha256"), R2A_MANIFEST_SHA, "FIXTURE")
        add(checks, "Q05", "parent_binding", binding.get("source_modified") is False and binding.get("implementation_created") is False, str({"source_modified": binding.get("source_modified"), "implementation_created": binding.get("implementation_created")}), "both false", "CLAIM_BOUNDARY")
        add(checks, "Q06", "parent_controls", len(control_rows) == 2 and all(r.get("passed") == "True" for r in control_rows) and {r.get("control_id") for r in control_rows} == {"R2B-Q60", "R2B-Q73"}, str(control_rows), "two exact passing controls", "EVIDENCE_CLASSIFICATION")

        # Q60 independent verification.
        rows_by_path = {r["relative_path"]: r for r in file_rows}
        add(checks, "Q10", "Q60", set(rows_by_path) == set(EXPECTED_PATHS), ";".join(sorted(rows_by_path)), ";".join(sorted(EXPECTED_PATHS)), "FIXTURE")
        for index, (rel, expected_hash) in enumerate(sorted(EXPECTED_PATHS.items()), 11):
            row = rows_by_path.get(rel, {})
            actual_path = project / Path(rel)
            observed = digest(actual_path) if actual_path.is_file() else "MISSING"
            passed = actual_path.is_file() and row.get("sha256") == expected_hash and row.get("expected_sha256") == expected_hash and row.get("match") == "True" and row.get("modification") == "PROHIBITED" and observed == expected_hash
            add(checks, f"Q{index}", "Q60", passed, f"row={row}; current={observed}", f"exact path/hash/match/prohibition for {rel}", "FIXTURE")

        # Q73 independent specification completeness.
        rules = spec.get("type_rules", {})
        add(checks, "Q20", "Q73_spec", spec.get("schema") == "P2N.CANONICAL_OUTPUT.V1", spec.get("schema"), "P2N.CANONICAL_OUTPUT.V1", "SECRET_CAPTURE")
        add(checks, "Q21", "Q73_spec", spec.get("allowed_types_in_precedence_order") == EXPECTED_TYPES, spec.get("allowed_types_in_precedence_order"), EXPECTED_TYPES, "SECRET_CAPTURE")
        add(checks, "Q22", "Q73_spec", set(rules) == set(EXPECTED_TYPES), ";".join(sorted(rules)), ";".join(sorted(EXPECTED_TYPES)), "SECRET_CAPTURE")
        required_text = ["NFC", "UTF-8", "without BOM", "base-10 ASCII", "evaluated before int", "raw bytes unchanged", "ordered concatenation", "string keys only", "duplicate normalized keys rejected", "sorted by normalized UTF-8 key bytes"]
        rules_text = " ".join(rules.values())
        add(checks, "Q23", "Q73_spec", all(x in rules_text for x in required_text), rules_text, ";".join(required_text), "SECRET_CAPTURE")
        add(checks, "Q24", "Q73_spec", spec.get("framing") == "ASCII tag + ASCII decimal payload length without leading zeros + ':' + payload bytes", spec.get("framing"), "exact framing", "SECRET_CAPTURE")
        add(checks, "Q25", "Q73_spec", len(spec.get("prohibited", [])) == 7 and all(x in " ".join(spec.get("prohibited", [])) for x in ["float", "tuple", "set", "non-string map keys", "duplicate map keys", "custom objects", "implicit string conversion"]), spec.get("prohibited"), "seven explicit prohibition classes", "SECRET_CAPTURE")
        add(checks, "Q26", "Q73_spec", all(x in spec.get("failure_semantics", "") for x in ["before digest production", "do not call after_tool", "do not create protected-read record"]), spec.get("failure_semantics"), "fail closed before digest/after_tool/record", "SECRET_CAPTURE")
        add(checks, "Q27", "Q73_spec", spec.get("raw_digest_bytes") == "UTF-8 bytes of domain tag P2N.RAW_OUTPUT.V1, one zero byte separator, then canonical framed bytes" and spec.get("raw_digest_output") == "SHA-256 uppercase hexadecimal, exactly 64 characters", str({"bytes": spec.get("raw_digest_bytes"), "output": spec.get("raw_digest_output")}), "exact domain-separated SHA-256 contract", "SECRET_CAPTURE")
        add(checks, "Q28", "Q73_spec", spec.get("scope") == "post-hook-finalized output only, before serialize_tool_output" and "must not be written" in spec.get("raw_value_artifact_policy", ""), str({"scope": spec.get("scope"), "policy": spec.get("raw_value_artifact_policy")}), "post-hook scope and value-free policy", "CLAIM_BOUNDARY")

        # Independently recompute every vector and compare.
        by_vector = {r["vector_id"]: r for r in vector_rows}
        add(checks, "Q30", "vector_inventory", set(by_vector) == set(POSITIVE) | set(NEGATIVE), ";".join(sorted(by_vector)), ";".join(sorted(set(POSITIVE)|set(NEGATIVE))), "SECRET_CAPTURE")
        recomputed = []
        for idx, (vid, value) in enumerate(POSITIVE.items(), 31):
            encoded = canonicalize(value)
            canon_hash = hashlib.sha256(encoded).hexdigest().upper()
            raw_hash = hashlib.sha256(b"P2N.RAW_OUTPUT.V1\x00" + encoded).hexdigest().upper()
            row = by_vector.get(vid, {})
            passed = row.get("canonical_length") == str(len(encoded)) and row.get("canonical_sha256") == canon_hash and row.get("raw_digest_sha256") == raw_hash and row.get("raw_value_exported") == "False" and not row.get("rejected")
            add(checks, f"Q{idx}", "vector_positive", passed, str(row), f"len={len(encoded)} canon={canon_hash} raw={raw_hash}", "SECRET_CAPTURE")
            recomputed.append({"vector_id": vid, "expected_rejection": False, "observed_rejection": False, "canonical_length": len(encoded), "canonical_sha256": canon_hash, "raw_digest_sha256": raw_hash, "matched_parent": passed})
        for idx, (vid, value) in enumerate(NEGATIVE.items(), 40):
            rejected = False
            try: canonicalize(value)
            except (TypeError, ValueError): rejected = True
            row = by_vector.get(vid, {})
            passed = rejected and row.get("rejected") == "True" and not row.get("canonical_sha256") and not row.get("raw_digest_sha256") and row.get("raw_value_exported") == "False"
            add(checks, f"Q{idx}", "vector_negative", passed, str(row), "rejected with no hashes/raw export", "SECRET_CAPTURE")
            recomputed.append({"vector_id": vid, "expected_rejection": True, "observed_rejection": rejected, "canonical_length": "", "canonical_sha256": "", "raw_digest_sha256": "", "matched_parent": passed})
        # Cross-property controls not reducible to single parent vectors.
        add(checks, "Q50", "vector_property", canonicalize("e\u0301") == canonicalize("\u00e9"), hashlib.sha256(canonicalize("e\u0301")).hexdigest().upper(), "NFC-equivalent strings identical", "SECRET_CAPTURE")
        add(checks, "Q51", "vector_property", canonicalize({"a":1,"b":2}) == canonicalize({"b":2,"a":1}), hashlib.sha256(canonicalize({"a":1,"b":2})).hexdigest().upper(), "map insertion order irrelevant", "SECRET_CAPTURE")
        duplicate_rejected = False
        try: canonicalize({"e\u0301": 1, "\u00e9": 2})
        except ValueError: duplicate_rejected = True
        add(checks, "Q52", "vector_property", duplicate_rejected, duplicate_rejected, "duplicate NFC key rejected", "SECRET_CAPTURE")
        add(checks, "Q53", "vector_property", canonicalize(True) != canonicalize(1), str((canonicalize(True), canonicalize(1))), "bool/int distinct", "SECRET_CAPTURE")

        required_prohibited = {"implementation existence", "source modification", "runtime wiring", "actual fs.read behavior", "source retrieval success", "secret capture", "protected-value lineage", "authorization transport correctness", "guardrail effectiveness", "real exfiltration prevention"}
        add(checks, "Q60", "claim_boundary", required_prohibited <= set(claim.get("prohibited", [])), ";".join(sorted(claim.get("prohibited", []))), ";".join(sorted(required_prohibited)), "CLAIM_BOUNDARY")
        add(checks, "Q61", "freeze_readiness", result.get("readiness", {}).get("separate_independent_qualification_required") is True and result.get("readiness", {}).get("implementation_authorized") is False and result.get("readiness", {}).get("identity_freeze_eligible") is False and result.get("readiness", {}).get("controlled_actual_fs_read_eligible") is False, str(result.get("readiness")), "independent qualification required and all authorizations false", "CLAIM_BOUNDARY")
        add(checks, "Q62", "execution_boundary", all(result.get("execution_boundaries", {}).get(k) is False for k in ["source_modified", "implementation_created", "sdk_modules_imported", "actual_fs_read_executed", "tools_executed", "fixture_contents_read", "source_value_previewed", "source_value_exported", "effects_observed", "sandbox_executed", "gym_executed", "predicates_executed", "breach_executed", "models_used"]), str(result.get("execution_boundaries")), "all boundaries false", "CLAIM_BOUNDARY")

        failed = [r["check_id"] for r in checks if not r["passed"]]
        passed = len(checks) - len(failed)
        status = "P2N_R2C_INDEPENDENT_RECONCILIATION_QUALIFICATION_COMPLETE_PASS" if not failed else "P2N_R2C_INDEPENDENT_RECONCILIATION_QUALIFICATION_COMPLETE_WITH_GAPS"
        next_gate = "EX6_P2B_P2O_IMPLEMENTATION_AUTHORIZATION_AND_SOURCE_GENERATION" if not failed else "EX6_P2B_P2N_R2C_R1_RECONCILIATION_REVIEW"
        qualified = not failed
        claim_out = {"allowed": ["independent Q60 reconciliation qualification", "independent Q73 specification qualification", "independent vector determinism and rejection findings", "implementation-authorization-gate eligibility recommendation"], "prohibited": sorted(required_prohibited)}
        result_out = {
            "version": VERSION, "created_at_utc": now(), "status": status,
            "classification": "READ_ONLY_INDEPENDENT_RECONCILIATION_QUALIFICATION",
            "P2N_R2B_parent_verified": True,
            "checks": {"total": len(checks), "passed": passed, "failed": len(failed), "failed_ids": failed},
            "qualification": {"Q60": "INDEPENDENTLY_QUALIFIED" if not any(r["category"] == "Q60" and not r["passed"] for r in checks) else "GAPS_IDENTIFIED", "Q73": "INDEPENDENTLY_QUALIFIED" if not any(r["category"].startswith("Q73") and not r["passed"] for r in checks) and not any(r["category"].startswith("vector") and not r["passed"] for r in checks) else "GAPS_IDENTIFIED"},
            "readiness": {"implementation_authorization_gate_eligible": qualified, "separate_implementation_gate_required": True, "implementation_authorized": False, "implementation_created": False, "identity_freeze_eligible": False, "controlled_actual_fs_read_eligible": False},
            "execution_boundaries": {"source_modified": False, "implementation_created": False, "sdk_modules_imported": False, "actual_fs_read_executed": False, "tools_executed": False, "fixture_contents_read": False, "source_value_previewed": False, "source_value_exported": False, "effects_observed": False, "sandbox_executed": False, "gym_executed": False, "predicates_executed": False, "breach_executed": False, "models_used": False},
            "scientific_verdict": {"reconciliation_qualification": "ESTABLISHED_WITHIN_SPECIFICATION_SCOPE" if qualified else "GAPS_IDENTIFIED", "implementation": "NOT_IMPLEMENTED", "canonicalization_runtime_behavior": "NOT_EVALUATED", "actual_source_retrieval": "NOT_EVALUATED", "secret_capture": "NOT_ESTABLISHED", "protected_value_lineage": "NOT_ESTABLISHED", "authorization_transport_correctness": "NOT_ESTABLISHED", "harness_trick": "NOT_DEMONSTRATED", "robust_security_findings": "NOT_ESTABLISHED"},
            "claim_boundary": claim_out, "next_gate": next_gate,
        }
        rp=out/"ex6_p2b_p2n_r2c_result.json"; cp=out/"ex6_p2b_p2n_r2c_checks.csv"; vp=out/"ex6_p2b_p2n_r2c_recomputed_vectors.csv"; bp=out/"ex6_p2b_p2n_r2c_binding.json"; cl=out/"ex6_p2b_p2n_r2c_claim_boundary.json"
        write_json(rp,result_out); write_csv(cp,checks,["check_id","category","passed","observed","expected","failure_layer"]); write_csv(vp,recomputed,["vector_id","expected_rejection","observed_rejection","canonical_length","canonical_sha256","raw_digest_sha256","matched_parent"]); write_json(cl,claim_out); write_json(bp,{"version":VERSION,"created_at_utc":now(),"runner":identity(Path(__file__).resolve()),"inputs":{k:identity(v) for k,v in inputs.items()},"project_root":str(project),"source_modified":False,"implementation_created":False})
        derived=(rp,cp,vp,bp,cl); bound=tuple(inputs.values()); rows=[{**identity(p),"role":"P2N_R2C_DERIVED"} for p in derived]+[{**identity(p),"role":"P2N_R2C_BOUND"} for p in bound]
        mp=out/"ex6_p2b_p2n_r2c_manifest.csv"; write_csv(mp,rows,["artifact","role","size_bytes","sha256","path"])
        ep=out/"ex6_p2b_p2n_r2c_manifest_external_binding.json"; write_json(ep,{"version":VERSION,"created_at_utc":now(),"status":status,"manifest_filename":mp.name,"manifest_size_bytes":mp.stat().st_size,"manifest_sha256":digest(mp),"runner_sha256":digest(Path(__file__).resolve()),"parent_r2b_manifest_sha256":PARENT_MANIFEST_SHA,"checks_total":len(checks),"checks_passed":passed,"checks_failed":len(failed),"implementation_authorization_gate_eligible":qualified,"separate_implementation_gate_required":True,"implementation_authorized":False,"implementation_created":False,"identity_freeze_eligible":False,"controlled_actual_fs_read_eligible":False,"source_modified":False,"actual_fs_read_executed":False,"next_gate":next_gate})
        print(json.dumps({"status":status,"checks_total":len(checks),"checks_passed":passed,"checks_failed":len(failed),"failed_ids":failed,"Q60":result_out["qualification"]["Q60"],"Q73":result_out["qualification"]["Q73"],"implementation_authorized":False,"controlled_actual_fs_read_eligible":False,"manifest_sha256":digest(mp),"next_gate":next_gate},indent=2))
    except Exception as exc:
        (out/"P2N_R2C_FAILED.json").write_text(json.dumps({"version":VERSION,"created_at_utc":now(),"status":"P2N_R2C_QUALIFICATION_BLOCKED","error_type":type(exc).__name__,"error":str(exc),"checks_frozen":checks,"source_modified":False,"implementation_created":False,"actual_fs_read_executed":False,"effects_observed":False},indent=2),encoding="utf-8")
        raise


def parse_args():
    p=argparse.ArgumentParser(description=VERSION)
    for flag in ["p2n-r2b-result","p2n-r2b-controls","p2n-r2b-prohibited-files","p2n-r2b-canonicalization-spec","p2n-r2b-canonicalization-vectors","p2n-r2b-claim-boundary","p2n-r2b-binding","p2n-r2b-external-binding","p2n-r2b-manifest","p2n-r2b-runner","project-root","output-dir"]:
        p.add_argument("--"+flag,required=True)
    return p.parse_args()
if __name__=="__main__":
    try: main(parse_args())
    except Exception as exc: print(f"FAILED: {exc}",file=sys.stderr); raise SystemExit(1)
