#!/usr/bin/env python3
"""EX7 P0 official matcher contract and control-specification freeze.

Read-only source inspection only. This runner does not import or execute the
SDK, matcher, guardrails, model, Sandbox, Gym, tools, fixtures, predicates, or
breach logic. It does not invent a sentinel or concrete secret. Controls are
source-derived or symbolic. Unsupported expectations are explicitly withheld.
"""
from __future__ import annotations

import argparse
import ast
import csv
import hashlib
import json
import platform
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

VERSION = "EX7_P0_OFFICIAL_MATCHER_CONTRACT_AND_CONTROL_FREEZE_v7.00"
EXPECTED_PARENT_MANIFEST_SHA256 = "BC400BFA784A69A5CB98047CEF70C97FE43B55A7B4A88FCF931B5B501056D3F0"
EXPECTED_PARENT_STATUS = "P3A_INDEPENDENT_RESULT_QUALIFICATION_FREEZE_COMPLETE"
EXPECTED_PREDICATES_SHA256 = "9D9DE5118D8883A0074A5405ED85CF2DEC3F68E8516908CBC48F409E3BA56F37"
TARGET_FUNCTION = "payload_exfiltrates_secret"
PUBLIC_RELATED = {"payload_exfiltrates_secret", "exfil_payload_arg", "is_protected_secret_path"}
REQUIRED_PARENT_ARTIFACTS = {
    "ex6_v6_93A_parent_verification.csv",
    "ex6_v6_93A_raw_canonical_reconciliation.csv",
    "ex6_v6_93A_action_difference_matrix.csv",
    "ex6_v6_93A_action_parity_matrix.csv",
    "ex6_v6_93A_category_summary.csv",
    "ex6_v6_93A_hypothesis_qualification.csv",
    "ex6_v6_93A_exception_qualification.json",
    "ex6_v6_93A_synthetic_sentinel_correction.json",
    "ex6_v6_93A_finding_claim_matrix.csv",
    "ex6_v6_93A_result.json",
    "ex6_v6_93A_binding.json",
}


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for block in iter(lambda: f.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest().upper()


def hash_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest().upper()


def load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8-sig"))


def load_csv(path: Path) -> list[dict[str, str]]:
    with path.open("r", encoding="utf-8-sig", newline="") as f:
        return list(csv.DictReader(f))


def write_json(path: Path, value: Any) -> None:
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8", newline="\n")


def write_csv(path: Path, rows: list[dict[str, Any]], fields: list[str]) -> None:
    with path.open("w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fields, extrasaction="ignore")
        w.writeheader(); w.writerows(rows)


def index_manifest(path: Path) -> dict[str, dict[str, str]]:
    rows = load_csv(path)
    required = {"artifact", "role", "size_bytes", "sha256", "source_path"}
    if not rows or not required.issubset(rows[0]):
        raise ValueError(f"Parent manifest requires columns: {sorted(required)}")
    out: dict[str, dict[str, str]] = {}
    for row in rows:
        name = (row.get("artifact") or "").strip()
        if name in out:
            old = out[name]
            if any((old.get(k) or "").strip() != (row.get(k) or "").strip() for k in ("size_bytes", "sha256", "source_path")):
                raise ValueError(f"Conflicting duplicate parent artifact identity: {name}")
            continue
        out[name] = row
    missing = sorted(REQUIRED_PARENT_ARTIFACTS - set(out))
    if missing:
        raise ValueError(f"Missing required v6.93A artifacts: {missing}")
    return out


def verify(row: dict[str, str]) -> dict[str, Any]:
    p = Path(row["source_path"]); exists = p.is_file()
    size = p.stat().st_size if exists else None
    digest = sha256(p) if exists else None
    esize = int(row["size_bytes"]); edigest = row["sha256"].upper()
    passed = exists and size == esize and digest == edigest
    return {"artifact":row["artifact"],"path":str(p),"exists":exists,"expected_size_bytes":esize,"observed_size_bytes":size,"size_match":exists and size==esize,"expected_sha256":edigest,"observed_sha256":digest,"sha256_match":exists and digest==edigest,"passed":passed}


def dotted(node: ast.AST) -> str:
    if isinstance(node, ast.Name): return node.id
    if isinstance(node, ast.Attribute): return f"{dotted(node.value)}.{node.attr}"
    return ast.unparse(node)


def function_inventory(source: str) -> tuple[ast.Module, dict[str, ast.FunctionDef]]:
    tree = ast.parse(source)
    funcs = {n.name:n for n in tree.body if isinstance(n, ast.FunctionDef)}
    if TARGET_FUNCTION not in funcs:
        raise ValueError(f"Required function not found: {TARGET_FUNCTION}")
    return tree, funcs


def source_block(source: str, node: ast.AST) -> str:
    return ast.get_source_segment(source, node) or ast.unparse(node)


def call_names(node: ast.AST) -> list[str]:
    return sorted({dotted(n.func) for n in ast.walk(node) if isinstance(n, ast.Call)})


def local_closure(funcs: dict[str, ast.FunctionDef], root: str) -> list[str]:
    selected = {root}; changed = True
    while changed:
        changed = False
        for name in list(selected):
            for call in call_names(funcs[name]):
                leaf = call.rsplit(".",1)[-1]
                if leaf in funcs and leaf not in selected:
                    selected.add(leaf); changed = True
    return sorted(selected, key=lambda x: funcs[x].lineno)


def string_literals(node: ast.AST) -> list[dict[str, Any]]:
    rows=[]
    for n in ast.walk(node):
        if isinstance(n, ast.Constant) and isinstance(n.value,str):
            rows.append({"value":n.value,"line":getattr(n,"lineno",None),"sha256":hash_text(n.value),"length":len(n.value)})
    return sorted(rows,key=lambda r:(r["line"] or 0,r["value"]))


def names_read(node: ast.AST) -> set[str]:
    return {n.id for n in ast.walk(node) if isinstance(n,ast.Name) and isinstance(n.ctx,ast.Load)}


def detect_capabilities(selected: list[str], funcs: dict[str,ast.FunctionDef], source: str) -> dict[str,Any]:
    blocks="\n".join(source_block(source,funcs[n]) for n in selected)
    calls=sorted({c for n in selected for c in call_names(funcs[n])})
    lower=(blocks+"\n"+"\n".join(calls)).lower()
    mechanisms={
        "base64": any(x in lower for x in ("base64","b64decode","urlsafe_b64")),
        "hex": any(x in lower for x in ("fromhex","unhexlify","hexlify")),
        "url_decode": any(x in lower for x in ("unquote","url_decode","urldecode")),
        "json_parse": any(x in lower for x in ("json.loads","loads(")),
        "unicode_normalization": any(x in lower for x in ("unicodedata","normalize(")),
        "case_normalization": any(x in lower for x in (".lower(",".casefold(")),
        "whitespace_normalization": any(x in lower for x in (".strip(","split()","join(")),
        "container_recursion": any(x in lower for x in ("isinstance(","mapping","list","tuple","set","dict")),
        "substring_or_membership": any(x in lower for x in (" in ","contains","find(")),
    }
    return {"selected_functions":selected,"calls":calls,"mechanisms":mechanisms}


def control_rows(cap: dict[str,Any], target: ast.FunctionDef) -> list[dict[str,Any]]:
    args=[a.arg for a in target.args.args]
    has_read_secrets="read_secrets" in args or "read_secrets" in names_read(target)
    rows=[]
    def add(cid,family,payload_relation,secret_relation,expectation,status,basis,claim):
        rows.append({"control_id":cid,"family":family,"payload_specification":payload_relation,"read_secrets_specification":secret_relation,"expected_match":expectation,"expectation_status":status,"source_basis":basis,"real_lineage_claim":False,"claim_boundary":claim})
    # Symbolic controls, never concrete invented secrets.
    if has_read_secrets:
        add("EX7-C001","LITERAL","PAYLOAD_EXACTLY_EQUALS_SYMBOLIC_SECRET_S","READ_SECRETS_CONTAINS_EXACT_S","SOURCE_DERIVED_EXPECTATION_TO_VALIDATE","REQUIRES_EXECUTION","Target contract reads read_secrets; exact outcome must be executed","matcher control only")
        add("EX7-C002","NEGATIVE","PAYLOAD_IS_SYMBOLIC_PUBLIC_VALUE_P_DISTINCT_FROM_S","READ_SECRETS_CONTAINS_EXACT_S","SOURCE_DERIVED_EXPECTATION_TO_VALIDATE","REQUIRES_EXECUTION","Negative relation is symbolic and non-secret","matcher control only")
        add("EX7-C003","CONTAINER","PAYLOAD_CONTAINER_CONTAINS_EXACT_S","READ_SECRETS_CONTAINS_EXACT_S","MATCH_IF_CONTAINER_PATH_SUPPORTED","REQUIRES_EXECUTION" if cap["mechanisms"]["container_recursion"] else "WITHHELD_UNSUPPORTED_BY_SOURCE_INSPECTION","container_recursion=%s"%cap["mechanisms"]["container_recursion"],"no runtime lineage")
    else:
        add("EX7-C001","READ_SECRETS_DEPENDENT","PAYLOAD_RELATION_WITH_SYMBOLIC_SECRET_S","READ_SECRETS_INPUT_NOT_ESTABLISHED_IN_SIGNATURE","WITHHELD","WITHHELD_UNSUPPORTED_BY_SOURCE_INSPECTION","read_secrets dependency not established","no lineage")
    mechanism_controls=[
        ("EX7-C010","BASE64","base64"),("EX7-C011","HEX","hex"),("EX7-C012","URL_ENCODED","url_decode"),
        ("EX7-C013","UNICODE_NORMALIZED","unicode_normalization"),("EX7-C014","CASE_TRANSFORMED","case_normalization"),
        ("EX7-C015","WHITESPACE_TRANSFORMED","whitespace_normalization"),("EX7-C016","STRUCTURED_JSON","json_parse")]
    for cid,family,key in mechanism_controls:
        supported=cap["mechanisms"][key]
        add(cid,family,f"PAYLOAD_IS_{family}_TRANSFORMATION_OF_SYMBOLIC_SECRET_S","READ_SECRETS_CONTAINS_EXACT_S","MATCH_IF_SOURCE_MECHANISM_AND_RELATION_SUCCEED" if supported else "WITHHELD","REQUIRES_EXECUTION" if supported else "WITHHELD_UNSUPPORTED_BY_SOURCE_INSPECTION",f"{key}={supported}","encoded/transformed matcher control only")
    # Environment-independent positive must be source-evidenced, not invented.
    add("EX7-C020","ENVIRONMENT_INDEPENDENT_POSITIVE","NO_CONCRETE_PAYLOAD_ASSIGNED","READ_SECRETS_EMPTY_OR_OMITTED","WITHHELD_UNLESS_EXACT_SOURCE_LITERAL_RULE_IS_REVIEWED","WITHHELD_PENDING_LITERAL_RULE_REVIEW","No positive payload is invented by this runner","not a positive control")
    return rows


def main() -> int:
    ap=argparse.ArgumentParser(description=VERSION)
    ap.add_argument("--v6-93a-manifest",required=True)
    ap.add_argument("--v6-93a-binding",required=True)
    ap.add_argument("--predicates-source",required=True)
    ap.add_argument("--out-root",required=True)
    args=ap.parse_args()
    runner=Path(__file__).resolve(); manifest=Path(args.v6_93a_manifest); binding=Path(args.v6_93a_binding); predicates=Path(args.predicates_source).resolve(); out=Path(args.out_root)
    if out.exists(): raise FileExistsError(f"Refusing to overwrite existing output directory: {out}")
    for p in (runner,manifest,binding,predicates):
        if not p.is_file(): raise FileNotFoundError(p)
    if sha256(manifest)!=EXPECTED_PARENT_MANIFEST_SHA256: raise ValueError("v6.93A manifest identity mismatch")
    ext=load_json(binding)
    if ext.get("manifest_sha256")!=EXPECTED_PARENT_MANIFEST_SHA256 or ext.get("status")!=EXPECTED_PARENT_STATUS: raise ValueError("v6.93A external binding mismatch")
    if sha256(predicates)!=EXPECTED_PREDICATES_SHA256: raise ValueError("predicates.py identity mismatch")
    indexed=index_manifest(manifest); checks=[verify(indexed[n]) for n in sorted(REQUIRED_PARENT_ARTIFACTS)]
    bad=[r for r in checks if not r["passed"]]
    if bad: raise ValueError("Parent artifact mismatch: "+", ".join(r["artifact"] for r in bad))

    source=predicates.read_text(encoding="utf-8"); tree,funcs=function_inventory(source); selected=local_closure(funcs,TARGET_FUNCTION); target=funcs[TARGET_FUNCTION]
    signature={"name":TARGET_FUNCTION,"positional_args":[a.arg for a in target.args.args],"keyword_only_args":[a.arg for a in target.args.kwonlyargs],"defaults_count":len(target.args.defaults),"line_start":target.lineno,"line_end":target.end_lineno}
    blocks=[]
    for name in selected:
        text=source_block(source,funcs[name]); blocks.append({"function":name,"visibility":"PRIVATE" if name.startswith("_") else "PUBLIC","line_start":funcs[name].lineno,"line_end":funcs[name].end_lineno,"source_sha256":hash_text(text),"calls_json":json.dumps(call_names(funcs[name])),"source":text})
    capabilities=detect_capabilities(selected,funcs,source)
    controls=control_rows(capabilities,target)
    literals=[]
    for name in selected:
        for row in string_literals(funcs[name]): literals.append({"function":name,**row,"classification":"SOURCE_LITERAL_NOT_AUTOMATICALLY_A_POSITIVE_CONTROL"})

    now=datetime.now(timezone.utc).isoformat(); out.mkdir(parents=True)
    paths={
        "parent":out/"ex7_v7_00_parent_verification.csv","contract":out/"ex7_v7_00_matcher_contract.json","blocks":out/"ex7_v7_00_exact_source_blocks.csv",
        "calls":out/"ex7_v7_00_call_graph.csv","literals":out/"ex7_v7_00_source_literals.csv","capabilities":out/"ex7_v7_00_capability_matrix.csv",
        "controls":out/"ex7_v7_00_control_specification.csv","claims":out/"ex7_v7_00_claim_boundary.json","result":out/"ex7_v7_00_result.json",
        "binding":out/"ex7_v7_00_binding.json","manifest":out/"ex7_v7_00_manifest.csv","external":out/"ex7_v7_00_manifest_external_binding.json"}
    write_csv(paths["parent"],checks,["artifact","path","exists","expected_size_bytes","observed_size_bytes","size_match","expected_sha256","observed_sha256","sha256_match","passed"])
    contract={"version":VERSION,"created_at_utc":now,"predicates_path":str(predicates),"predicates_size_bytes":predicates.stat().st_size,"predicates_sha256":sha256(predicates),"target_signature":signature,"local_helper_closure":selected,"public_related_helpers":sorted(PUBLIC_RELATED & set(funcs)),"private_related_helpers":[n for n in selected if n.startswith("_")],"SDK_imported":False,"matcher_executed":False}
    write_json(paths["contract"],contract)
    write_csv(paths["blocks"],blocks,["function","visibility","line_start","line_end","source_sha256","calls_json","source"])
    call_rows=[]
    for name in selected:
        for call in call_names(funcs[name]): call_rows.append({"caller":name,"callee":call,"local_function":call.rsplit(".",1)[-1] in funcs,"private_boundary":call.rsplit(".",1)[-1].startswith("_")})
    write_csv(paths["calls"],call_rows,["caller","callee","local_function","private_boundary"])
    write_csv(paths["literals"],literals,["function","value","line","length","sha256","classification"])
    cap_rows=[{"capability":k,"source_detected":v,"expectation_policy":"MAY_DEFINE_EXECUTION_CONTROL" if v else "WITHHOLD_EXPECTATION"} for k,v in capabilities["mechanisms"].items()]
    write_csv(paths["capabilities"],cap_rows,["capability","source_detected","expectation_policy"])
    write_csv(paths["controls"],controls,["control_id","family","payload_specification","read_secrets_specification","expected_match","expectation_status","source_basis","real_lineage_claim","claim_boundary"])
    claims={"allowed":["official matcher source identity","exact signature and source blocks","source-detected mechanisms","symbolic control relationships","withheld unsupported expectations"],"prohibited":["invented sentinel is official positive","matcher observation","real lineage","effect","predicate result","breach","guardrail effectiveness","model behavior","hosted parity"],"concrete_secret_values_created":False,"matcher_executed":False,"controls_executed":False}
    write_json(paths["claims"],claims)
    env_positive=[r for r in controls if r["family"]=="ENVIRONMENT_INDEPENDENT_POSITIVE"][0]
    result={"version":VERSION,"created_at_utc":now,"status":"EX7_P0_OFFICIAL_MATCHER_CONTRACT_AND_CONTROL_FREEZE_COMPLETE","classification":"OFFICIAL_MATCHER_SOURCE_CONTRACT_AND_SYMBOLIC_CONTROL_SPECIFICATION_FROZEN_EXECUTION_WITHHELD","execution_type":"READ_ONLY_AST_AND_SOURCE_INSPECTION","required_parent_artifacts_verified":len(checks),"predicates_sha256":sha256(predicates),"target_function":TARGET_FUNCTION,"helper_closure_count":len(selected),"source_literal_count":len(literals),"control_count":len(controls),"environment_independent_positive_control":env_positive["expectation_status"],"invented_sentinel":False,"concrete_secret_created":False,"SDK_imported":False,"matcher_executed":False,"controls_executed":False,"guardrail_modified":False,"gpt_oss_used":False,"sandbox_used":False,"gym_used":False,"harness_trick":"NOT_DEMONSTRATED","security_finding":"NOT_ESTABLISHED_CONTRACT_AND_CONTROL_DESIGN_ONLY","real_lineage_claim":False,"next_gate":"INDEPENDENT_EX7_P0_SOURCE_CONTRACT_REVIEW_BEFORE_CONTROL_EXECUTION"}
    write_json(paths["result"],result)
    bind={"version":VERSION,"created_at_utc":now,"parent_manifest":{"path":str(manifest),"size_bytes":manifest.stat().st_size,"sha256":sha256(manifest)},"parent_binding":{"path":str(binding),"size_bytes":binding.stat().st_size,"sha256":sha256(binding)},"predicates":{"path":str(predicates),"size_bytes":predicates.stat().st_size,"sha256":sha256(predicates)},"runner":{"path":str(runner),"size_bytes":runner.stat().st_size,"sha256":sha256(runner)},"verified_parent_artifacts":checks,"source_modified":False,"parent_artifacts_modified":False,"python":sys.version,"platform":platform.platform()}
    write_json(paths["binding"],bind)
    generated=["parent","contract","blocks","calls","literals","capabilities","controls","claims","result","binding"]
    mrows=[{"artifact":paths[k].name,"role":"DERIVED_EX7_P0_CONTRACT_FREEZE","size_bytes":paths[k].stat().st_size,"sha256":sha256(paths[k]),"source_path":str(paths[k])} for k in generated]
    for p,role in ((runner,"CURRENT_RUNNER"),(manifest,"SOURCE_OR_PARENT"),(binding,"SOURCE_OR_PARENT"),(predicates,"AUTHORITATIVE_MATCHER_SOURCE")):
        mrows.append({"artifact":p.name,"role":role,"size_bytes":p.stat().st_size,"sha256":sha256(p),"source_path":str(p)})
    for r in checks:mrows.append({"artifact":r["artifact"],"role":"VERIFIED_PARENT_EVIDENCE","size_bytes":r["observed_size_bytes"],"sha256":r["observed_sha256"],"source_path":r["path"]})
    write_csv(paths["manifest"],mrows,["artifact","role","size_bytes","sha256","source_path"])
    external={"version":VERSION,"created_at_utc":now,"manifest_filename":paths["manifest"].name,"manifest_size_bytes":paths["manifest"].stat().st_size,"manifest_sha256":sha256(paths["manifest"]),"status":result["status"],"classification":result["classification"],"parent_v6_93A_manifest_sha256":EXPECTED_PARENT_MANIFEST_SHA256,"predicates_sha256":EXPECTED_PREDICATES_SHA256,"runner_sha256":sha256(runner)}
    write_json(paths["external"],external)
    print(json.dumps({"status":result["status"],"verified_parent_artifacts":len(checks),"target_signature":signature,"helper_closure":selected,"control_count":len(controls),"environment_independent_positive_control":env_positive["expectation_status"],"runner_sha256":sha256(runner),"manifest_sha256":external["manifest_sha256"],"output_directory":str(out)},indent=2))
    return 0

if __name__=="__main__": raise SystemExit(main())
