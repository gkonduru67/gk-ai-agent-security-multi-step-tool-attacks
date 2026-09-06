#!/usr/bin/env python3
"""P2O-C independent source and authorization conformance qualification.

Read-only static qualification of the three P2O-B-generated sources against the
frozen P2O-A authorization contract. Rehashes all evidence and source inputs,
independently parses ASTs, evaluates exact public-symbol/function/constructor
contracts, freezes an import-normalization rule, checks allowed/prohibited
imports, verifies requirement coverage and selected fail-closed source
constructs, performs narrow credential/raw-value static scans, and preserves
claim boundaries.

No generated or SDK module is imported. No generated symbol, fs.read, tool,
Sandbox, Gym, predicate, breach logic, model, fixture read, protected-value
preview/export, or external effect is executed.
"""
from __future__ import annotations

import argparse
import ast
import csv
import hashlib
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

VERSION = "EX6_P2B_P2O_C_INDEPENDENT_SOURCE_AND_AUTHORIZATION_CONFORMANCE_QUALIFICATION_v1.0"
PARENT_VERSION = "EX6_P2B_P2O_B_AUTHORIZED_SOURCE_GENERATION_v1.0"
PARENT_STATUS = "P2O_B_AUTHORIZED_SOURCE_GENERATION_COMPLETE_PASS"
PARENT_MANIFEST_SHA = "4923F7B0124490687D3B89283EB4B72410695711265C88EB030BC60A66AFD67B"
PARENT_RUNNER_SHA = "735AF90759B7161BA81679164742FD7B35ED08F1CF292FEA75827F8075AAFFE1"
AUTH_MANIFEST_SHA = "CB85AAE890FF76583829067242A74ABF0BB9E7B0FD231B34BC39C9917740634A"

GENERATED = {
    "AUTH-F01": ("aicomp_sdk/core/env/trusted_outcome_transport_v1.py", 6170, "5C7F7D16A37896959C6F4CC769E5F72A6E5E534EE140BA5CAF2FB70661102CE1"),
    "AUTH-F02": ("aicomp_sdk/core/env/sandbox_trusted_bridge_v1.py", 743, "3EE9BBB1E65949795A5639D12C55D81D8D0645357260DFC5A91DB1E9710288B6"),
    "AUTH-F03": ("aicomp_sdk/core/tools/fs_trusted_result_v1.py", 791, "EF6EC29952194AC83A741CCFAF3FCE41DD64D2D6BEE5501A8273209CD3C21F8F"),
}
PROTECTED = {
    "aicomp_sdk/core/env/sandbox.py": "B781375C5AAE3C2533F6992AAE6D3C65CA56B7077822F1A27955756BEF1168D0",
    "aicomp_sdk/core/predicates.py": "9D9DE5118D8883A0074A5405ED85CF2DEC3F68E8516908CBC48F409E3BA56F37",
    "aicomp_sdk/core/tools/fs.py": "4B8C54032ED807CE4C35BAB403EE622141881158E10F600A4B6D329E6D6F95B8",
    "aicomp_sdk/guardrails/optimal.py": "6724FEDF7BBF3E67DFCDD564BA8A73463E0F783D5C84E0A70DCEFF40C1BC61ED",
    "aicomp_sdk/guardrails/trusted_context_adapter_v1_1.py": "BFDE535B805979FF6D13BA0970A9A13466192F1B1111B02CE8B8BB8C670FFA99",
}
PUBLIC_SYMBOLS = {
    "AUTH-F01": {
        "TrustedEventSequenceStateV1", "TrustedOutcomeTransportV1",
        "canonicalize_post_hook_output_v1", "compute_raw_output_sha256_v1",
        "compute_protected_value_bound_digest_v1", "snapshot_trusted_transport_state_v1",
    },
    "AUTH-F02": {"TrustedBridgeSandboxV1"},
    "AUTH-F03": {"canonical_source_path_v1"},
}
EXPECTED_CONTRACTS = {
    ("AUTH-F01", "canonicalize_post_hook_output_v1"): {"kind":"function","pos":["value"],"vararg":None,"kwonly":[],"kwarg":None,"return":"bytes"},
    ("AUTH-F01", "compute_raw_output_sha256_v1"): {"kind":"function","pos":["value"],"vararg":None,"kwonly":[],"kwarg":None,"return":"str"},
    ("AUTH-F01", "compute_protected_value_bound_digest_v1"): {"kind":"function","pos":["trace_identity","proposal_digest","outcome_event_identity","canonical_source_path","raw_output_sha256"],"vararg":None,"kwonly":[],"kwarg":None,"return":"str"},
    ("AUTH-F01", "snapshot_trusted_transport_state_v1"): {"kind":"function","pos":["sequence_state"],"vararg":None,"kwonly":[],"kwarg":None,"return":"dict[str, object]"},
    ("AUTH-F03", "canonical_source_path_v1"): {"kind":"function","pos":["filesystem_root","requested_path","resolved_path"],"vararg":None,"kwonly":[],"kwarg":None,"return":"str"},
    ("AUTH-F01", "TrustedEventSequenceStateV1"): {"kind":"constructor","pos":[],"vararg":None,"kwonly":[],"kwarg":None,"implicit_dataclass":True},
    ("AUTH-F01", "TrustedOutcomeTransportV1"): {"kind":"constructor","pos":["adapter","sequence_state"],"vararg":None,"kwonly":[],"kwarg":None},
    ("AUTH-F02", "TrustedBridgeSandboxV1"): {"kind":"constructor","pos":[],"vararg":"args","kwonly":["trusted_transport"],"kwarg":"kwargs"},
}
ALLOWED_MODULES = {
    "AUTH-F01": {"__future__", "dataclasses", "hashlib", "json", "threading", "unicodedata", "typing"},
    "AUTH-F02": {"__future__", "typing", "aicomp_sdk.core.env.sandbox", "aicomp_sdk.core.env.trusted_outcome_transport_v1"},
    "AUTH-F03": {"__future__", "pathlib"},
}
PROHIBITED_PREFIXES = {
    "subprocess", "socket", "requests", "urllib", "http.client", "ftplib",
    "aicomp_sdk.core.env.gym", "aicomp_sdk.core.predicates",
}
REQ_SYMBOLS = {
    "P2N-01": {("AUTH-F01","TrustedOutcomeTransportV1"),("AUTH-F02","TrustedBridgeSandboxV1")},
    "P2N-02": {("AUTH-F01","canonicalize_post_hook_output_v1"),("AUTH-F01","compute_raw_output_sha256_v1")},
    "P2N-03": {("AUTH-F01","compute_protected_value_bound_digest_v1")},
    "P2N-04": {("AUTH-F01","TrustedEventSequenceStateV1"),("AUTH-F01","snapshot_trusted_transport_state_v1")},
    "P2N-05": {("AUTH-F03","canonical_source_path_v1")},
}


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest().upper()


def identity(path: Path) -> dict[str, Any]:
    path = path.resolve()
    return {"artifact": path.name, "path": str(path), "size_bytes": path.stat().st_size, "sha256": sha256(path)}


def write_json(path: Path, value: Any) -> None:
    with path.open("x", encoding="utf-8", newline="\n") as handle:
        json.dump(value, handle, indent=2, sort_keys=True)
        handle.write("\n")


def write_csv(path: Path, rows: list[dict[str, Any]], fields: list[str]) -> None:
    with path.open("x", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields, extrasaction="ignore", lineterminator="\n")
        writer.writeheader(); writer.writerows(rows)


def add(rows, check_id, category, passed, observed, expected, layer):
    rows.append({"check_id":check_id,"category":category,"passed":bool(passed),"observed":str(observed),"expected":str(expected),"failure_layer":layer})


def sig_shape(node: ast.FunctionDef | ast.AsyncFunctionDef, drop_self: bool = False) -> dict[str, Any]:
    args = node.args
    positional = [x.arg for x in args.posonlyargs + args.args]
    if drop_self and positional and positional[0] in {"self", "cls"}:
        positional = positional[1:]
    return {
        "pos": positional,
        "vararg": args.vararg.arg if args.vararg else None,
        "kwonly": [x.arg for x in args.kwonlyargs],
        "kwarg": args.kwarg.arg if args.kwarg else None,
        "return": ast.unparse(node.returns) if node.returns else None,
    }


def import_records(tree: ast.AST, file_id: str) -> list[dict[str, Any]]:
    rows=[]
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                rows.append({"file_id":file_id,"lineno":node.lineno,"style":"import","module":alias.name,"members":"","alias":alias.asname or ""})
        elif isinstance(node, ast.ImportFrom):
            rows.append({"file_id":file_id,"lineno":node.lineno,"style":"from","module":node.module or "","members":";".join(a.name for a in node.names),"alias":";".join(a.asname or "" for a in node.names)})
    return rows


def find_class(tree: ast.Module, name: str):
    return next((n for n in tree.body if isinstance(n, ast.ClassDef) and n.name == name), None)


def find_function(tree: ast.Module, name: str):
    return next((n for n in tree.body if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) and n.name == name), None)


def class_init(cls: ast.ClassDef):
    return next((n for n in cls.body if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) and n.name == "__init__"), None)


def calls_in(node: ast.AST) -> list[str]:
    names=[]
    for item in ast.walk(node):
        if isinstance(item, ast.Call):
            try: names.append(ast.unparse(item.func))
            except Exception: names.append("UNPARSE_FAILED")
    return names


def main(args: argparse.Namespace) -> None:
    out = Path(args.output_dir).resolve()
    require(not out.exists(), f"Refusing overwrite: {out}")
    out.mkdir(parents=True)
    checks=[]
    try:
        project=Path(args.project_root).resolve(); require(project.is_dir(), f"Missing project root: {project}")
        inputs={
            "result":Path(args.p2o_b_result).resolve(), "generated_files":Path(args.p2o_b_generated_files).resolve(),
            "symbols":Path(args.p2o_b_symbols).resolve(), "imports":Path(args.p2o_b_imports).resolve(),
            "protected_after":Path(args.p2o_b_protected_after).resolve(), "leakage_scan":Path(args.p2o_b_leakage_scan).resolve(),
            "claim_boundary":Path(args.p2o_b_claim_boundary).resolve(), "binding":Path(args.p2o_b_binding).resolve(),
            "external_binding":Path(args.p2o_b_external_binding).resolve(), "manifest":Path(args.p2o_b_manifest).resolve(),
            "runner":Path(args.p2o_b_runner).resolve(), "p2o_a_authorization":Path(args.p2o_a_authorization).resolve(),
            "p2o_a_files":Path(args.p2o_a_files).resolve(), "p2o_a_symbols":Path(args.p2o_a_symbols).resolve(),
            "p2o_a_imports":Path(args.p2o_a_imports).resolve(), "p2o_a_traceability":Path(args.p2o_a_traceability).resolve(),
            "p2o_a_protected_sources":Path(args.p2o_a_protected_sources).resolve(), "p2o_a_manifest":Path(args.p2o_a_manifest).resolve(),
        }
        for key,path in inputs.items(): require(path.is_file(), f"Missing {key}: {path}")
        result=json.loads(inputs["result"].read_text(encoding="utf-8-sig"))
        external=json.loads(inputs["external_binding"].read_text(encoding="utf-8-sig"))
        claim=json.loads(inputs["claim_boundary"].read_text(encoding="utf-8-sig"))
        authorization=json.loads(inputs["p2o_a_authorization"].read_text(encoding="utf-8-sig"))
        generated_rows=list(csv.DictReader(inputs["generated_files"].open(encoding="utf-8-sig",newline="")))
        authorized_file_rows=list(csv.DictReader(inputs["p2o_a_files"].open(encoding="utf-8-sig",newline="")))
        authorized_symbol_rows=list(csv.DictReader(inputs["p2o_a_symbols"].open(encoding="utf-8-sig",newline="")))
        trace_rows=list(csv.DictReader(inputs["p2o_a_traceability"].open(encoding="utf-8-sig",newline="")))

        add(checks,"Q01","parent",result.get("version")==PARENT_VERSION and result.get("status")==PARENT_STATUS,result.get("status"),PARENT_STATUS,"FIXTURE")
        add(checks,"Q02","parent",sha256(inputs["manifest"])==PARENT_MANIFEST_SHA and external.get("manifest_sha256")==PARENT_MANIFEST_SHA,sha256(inputs["manifest"]),PARENT_MANIFEST_SHA,"FIXTURE")
        add(checks,"Q03","parent",sha256(inputs["runner"])==PARENT_RUNNER_SHA and external.get("runner_sha256")==PARENT_RUNNER_SHA,sha256(inputs["runner"]),PARENT_RUNNER_SHA,"FIXTURE")
        add(checks,"Q04","parent",external.get("parent_p2o_a_manifest_sha256")==AUTH_MANIFEST_SHA and sha256(inputs["p2o_a_manifest"])==AUTH_MANIFEST_SHA,external.get("parent_p2o_a_manifest_sha256"),AUTH_MANIFEST_SHA,"FIXTURE")
        add(checks,"Q05","authorization",authorization.get("authorization_id")=="P2O-A-AUTH-v1.0" and authorization.get("overwrite_existing_paths") is False and authorization.get("modify_protected_sources") is False,str(authorization),"exact P2O-A authorization and no overwrite/modification","CLAIM_BOUNDARY")

        expected_paths={v[0] for v in GENERATED.values()}
        parent_paths={r["relative_path"] for r in generated_rows}; auth_paths={r["relative_path"] for r in authorized_file_rows}
        add(checks,"Q10","path_set",parent_paths==expected_paths,parent_paths,expected_paths,"FIXTURE")
        add(checks,"Q11","path_set",auth_paths==expected_paths,auth_paths,expected_paths,"FIXTURE")

        trees={}; source_texts={}; source_inventory=[]
        for idx,(file_id,(rel,size,expected_hash)) in enumerate(GENERATED.items(),12):
            path=project/Path(rel)
            observed_hash=sha256(path) if path.is_file() else "MISSING"
            observed_size=path.stat().st_size if path.is_file() else -1
            ok=path.is_file() and observed_hash==expected_hash and observed_size==size
            add(checks,f"Q{idx}","source_identity",ok,f"{rel}|{observed_size}|{observed_hash}",f"{rel}|{size}|{expected_hash}","FIXTURE")
            if path.is_file():
                text=path.read_text(encoding="utf-8"); source_texts[file_id]=text
                try: tree=ast.parse(text,filename=str(path)); parsed=True
                except SyntaxError: tree=None; parsed=False
                add(checks,f"Q{idx+10}","ast_parse",parsed,rel,"AST parse pass","ADAPTER_PARSE")
                if parsed: trees[file_id]=tree
                source_inventory.append({"file_id":file_id,"relative_path":rel,"size_bytes":observed_size,"sha256":observed_hash,"ast_parse":parsed})

        protected_inventory=[]
        for idx,(rel,expected_hash) in enumerate(PROTECTED.items(),30):
            path=project/Path(rel); observed=sha256(path) if path.is_file() else "MISSING"
            ok=path.is_file() and observed==expected_hash
            add(checks,f"Q{idx}","protected_identity",ok,f"{rel}|{observed}",expected_hash,"FIXTURE")
            protected_inventory.append({"relative_path":rel,"sha256":observed,"expected_sha256":expected_hash,"match":ok})

        observed_symbols=set(); signature_rows=[]
        for file_id,tree in trees.items():
            top={n.name for n in tree.body if isinstance(n,(ast.FunctionDef,ast.AsyncFunctionDef,ast.ClassDef)) and not n.name.startswith("_")}
            observed_symbols |= {(file_id,name) for name in top}
            add(checks,f"Q40{file_id[-1]}","public_symbols",top==PUBLIC_SYMBOLS[file_id],sorted(top),sorted(PUBLIC_SYMBOLS[file_id]),"ADAPTER_PARSE")
        authorized_pairs={(r["file_id"],r["name"]) for r in authorized_symbol_rows}
        add(checks,"Q404","public_symbols",observed_symbols==authorized_pairs,sorted(observed_symbols),sorted(authorized_pairs),"REQUIREMENT_TRACEABILITY")

        check_num=410
        for (file_id,name),contract in EXPECTED_CONTRACTS.items():
            tree=trees.get(file_id); node=None; observed_shape=None; passed=False
            if tree:
                if contract["kind"]=="function":
                    node=find_function(tree,name)
                    if node: observed_shape=sig_shape(node)
                else:
                    cls=find_class(tree,name); node=cls
                    if cls:
                        init=class_init(cls)
                        if init: observed_shape=sig_shape(init,drop_self=True)
                        elif contract.get("implicit_dataclass"):
                            observed_shape={"pos":[],"vararg":None,"kwonly":[],"kwarg":None,"return":None}
                if observed_shape:
                    passed=(observed_shape["pos"]==contract["pos"] and observed_shape["vararg"]==contract["vararg"] and observed_shape["kwonly"]==contract["kwonly"] and observed_shape["kwarg"]==contract["kwarg"] and (contract.get("return") is None or observed_shape.get("return")==contract.get("return")))
            add(checks,f"Q{check_num}","signature",passed,observed_shape,contract,"ADAPTER_PARSE")
            signature_rows.append({"file_id":file_id,"symbol":name,"kind":contract["kind"],"observed":json.dumps(observed_shape,sort_keys=True) if observed_shape else "NOT_FOUND","expected":json.dumps(contract,sort_keys=True),"match":passed})
            check_num+=1

        import_rows=[]; import_ok=True; prohibited_hits=[]
        normalization={
            "rule_id":"P2O-C.IMPORT.NORMALIZATION.V1",
            "rules":[
                "module permission authorizes from-import members from that exact module",
                "__future__.annotations is explicitly allowed for all three generated files",
                "aliases do not change the authorized module identity",
                "relative imports are prohibited",
                "prohibited prefixes are checked against the normalized module path",
            ],
        }
        for file_id,tree in trees.items():
            rows=import_records(tree,file_id); import_rows.extend(rows)
            for row in rows:
                module=row["module"]
                allowed=module in ALLOWED_MODULES[file_id]
                prohibited=any(module==p or module.startswith(p+".") for p in PROHIBITED_PREFIXES)
                row["allowed_module"]=allowed; row["prohibited_match"]=prohibited
                import_ok=import_ok and allowed and not prohibited
                if prohibited: prohibited_hits.append(f"{file_id}:{module}")
        add(checks,"Q430","import_normalization",True,normalization["rule_id"],"frozen normalization rule","ADAPTER_PARSE")
        add(checks,"Q431","import_allowlist",import_ok,[(r['file_id'],r['module'],r['allowed_module']) for r in import_rows],"all normalized modules allowed","ADAPTER_PARSE")
        add(checks,"Q432","prohibited_imports",not prohibited_hits,prohibited_hits,"no prohibited prefixes","ADAPTER_PARSE")

        all_trace_requirements={r["requirement"] for r in trace_rows}
        coverage_ok=all(req in all_trace_requirements and required<=observed_symbols for req,required in REQ_SYMBOLS.items())
        add(checks,"Q440","traceability",coverage_ok,sorted(all_trace_requirements),sorted(REQ_SYMBOLS),"REQUIREMENT_TRACEABILITY")

        # Static fail-closed evidence, without executing code.
        fail_closed=[]
        t1=trees.get("AUTH-F01"); t2=trees.get("AUTH-F02"); t3=trees.get("AUTH-F03")
        canon=find_function(t1,"canonicalize_post_hook_output_v1") if t1 else None
        bound=find_function(t1,"compute_protected_value_bound_digest_v1") if t1 else None
        state=find_class(t1,"TrustedEventSequenceStateV1") if t1 else None
        outcome=find_class(t1,"TrustedOutcomeTransportV1") if t1 else None
        bridge=find_class(t2,"TrustedBridgeSandboxV1") if t2 else None
        path_fn=find_function(t3,"canonical_source_path_v1") if t3 else None
        properties={
            "canonicalizer_has_raises": canon is not None and sum(isinstance(n,ast.Raise) for n in ast.walk(canon))>=4,
            "bound_digest_validates_and_raises": bound is not None and any(isinstance(n,ast.Raise) for n in ast.walk(bound)),
            "sequence_consumption_rejects_reuse": state is not None and "outcome identity already consumed" in ast.unparse(state),
            "snapshot_restore_schema_rejection": state is not None and "unsupported snapshot schema" in ast.unparse(state),
            "bridge_type_guard": bridge is not None and "trusted_transport must be TrustedOutcomeTransportV1" in ast.unparse(bridge),
            "canonical_path_escape_rejection": path_fn is not None and "outside filesystem root" in ast.unparse(path_fn),
        }
        for idx,(name,ok) in enumerate(properties.items(),450):
            add(checks,f"Q{idx}","fail_closed",ok,name,"static fail-closed construct present","AUTHORIZATION_TRANSPORT")
            fail_closed.append({"property":name,"present":ok})
        acknowledge=None
        if outcome:
            acknowledge=next((n for n in outcome.body if isinstance(n,ast.FunctionDef) and n.name=="acknowledge"),None)
        call_names=calls_in(acknowledge) if acknowledge else []
        after_idx=next((i for i,x in enumerate(call_names) if x.endswith("adapter.after_tool") or x=="self.adapter.after_tool"),-1)
        consume_idx=next((i for i,x in enumerate(call_names) if x.endswith("sequence_state.consume_outcome") or x=="self.sequence_state.consume_outcome"),-1)
        add(checks,"Q456","static_order",after_idx>=0 and consume_idx>after_idx,call_names,"after_tool before consume_outcome","AUTHORIZATION_TRANSPORT")

        dangerous_calls=[]
        for file_id,tree in trees.items():
            for call in calls_in(tree):
                if call in {"eval","exec","open","compile","__import__"} or call.endswith(".read") or call.endswith(".write") or call.startswith("subprocess."):
                    dangerous_calls.append(f"{file_id}:{call}")
        add(checks,"Q460","prohibited_calls",not dangerous_calls,dangerous_calls,"no static dangerous/runtime call sites","TOOL")

        scan_rows=[]
        patterns={
            "aws_access_key":r"AKIA[0-9A-Z]{16}",
            "private_key":r"-----BEGIN [A-Z ]*PRIVATE KEY-----",
            "password_assignment":r"(?i)password\s*=\s*[\"'][^\"']+[\"']",
            "api_key_assignment":r"(?i)api[_-]?key\s*=\s*[\"'][^\"']+[\"']",
            "secret_assignment":r"(?i)secret\s*=\s*[\"'][^\"']+[\"']",
        }
        for file_id,text in source_texts.items():
            for label,pattern in patterns.items():
                for match in re.finditer(pattern,text):
                    scan_rows.append({"file_id":file_id,"pattern":label,"line":text.count("\n",0,match.start())+1})
        add(checks,"Q470","static_scan",not scan_rows,scan_rows,"zero configured credential/raw-value literal findings","SECRET_CAPTURE")

        required_prohibited={"runtime behavior","importability","runtime canonicalization correctness","actual fs.read behavior","source retrieval success","secret capture","protected-value lineage","authorization transport correctness","guardrail effectiveness","real exfiltration prevention"}
        add(checks,"Q480","claim_boundary",required_prohibited<=set(claim.get("prohibited",[])),sorted(claim.get("prohibited",[])),sorted(required_prohibited),"CLAIM_BOUNDARY")
        boundaries=result.get("execution_boundaries",{})
        false_fields=["protected_source_modified","sdk_modules_imported","generated_modules_imported","generated_symbols_executed","actual_fs_read_executed","tools_executed","fixture_contents_read","source_value_previewed","source_value_exported","effects_observed","sandbox_instantiated","sandbox_executed","gym_executed","predicates_executed","breach_executed","models_used"]
        add(checks,"Q481","execution_boundary",all(boundaries.get(x) is False for x in false_fields),{x:boundaries.get(x) for x in false_fields},"all prohibited execution fields false","CLAIM_BOUNDARY")

        failed=[r["check_id"] for r in checks if not r["passed"]]
        qualified=not failed
        status="P2O_C_INDEPENDENT_SOURCE_AND_AUTHORIZATION_CONFORMANCE_QUALIFICATION_COMPLETE_PASS" if qualified else "P2O_C_INDEPENDENT_SOURCE_AND_AUTHORIZATION_CONFORMANCE_QUALIFICATION_COMPLETE_WITH_GAPS"
        next_gate="EX6_P2B_P2O_D_CONTROLLED_IMPORT_AND_PURE_UNIT_QUALIFICATION" if qualified else "EX6_P2B_P2O_C_R1_SOURCE_CONFORMANCE_RECONCILIATION"
        claim_out={"allowed":["independent static source identity and authorization conformance findings","exact static signature and import-normalization findings","static fail-closed construct findings","narrow configured credential/raw-value scan findings","eligibility recommendation for a separate controlled import and pure-unit gate"],"prohibited":["importability","runtime behavior","runtime canonicalization correctness","actual fs.read behavior","source retrieval success","secret capture","protected-value lineage","authorization transport correctness","guardrail effectiveness","real exfiltration prevention"]}
        result_out={
            "version":VERSION,"created_at_utc":utc_now(),"status":status,"classification":"READ_ONLY_INDEPENDENT_STATIC_SOURCE_QUALIFICATION","P2O_B_parent_verified":True,
            "checks":{"total":len(checks),"passed":len(checks)-len(failed),"failed":len(failed),"failed_ids":failed},
            "qualification":{"generated_source_identity":"INDEPENDENTLY_QUALIFIED" if qualified else "GAPS_IDENTIFIED","exact_static_authorization_conformance":"INDEPENDENTLY_QUALIFIED" if qualified else "GAPS_IDENTIFIED","import_normalization_rule":normalization["rule_id"],"configured_static_scan_findings":len(scan_rows)},
            "readiness":{"controlled_import_and_pure_unit_gate_eligible":qualified,"generated_modules_imported":False,"generated_symbols_executed":False,"implementation_runtime_qualified":False,"identity_freeze_eligible":False,"controlled_actual_fs_read_eligible":False},
            "execution_boundaries":{"source_modified":False,"protected_source_modified":False,"sdk_modules_imported":False,"generated_modules_imported":False,"generated_symbols_executed":False,"actual_fs_read_executed":False,"tools_executed":False,"fixture_contents_read":False,"source_value_previewed":False,"source_value_exported":False,"effects_observed":False,"sandbox_instantiated":False,"sandbox_executed":False,"gym_executed":False,"predicates_executed":False,"breach_executed":False,"models_used":False},
            "scientific_verdict":{"static_source_conformance":"ESTABLISHED" if qualified else "GAPS_IDENTIFIED","importability":"NOT_EVALUATED","implementation_runtime_behavior":"NOT_EVALUATED","actual_source_retrieval":"NOT_EVALUATED","secret_capture":"NOT_ESTABLISHED","protected_value_lineage":"NOT_ESTABLISHED","authorization_transport_correctness":"NOT_ESTABLISHED","harness_trick":"NOT_DEMONSTRATED","robust_security_findings":"NOT_ESTABLISHED"},
            "claim_boundary":claim_out,"next_gate":next_gate,
        }

        paths={
            "result":out/"ex6_p2b_p2o_c_result.json", "checks":out/"ex6_p2b_p2o_c_checks.csv",
            "sources":out/"ex6_p2b_p2o_c_source_identities.csv", "signatures":out/"ex6_p2b_p2o_c_signatures.csv",
            "imports":out/"ex6_p2b_p2o_c_imports.csv", "import_rule":out/"ex6_p2b_p2o_c_import_normalization.json",
            "protected":out/"ex6_p2b_p2o_c_protected_sources.csv", "fail_closed":out/"ex6_p2b_p2o_c_fail_closed.csv",
            "scan":out/"ex6_p2b_p2o_c_static_scan.csv", "claim":out/"ex6_p2b_p2o_c_claim_boundary.json",
            "binding":out/"ex6_p2b_p2o_c_binding.json",
        }
        write_json(paths["result"],result_out)
        write_csv(paths["checks"],checks,["check_id","category","passed","observed","expected","failure_layer"])
        write_csv(paths["sources"],source_inventory,["file_id","relative_path","size_bytes","sha256","ast_parse"])
        write_csv(paths["signatures"],signature_rows,["file_id","symbol","kind","observed","expected","match"])
        write_csv(paths["imports"],import_rows,["file_id","lineno","style","module","members","alias","allowed_module","prohibited_match"])
        write_json(paths["import_rule"],normalization)
        write_csv(paths["protected"],protected_inventory,["relative_path","sha256","expected_sha256","match"])
        write_csv(paths["fail_closed"],fail_closed,["property","present"])
        write_csv(paths["scan"],scan_rows,["file_id","pattern","line"])
        write_json(paths["claim"],claim_out)
        generated_paths={file_id:project/Path(rel) for file_id,(rel,_,_) in GENERATED.items()}
        write_json(paths["binding"],{"version":VERSION,"created_at_utc":utc_now(),"runner":identity(Path(__file__).resolve()),"inputs":{k:identity(v) for k,v in inputs.items()},"generated_sources":{k:identity(v) for k,v in generated_paths.items()},"project_root":str(project),"source_modified":False,"generated_modules_imported":False})
        derived=tuple(paths.values()); bound=tuple(inputs.values()); generated=tuple(generated_paths.values())
        manifest_rows=[{**identity(p),"role":"P2O_C_DERIVED"} for p in derived]+[{**identity(p),"role":"P2O_C_BOUND"} for p in bound]+[{**identity(p),"role":"P2O_C_QUALIFIED_SOURCE"} for p in generated]
        manifest=out/"ex6_p2b_p2o_c_manifest.csv"; write_csv(manifest,manifest_rows,["artifact","role","size_bytes","sha256","path"])
        external_path=out/"ex6_p2b_p2o_c_manifest_external_binding.json"
        write_json(external_path,{"version":VERSION,"created_at_utc":utc_now(),"status":status,"manifest_filename":manifest.name,"manifest_size_bytes":manifest.stat().st_size,"manifest_sha256":sha256(manifest),"runner_sha256":sha256(Path(__file__).resolve()),"parent_p2o_b_manifest_sha256":PARENT_MANIFEST_SHA,"checks_total":len(checks),"checks_passed":len(checks)-len(failed),"checks_failed":len(failed),"controlled_import_and_pure_unit_gate_eligible":qualified,"generated_modules_imported":False,"generated_symbols_executed":False,"identity_freeze_eligible":False,"controlled_actual_fs_read_eligible":False,"source_modified":False,"next_gate":next_gate})
        print(json.dumps({"status":status,"checks_total":len(checks),"checks_passed":len(checks)-len(failed),"checks_failed":len(failed),"failed_ids":failed,"generated_modules_imported":False,"runtime_behavior":"NOT_EVALUATED","manifest_sha256":sha256(manifest),"next_gate":next_gate},indent=2))
    except Exception as exc:
        (out/"P2O_C_FAILED.json").write_text(json.dumps({"version":VERSION,"created_at_utc":utc_now(),"status":"P2O_C_QUALIFICATION_BLOCKED","error_type":type(exc).__name__,"error":str(exc),"checks_frozen":checks,"source_modified":False,"generated_modules_imported":False,"generated_symbols_executed":False,"actual_fs_read_executed":False,"effects_observed":False},indent=2),encoding="utf-8")
        raise


def parse_args() -> argparse.Namespace:
    p=argparse.ArgumentParser(description=VERSION)
    for flag in [
        "p2o-b-result","p2o-b-generated-files","p2o-b-symbols","p2o-b-imports","p2o-b-protected-after",
        "p2o-b-leakage-scan","p2o-b-claim-boundary","p2o-b-binding","p2o-b-external-binding","p2o-b-manifest","p2o-b-runner",
        "p2o-a-authorization","p2o-a-files","p2o-a-symbols","p2o-a-imports","p2o-a-traceability","p2o-a-protected-sources","p2o-a-manifest",
        "project-root","output-dir",
    ]:
        p.add_argument("--"+flag,required=True)
    return p.parse_args()

if __name__=="__main__":
    try: main(parse_args())
    except Exception as exc: print(f"FAILED: {exc}",file=sys.stderr); raise SystemExit(1)
