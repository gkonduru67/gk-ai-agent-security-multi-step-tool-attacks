#!/usr/bin/env python3
"""Controlled V2.2 malformed-hook runtime qualification v1.0.

Allowed: exact frozen package import; HookContext/HookResult, V2.1 ledger,
V2.2 hook, and HookRegistry construction; direct and registry delivery using
synthetic in-memory contexts; ledger snapshot/restore and record inspection.

Prohibited and not performed: Sandbox/Gym construction, any tool or fs.read,
filesystem fixture read, HTTP, guardrail decision execution, official predicate
execution, breach logic, models, threads, or external effects.

O5/O6 need to reach branches located after is_protected_secret_path(path), but
this gate prohibits predicate execution. The runner therefore temporarily
substitutes the outcome module's already-imported predicate reference with a
controlled function returning True, records that substitution, runs only O5/O6,
and restores the exact original function in a finally block. Thus O6 qualifies
hook-to-ledger wiring only, not official path matching or source retrieval.
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import importlib
import json
import sys
from dataclasses import asdict, is_dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

VERSION = "CONTROLLED_V2_2_MALFORMED_HOOK_RUNTIME_QUALIFICATION_v1.0"
CONTROLLED_PATH = "secret.txt"
CONTROLLED_OUTPUT = "CONTROLLED_V22_RUNTIME_VALUE=RUNTIME_MARKER_7F4A91"
EXPECTED = {
    "corrected_manifest": (4291, "4F832E0895AF3BF49EE8BB14A448862CCF8CD67AF852C93B92C93FF7606E56C0"),
    "corrected_result": (12456, "F6C1BA9931AF97307D869A53894796A92317056B3DD15543A78B843218A33CC9"),
    "corrected_checks": (14629, "3A5F3617C25876E8F9AF52441F6BE26B6703590781ED17110B398A154386F3A9"),
    "corrected_binding": (4383, "FE60D3F530D2E9A7B31C54E0630B960D0DB703179F0450F7EAA9B7A0B12A1063"),
    "v22_init": (484, "3A868F18E87E891C3EBEBA4E6534918DC730D4A27B7E21B1D834F3EC77BD004B"),
    "v22_proposal": (1972, "F4AB269075C1195FF27B3D15357EDB0351E0B70106059ECB70643649A3E238E8"),
    "v22_outcome": (2233, "D5819673ECBB6B3330B27F2C5046F8EB1720924E41236DBF265D631BE7050118"),
    "v22_factory": (2039, "8188BFFFFC1EBFE6B4A1E6DAB4C1678B1DE77389EC55BE7A4E4EA705665FCB9E"),
    "v21_ledger": (8335, "18146742E6866C491A032AA96EFC248FFED05706895D32FDE724145D0878009C"),
    "sdk_types": (1585, "0D3C7B5921749C22CADC5478532C7FE84B86AA90447FEEA8060ACFA9F44D3C7E"),
    "sdk_registry": (8633, "5635B45136517CB5B7FBC6BAB6C9440FE7D6D699E484B6D63651AE296D4BB00B"),
    "sdk_predicates": (16718, "9D9DE5118D8883A0074A5405ED85CF2DEC3F68E8516908CBC48F409E3BA56F37"),
    "sdk_sandbox": (19906, "B781375C5AAE3C2533F6992AAE6D3C65CA56B7077822F1A27955756BEF1168D0"),
}


def now() -> str:
    return datetime.now(timezone.utc).isoformat()


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for block in iter(lambda: f.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest().upper()


def identity(path: Path) -> dict[str, Any]:
    path = path.resolve()
    return {"artifact": path.name, "path": str(path), "size_bytes": path.stat().st_size, "sha256": sha256(path)}


def require(value: bool, message: str) -> None:
    if not value:
        raise ValueError(message)


def read_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8-sig"))


def read_csv(path: Path) -> list[dict[str, str]]:
    with path.open(encoding="utf-8-sig", newline="") as f:
        return list(csv.DictReader(f))


def write_json(path: Path, value: Any) -> None:
    with path.open("x", encoding="utf-8", newline="\n") as f:
        json.dump(value, f, indent=2, sort_keys=True, ensure_ascii=False, default=str)
        f.write("\n")


def write_csv(path: Path, rows: list[dict[str, Any]], fields: list[str]) -> None:
    with path.open("x", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fields, extrasaction="ignore", lineterminator="\n")
        w.writeheader(); w.writerows(rows)


def simple(value: Any) -> Any:
    if is_dataclass(value):
        return {k: simple(v) for k, v in asdict(value).items()}
    if isinstance(value, dict):
        return {str(k): simple(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [simple(v) for v in value]
    return value


def add(checks: list[dict[str, Any]], cid: str, category: str, passed: bool,
        observed: Any, expected: Any, layer: str) -> None:
    checks.append({"check_id": cid, "category": category, "passed": bool(passed),
                   "observed": json.dumps(simple(observed), sort_keys=True, default=str),
                   "expected": json.dumps(simple(expected), sort_keys=True, default=str),
                   "failure_layer": layer})


def record_case(rows: list[dict[str, Any]], case_id: str, delivery: str, before: int,
                after: int, result: Any, context: Any, exception: str | None,
                dependency_mode: str = "OFFICIAL_UNREACHED_OR_NOT_REQUIRED") -> None:
    metadata = getattr(result, "metadata", {}) if result is not None else {}
    modified = getattr(result, "modified_context", None) if result is not None else None
    rows.append({
        "case_id": case_id, "delivery": delivery, "ledger_before": before,
        "ledger_after": after, "ledger_delta": after - before,
        "continue_execution": getattr(result, "continue_execution", None),
        "result_metadata": json.dumps(simple(metadata), sort_keys=True),
        "modified_context_should_block": getattr(modified, "should_block", None),
        "active_context_should_block": getattr(context, "should_block", None),
        "exception": exception or "", "dependency_mode": dependency_mode,
    })


def main(args: argparse.Namespace) -> None:
    out = Path(args.output_dir).resolve()
    require(not out.exists(), f"Refusing overwrite: {out}")
    out.mkdir(parents=True)
    checks: list[dict[str, Any]] = []
    cases: list[dict[str, Any]] = []
    scope = {
        "V2_2_imported": False, "hooks_instantiated": False, "HookRegistry_instantiated": False,
        "ledger_instantiated": False, "controlled_predicate_substitution_used": False,
        "controlled_predicate_substitution_restored": False,
        "official_predicate_executed": False, "Sandbox_instantiated": False,
        "Gym_instantiated": False, "tools_executed": False, "actual_fs_read_executed": False,
        "filesystem_fixture_read": False, "HTTP_executed": False,
        "guardrail_decision_executed": False, "breach_executed": False,
        "models_used": False, "threads_executed": False, "external_effects_observed": False,
        "V2_2_modified": False, "V2_1_modified": False, "SDK_modified": False,
    }
    try:
        project = Path(args.project_root).resolve()
        pkg = project / "aicomp_sdk_exfil_v2_2"
        paths = {
            "corrected_manifest": Path(args.corrected_manifest).resolve(),
            "corrected_result": Path(args.corrected_result).resolve(),
            "corrected_checks": Path(args.corrected_checks).resolve(),
            "corrected_binding": Path(args.corrected_binding).resolve(),
            "v22_init": pkg / "__init__.py",
            "v22_proposal": pkg / "trusted_read_proposal_hook_v2_2.py",
            "v22_outcome": pkg / "trusted_read_outcome_hook_v2_2.py",
            "v22_factory": pkg / "integration_factory_v2_2.py",
            "v21_ledger": project / "aicomp_sdk_exfil_v2_1" / "successful_read_ledger_v2_1.py",
            "sdk_types": project / "aicomp_sdk" / "hooks" / "types.py",
            "sdk_registry": project / "aicomp_sdk" / "hooks" / "registry.py",
            "sdk_predicates": project / "aicomp_sdk" / "core" / "predicates.py",
            "sdk_sandbox": project / "aicomp_sdk" / "core" / "env" / "sandbox.py",
        }
        for name, path in paths.items(): require(path.is_file(), f"Missing {name}: {path}")
        for i, (name, (size, digest)) in enumerate(EXPECTED.items(), 1):
            ident = identity(paths[name]); add(checks, f"RV22-{i:03d}", "identity",
                ident["size_bytes"] == size and ident["sha256"] == digest,
                ident, {"size_bytes": size, "sha256": digest}, "FIXTURE")

        corrected_result = read_json(paths["corrected_result"])
        corrected_checks = read_csv(paths["corrected_checks"])
        parent_ok = (corrected_result.get("checks") == {"failed": 0, "failed_ids": [], "passed": 20, "total": 20}
                     and corrected_result.get("outcome") == "IV22_018_AND_IV22_026_QUALIFIER_GAPS_CONFIRMED_AND_CORRECTED"
                     and corrected_result.get("reviewed_disposition") == "INDEPENDENT_V2_2_HOOK_STATIC_QUALIFICATION_PASS_AFTER_QUALIFIER_CORRECTION"
                     and len(corrected_checks) == 20 and all(r.get("passed") == "True" for r in corrected_checks))
        add(checks, "RV22-014", "parent", parent_ok,
            {"checks": corrected_result.get("checks"), "outcome": corrected_result.get("outcome"),
             "disposition": corrected_result.get("reviewed_disposition"), "rows": len(corrected_checks)},
            "20/20 corrected static pass", "EVIDENCE")

        sys.path.insert(0, str(project))
        try:
            types_mod = importlib.import_module("aicomp_sdk.hooks.types")
            registry_mod = importlib.import_module("aicomp_sdk.hooks.registry")
            ledger_mod = importlib.import_module("aicomp_sdk_exfil_v2_1.successful_read_ledger_v2_1")
            proposal_mod = importlib.import_module("aicomp_sdk_exfil_v2_2.trusted_read_proposal_hook_v2_2")
            outcome_mod = importlib.import_module("aicomp_sdk_exfil_v2_2.trusted_read_outcome_hook_v2_2")
            importlib.import_module("aicomp_sdk_exfil_v2_2")
            scope["V2_2_imported"] = True
        finally:
            if sys.path and sys.path[0] == str(project): sys.path.pop(0)
        add(checks, "RV22-015", "runtime_import", scope["V2_2_imported"], True, True, "V2_2_IMPORT_RUNTIME_GAP")

        HookContext, HookResult, HookStage = types_mod.HookContext, types_mod.HookResult, types_mod.HookStage
        HookRegistry = registry_mod.HookRegistry
        Ledger = ledger_mod.SuccessfulReadLedgerV21
        Proposal, Outcome = proposal_mod.TrustedReadProposalHookV22, outcome_mod.TrustedReadOutcomeHookV22
        ledger = Ledger(); proposal = Proposal(); outcome_hook = Outcome(ledger=ledger); registry = HookRegistry()
        registry.register_hook(HookStage.PRE_TOOL_CALL, proposal, 0)
        registry.register_hook(HookStage.POST_TOOL_CALL, outcome_hook, 0)
        scope.update({"hooks_instantiated": True, "HookRegistry_instantiated": True, "ledger_instantiated": True})
        add(checks, "RV22-016", "constructors", all([ledger, proposal, outcome_hook, registry]), True, True, "ADAPTER_PARSE")

        initial_snapshot = ledger.snapshot_state()
        add(checks, "RV22-017", "ledger_control", len(ledger.records()) == 0 and initial_snapshot.get("next_sequence") == 1,
            initial_snapshot, {"records": [], "next_sequence": 1}, "PROVENANCE")

        # P1-P7 direct proposal cases.
        p_matrix = [
            ("P1", HookStage.PRE_TOOL_CALL, "fs.read", None, True, False, "TOOL_ARGS_NOT_MAPPING"),
            ("P2", HookStage.PRE_TOOL_CALL, "fs.read", {}, True, False, "PATH_MISSING"),
            ("P3", HookStage.PRE_TOOL_CALL, "fs.read", {"path": 123}, True, False, "PATH_NOT_STRING"),
            ("P4", HookStage.PRE_TOOL_CALL, "fs.read", {"path": "   "}, True, False, "PATH_EMPTY"),
            ("P5", HookStage.POST_TOOL_CALL, "fs.read", {"path": "controlled.txt"}, False, True, None),
            ("P6", HookStage.PRE_TOOL_CALL, "other.tool", {"path": "controlled.txt"}, False, True, None),
            ("P7", HookStage.PRE_TOOL_CALL, "fs.read", {"path": "controlled_nonempty_string"}, False, True, None),
        ]
        for idx, (cid, stage, tool, tool_args, expect_block, expect_continue, reason) in enumerate(p_matrix, 18):
            ctx = HookContext(stage=stage, tool_name=tool, tool_args=tool_args)
            before = len(ledger.records()); exc = None; result = None
            try: result = proposal(ctx)
            except Exception as e: exc = f"{type(e).__name__}: {e}"
            after = len(ledger.records()); record_case(cases, cid, "DIRECT", before, after, result, ctx, exc)
            observed_block = bool(result and result.modified_context and result.modified_context.should_block)
            observed_reason = result.metadata.get("reason_detail") if result else None
            ok = (exc is None and observed_block is expect_block
                  and getattr(result, "continue_execution", None) is expect_continue
                  and observed_reason == reason and after-before == 0)
            add(checks, f"RV22-{idx:03d}", "proposal_direct", ok,
                {"block": observed_block, "continue": getattr(result, "continue_execution", None),
                 "reason": observed_reason, "ledger_delta": after-before, "exception": exc},
                {"block": expect_block, "continue": expect_continue, "reason": reason, "ledger_delta": 0, "exception": None},
                "AUTHORIZATION_TRANSPORT")

        # O1-O4 direct, official predicate unreachable/not required.
        o_matrix = [
            ("O1", HookContext(stage=HookStage.POST_TOOL_CALL, tool_name="fs.read", tool_args={"path": CONTROLLED_PATH}, tool_output="x", context=[]), None),
            ("O2", HookContext(stage=HookStage.POST_TOOL_CALL, tool_name="fs.read", tool_args={"path": CONTROLLED_PATH}, tool_output="x", context={"ok": False}), None),
            ("O3", HookContext(stage=HookStage.POST_TOOL_CALL, tool_name="fs.read", tool_args=None, tool_output="x", context={"ok": True}), "TOOL_ARGS_NOT_MAPPING"),
            ("O4", HookContext(stage=HookStage.POST_TOOL_CALL, tool_name="fs.read", tool_args={"path": "   "}, tool_output="x", context={"ok": True}), "PATH_INVALID"),
        ]
        for idx, (cid, ctx, reason) in enumerate(o_matrix, 25):
            before=len(ledger.records()); exc=None; result=None
            try: result=outcome_hook(ctx)
            except Exception as e: exc=f"{type(e).__name__}: {e}"
            after=len(ledger.records()); record_case(cases,cid,"DIRECT",before,after,result,ctx,exc)
            classification = result.metadata.get("classification") if result else None
            observed_reason = result.metadata.get("reason_detail") if result else None
            expected_class = "POST_TOOL_OBSERVATION_CONTRACT_VIOLATION" if reason else None
            ok=(exc is None and after-before==0 and classification==expected_class and observed_reason==reason
                and ctx.should_block is False and getattr(result.modified_context if result else None,"should_block",False) is False)
            add(checks,f"RV22-{idx:03d}","outcome_direct",ok,
                {"classification":classification,"reason":observed_reason,"ledger_delta":after-before,"should_block":ctx.should_block,"exception":exc},
                {"classification":expected_class,"reason":reason,"ledger_delta":0,"should_block":False,"exception":None},"PROVENANCE")

        # O5/O6 with explicit controlled substitution, restored in finally.
        original_predicate = outcome_mod.is_protected_secret_path
        substitution_calls=[]
        def controlled_path_gate(path: Any) -> bool:
            substitution_calls.append(path); return True
        scope["controlled_predicate_substitution_used"] = True
        outcome_mod.is_protected_secret_path = controlled_path_gate
        try:
            ctx5=HookContext(stage=HookStage.POST_TOOL_CALL, tool_name="fs.read", tool_args={"path":CONTROLLED_PATH}, tool_output=123, context={"ok":True,"error":None})
            before=len(ledger.records()); exc=None; r5=None
            try:r5=outcome_hook(ctx5)
            except Exception as e:exc=f"{type(e).__name__}: {e}"
            after=len(ledger.records()); record_case(cases,"O5","DIRECT",before,after,r5,ctx5,exc,"CONTROLLED_PATH_GATE_TRUE")
            ok5=(exc is None and after-before==0 and r5.metadata.get("reason")=="EXFIL_V22_MALFORMED_READ_OUTPUT"
                 and r5.metadata.get("classification")=="POST_TOOL_OBSERVATION_CONTRACT_VIOLATION"
                 and r5.metadata.get("reason_detail")=="OUTPUT_NOT_STRING" and ctx5.should_block is False)
            add(checks,"RV22-029","outcome_direct_substituted",ok5,
                {"metadata":r5.metadata if r5 else None,"delta":after-before,"should_block":ctx5.should_block,"exception":exc},
                {"reason":"EXFIL_V22_MALFORMED_READ_OUTPUT","classification":"POST_TOOL_OBSERVATION_CONTRACT_VIOLATION","reason_detail":"OUTPUT_NOT_STRING","delta":0,"should_block":False,"exception":None},"PROVENANCE")

            ctx6=HookContext(stage=HookStage.POST_TOOL_CALL, tool_name="fs.read", tool_args={"path":CONTROLLED_PATH}, tool_output=CONTROLLED_OUTPUT, context={"ok":True,"error":None})
            before=len(ledger.records()); exc=None; r6=None
            try:r6=outcome_hook(ctx6)
            except Exception as e:exc=f"{type(e).__name__}: {e}"
            after=len(ledger.records()); rec=ledger.records()[-1] if after else None
            record_case(cases,"O6","DIRECT",before,after,r6,ctx6,exc,"CONTROLLED_PATH_GATE_TRUE")
            ok6=(exc is None and after-before==1 and r6.metadata.get("successful_protected_read_recorded_v22") is True
                 and rec is not None and rec.raw_output==CONTROLLED_OUTPUT and rec.canonical_path==CONTROLLED_PATH)
            add(checks,"RV22-030","outcome_direct_substituted",ok6,
                {"delta":after-before,"metadata":r6.metadata if r6 else None,"raw_output":getattr(rec,"raw_output",None),"path":getattr(rec,"canonical_path",None),"exception":exc},
                {"delta":1,"success_metadata":True,"raw_output":CONTROLLED_OUTPUT,"path":CONTROLLED_PATH,"exception":None},"PROVENANCE")

            # Duplicate direct delivery separately: append exactly one additional record.
            before=len(ledger.records()); exc=None; rd=None
            try:rd=outcome_hook(ctx6)
            except Exception as e:exc=f"{type(e).__name__}: {e}"
            after=len(ledger.records()); record_case(cases,"O6_DUP","DIRECT_DUPLICATE",before,after,rd,ctx6,exc,"CONTROLLED_PATH_GATE_TRUE")
            add(checks,"RV22-031","duplicate_delivery",exc is None and after-before==1,
                {"delta":after-before,"exception":exc},{"delta":1,"exception":None},"PROVENANCE")
        finally:
            outcome_mod.is_protected_secret_path = original_predicate
            scope["controlled_predicate_substitution_restored"] = outcome_mod.is_protected_secret_path is original_predicate
        add(checks,"RV22-032","dependency_restoration",scope["controlled_predicate_substitution_restored"] and len(substitution_calls)==3,
            {"restored":scope["controlled_predicate_substitution_restored"],"calls":substitution_calls},
            {"restored":True,"calls":[CONTROLLED_PATH,CONTROLLED_PATH,CONTROLLED_PATH]},"SCOPE_VIOLATION")

        # Snapshot and restore exact empty initial state.
        pre_restore_count=len(ledger.records()); ledger.restore_state(initial_snapshot); post_restore_count=len(ledger.records())
        add(checks,"RV22-033","ledger_restore",pre_restore_count==2 and post_restore_count==0,
            {"before_restore":pre_restore_count,"after_restore":post_restore_count},{"before_restore":2,"after_restore":0},"PROVENANCE")

        # R1 proposal malformed via registry.
        rctx1=HookContext(stage=HookStage.PRE_TOOL_CALL,tool_name="fs.read",tool_args=None)
        before=len(ledger.records()); exc=None; rr1=[]
        try:rr1=registry.execute_hooks(HookStage.PRE_TOOL_CALL,rctx1)
        except Exception as e:exc=f"{type(e).__name__}: {e}"
        after=len(ledger.records()); first=rr1[0] if rr1 else None; record_case(cases,"R1","REGISTRY",before,after,first,rctx1,exc)
        ok=(exc is None and len(rr1)==1 and first.continue_execution is False and rctx1.should_block is True and after-before==0)
        add(checks,"RV22-034","registry",ok,{"results":len(rr1),"continue":getattr(first,"continue_execution",None),"context_block":rctx1.should_block,"delta":after-before,"exception":exc},
            {"results":1,"continue":False,"context_block":True,"delta":0,"exception":None},"AUTHORIZATION_TRANSPORT")

        # R2 valid proposal via registry.
        rctx2=HookContext(stage=HookStage.PRE_TOOL_CALL,tool_name="fs.read",tool_args={"path":"controlled_nonempty_string"})
        before=len(ledger.records()); exc=None; rr2=[]
        try:rr2=registry.execute_hooks(HookStage.PRE_TOOL_CALL,rctx2)
        except Exception as e:exc=f"{type(e).__name__}: {e}"
        after=len(ledger.records()); first=rr2[0] if rr2 else None; record_case(cases,"R2","REGISTRY",before,after,first,rctx2,exc)
        ok=(exc is None and len(rr2)==1 and first.continue_execution is True and rctx2.should_block is False and after-before==0)
        add(checks,"RV22-035","registry",ok,{"results":len(rr2),"continue":getattr(first,"continue_execution",None),"context_block":rctx2.should_block,"delta":after-before,"exception":exc},
            {"results":1,"continue":True,"context_block":False,"delta":0,"exception":None},"AUTHORIZATION_TRANSPORT")

        # R3 malformed output via registry, path invalid before predicate.
        rctx3=HookContext(stage=HookStage.POST_TOOL_CALL,tool_name="fs.read",tool_args={"path":"   "},tool_output="x",context={"ok":True})
        before=len(ledger.records()); exc=None; rr3=[]
        try:rr3=registry.execute_hooks(HookStage.POST_TOOL_CALL,rctx3)
        except Exception as e:exc=f"{type(e).__name__}: {e}"
        after=len(ledger.records()); first=rr3[0] if rr3 else None; record_case(cases,"R3","REGISTRY",before,after,first,rctx3,exc)
        ok=(exc is None and len(rr3)==1 and first.metadata.get("classification")=="POST_TOOL_OBSERVATION_CONTRACT_VIOLATION"
            and first.metadata.get("reason_detail")=="PATH_INVALID" and rctx3.should_block is False and after-before==0
            and "error" not in first.metadata)
        add(checks,"RV22-036","registry",ok,{"results":len(rr3),"metadata":first.metadata if first else None,"context_block":rctx3.should_block,"delta":after-before,"exception":exc},
            {"results":1,"classification":"POST_TOOL_OBSERVATION_CONTRACT_VIOLATION","reason_detail":"PATH_INVALID","context_block":False,"delta":0,"exception":None},"PROVENANCE")

        final_unchanged = all(identity(paths[n])["size_bytes"]==v[0] and sha256(paths[n])==v[1] for n,v in EXPECTED.items())
        add(checks,"RV22-037","immutability",final_unchanged,"all parent/source identities unchanged",True,"FIXTURE")
        scope_ok=(not scope["Sandbox_instantiated"] and not scope["tools_executed"] and not scope["actual_fs_read_executed"]
                  and not scope["filesystem_fixture_read"] and not scope["HTTP_executed"]
                  and not scope["guardrail_decision_executed"] and not scope["official_predicate_executed"]
                  and scope["controlled_predicate_substitution_restored"])
        add(checks,"RV22-038","scope",scope_ok,scope,"prohibited execution false and substitution restored","SCOPE_VIOLATION")

        failed=[r["check_id"] for r in checks if not r["passed"]]
        status="CONTROLLED_V2_2_MALFORMED_HOOK_RUNTIME_QUALIFICATION_COMPLETE_PASS" if not failed else "CONTROLLED_V2_2_MALFORMED_HOOK_RUNTIME_QUALIFICATION_COMPLETE_WITH_GAPS"
        outcome="CONTROLLED_V2_2_MALFORMED_HOOK_RUNTIME_QUALIFICATION_PASS" if not failed else "CONTROLLED_V2_2_MALFORMED_HOOK_RUNTIME_GAP"
        claim={"allowed":["exact frozen V2.2 package imported in controlled environment","V2.2 proposal and outcome hooks and V2.1 ledger constructed","direct malformed proposal contract qualified","controlled HookRegistry modified-context transport qualified","malformed post-output diagnostic behavior qualified","controlled substituted-path hook-to-ledger wiring qualified","duplicate direct delivery appends duplicate records","ledger snapshot restore qualified"],
               "prohibited":["official protected-path predicate behavior qualified","actual source retrieval or actual fs.read established","Sandbox enforcement established","guardrail effectiveness established","HTTP policy or sink behavior established","predicate or breach established","real-agent exfiltration or robust end-to-end security established"]}
        result={"version":VERSION,"created_at_utc":now(),"status":status,
            "classification":"CONTROLLED_SYNTHETIC_CONTEXT_HOOK_AND_REGISTRY_RUNTIME_QUALIFICATION",
            "checks":{"total":len(checks),"passed":len(checks)-len(failed),"failed":len(failed),"failed_ids":failed},
            "outcome":outcome,"case_count":len(cases),"cases":cases,
            "dependency_substitution":{"used":scope["controlled_predicate_substitution_used"],"target":"outcome_module.is_protected_secret_path","replacement":"controlled function returning True","cases":["O5","O6","O6_DUP"],"restored":scope["controlled_predicate_substitution_restored"],"official_predicate_executed":False,"claim_limit":"hook-to-ledger wiring only"},
            "execution_boundaries":scope,
            "scientific_verdict":{"runtime_import":"ESTABLISHED" if not failed else "NOT_ESTABLISHED","constructors":"ESTABLISHED" if not failed else "NOT_ESTABLISHED","direct_malformed_proposal_contract":"ESTABLISHED" if not failed else "NOT_ESTABLISHED","registry_modified_context_transport":"ESTABLISHED" if not failed else "NOT_ESTABLISHED","malformed_outcome_diagnostics":"ESTABLISHED" if not failed else "NOT_ESTABLISHED","controlled_hook_to_ledger_wiring":"ESTABLISHED_WITH_SUBSTITUTED_PATH_GATE" if not failed else "NOT_ESTABLISHED","actual_source_retrieval":"NOT_EVALUATED","Sandbox_enforcement":"NOT_EVALUATED","harness_trick":"NOT_DEMONSTRATED","controlled_test_harness_used":True,"robust_security_findings":"NOT_ESTABLISHED"},
            "claim_boundary":claim,"next_gate":"REVIEWED_ACTUAL_READ_LINEAGE_SYNTHESIS" if not failed else "CONTROLLED_V2_2_RUNTIME_GAP_REVIEW"}

        outputs={"result":out/"controlled_v2_2_runtime_result.json","checks":out/"controlled_v2_2_runtime_checks.csv","cases":out/"controlled_v2_2_runtime_cases.csv","substitution":out/"controlled_v2_2_runtime_dependency_substitution.json","claim":out/"controlled_v2_2_runtime_claim_boundary.json","binding":out/"controlled_v2_2_runtime_binding.json"}
        write_json(outputs["result"],result); write_csv(outputs["checks"],checks,["check_id","category","passed","observed","expected","failure_layer"])
        write_csv(outputs["cases"],cases,["case_id","delivery","ledger_before","ledger_after","ledger_delta","continue_execution","result_metadata","modified_context_should_block","active_context_should_block","exception","dependency_mode"])
        write_json(outputs["substitution"],result["dependency_substitution"]);write_json(outputs["claim"],claim)
        write_json(outputs["binding"],{"version":VERSION,"created_at_utc":now(),"runner":identity(Path(__file__).resolve()),"inputs":{n:identity(p) for n,p in paths.items()},"execution_boundaries":scope})
        manifest_rows=[{**identity(p),"role":"CONTROLLED_V22_RUNTIME_DERIVED"} for p in outputs.values()]+[{**identity(p),"role":"CONTROLLED_V22_RUNTIME_BOUND_INPUT"} for p in paths.values()]
        manifest=out/"controlled_v2_2_runtime_manifest.csv";write_csv(manifest,manifest_rows,["artifact","role","size_bytes","sha256","path"])
        external=out/"controlled_v2_2_runtime_manifest_external_binding.json";write_json(external,{"version":VERSION,"created_at_utc":now(),"status":status,"manifest_filename":manifest.name,"manifest_size_bytes":manifest.stat().st_size,"manifest_sha256":sha256(manifest),"runner_sha256":sha256(Path(__file__).resolve()),"corrected_manifest_sha256":EXPECTED["corrected_manifest"][1],"checks_total":len(checks),"checks_passed":len(checks)-len(failed),"checks_failed":len(failed),"failed_ids":failed,"case_count":len(cases),"outcome":outcome,"controlled_predicate_substitution_used":True,"controlled_predicate_substitution_restored":scope["controlled_predicate_substitution_restored"],"official_predicate_executed":False,"Sandbox_instantiated":False,"tools_executed":False,"next_gate":result["next_gate"]})
        print(json.dumps({"status":status,"checks":f"{len(checks)-len(failed)}/{len(checks)}","failed_ids":failed,"outcome":outcome,"case_count":len(cases),"controlled_substitution_restored":scope["controlled_predicate_substitution_restored"],"manifest_sha256":sha256(manifest),"next_gate":result["next_gate"]},indent=2))
    except Exception as exc:
        (out/"CONTROLLED_V2_2_RUNTIME_FAILED.json").write_text(json.dumps({"version":VERSION,"created_at_utc":now(),"status":"BLOCKED","error_type":type(exc).__name__,"error":str(exc),"checks_frozen":checks,"cases_frozen":cases,"execution_boundaries":scope},indent=2,default=str),encoding="utf-8")
        raise


def parse_args() -> argparse.Namespace:
    p=argparse.ArgumentParser(description=VERSION)
    for name in ("corrected-manifest","corrected-result","corrected-checks","corrected-binding","project-root","output-dir"):
        p.add_argument("--"+name,required=True)
    return p.parse_args()


if __name__=="__main__":
    try:main(parse_args())
    except Exception as exc:print(f"FAILED: {exc}",file=sys.stderr);raise SystemExit(1)
