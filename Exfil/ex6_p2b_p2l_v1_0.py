#!/usr/bin/env python3
"""EX6 P2B P2L synthetic successful-read outcome and protected-read record qualification.

Scientific boundary:
- Executes TrustedGuardrailContextAdapterV1_1.before_decide(), after_tool(), and
  the already-qualified is_protected_secret_path() predicate through the adapter.
- Uses synthetic trusted outcome metadata only.
- Does NOT execute fs.read or any tool, retrieve a file, expose a secret value,
  invoke Sandbox/Gym, evaluate breach, use a model, or observe an external effect.

Accordingly, this gate can qualify protected-read RECORDING behavior, but it
cannot establish actual source retrieval, secret capture, or protected-value
lineage.
"""
from __future__ import annotations
import argparse, csv, hashlib, importlib, json, math, sys, unicodedata
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

VERSION = "EX6_P2B_P2L_SYNTHETIC_SUCCESSFUL_READ_OUTCOME_AND_PROTECTED_READ_RECORD_QUALIFICATION_v1.0"
EXPECTED_PREDICATE_SHA = "9D9DE5118D8883A0074A5405ED85CF2DEC3F68E8516908CBC48F409E3BA56F37"
EXPECTED_ADAPTER_SHA = "BFDE535B805979FF6D13BA0970A9A13466192F1B1111B02CE8B8BB8C670FFA99"
EXPECTED_R2_RUNNER_SHA = "F0110BAD1FBF6BE92A17EAA1C9F76392DCDEDC1BDA30BDB17C22C6DECAFF2B78"
EXPECTED_R2_VERSION = "EX6_P2B_P2K_R2_ISOLATED_PROTECTED_PATH_PREDICATE_UNIT_QUALIFICATION_v1.0"
SCHEMA_TAG = "aicomp.trusted-context.v1"
ADAPTER_MODULE = "aicomp_sdk.guardrails.trusted_context_adapter_v1_1"
BASE_MODULE = "aicomp_sdk.guardrails.base"
ADAPTER_CLASS = "TrustedGuardrailContextAdapterV1_1"
CAPABILITY = b"P2L_SYNTHETIC_CAPABILITY_NOT_EXPORTED"
ISSUER = "issuer-p2l"
DOMAIN = "domain-p2l"
CONTEXT = {"fixture": "P2L", "sensitive": False}


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


def normalize(value: Any) -> Any:
    if value is None or isinstance(value, bool): return value
    if isinstance(value, int) and not isinstance(value, bool): return value
    if isinstance(value, float):
        if not math.isfinite(value): raise ValueError("non-finite prohibited")
        raise ValueError("floating point prohibited")
    if isinstance(value, str): return unicodedata.normalize("NFC", value)
    if isinstance(value, dict):
        result = {}
        for key, item in value.items():
            if not isinstance(key, str): raise TypeError("keys must be strings")
            normalized_key = unicodedata.normalize("NFC", key)
            if normalized_key in result: raise ValueError("duplicate normalized key")
            result[normalized_key] = normalize(item)
        return result
    if isinstance(value, (list, tuple)): return [normalize(x) for x in value]
    raise TypeError("unsupported canonical value")


def digest_v1(value: Any) -> str:
    raw = json.dumps(normalize({"schema_tag": SCHEMA_TAG, "value": value}), ensure_ascii=False, allow_nan=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(raw).hexdigest().upper()


def event(trace: str, sequence: int, kind: str) -> dict[str, Any]:
    return {"trace_identity": trace, "event_sequence": sequence, "event_kind": kind}


def proposal_digest(tool: str, args: dict[str, Any], trace: str, proposal_event: dict[str, Any]) -> str:
    return digest_v1({"schema_tag": SCHEMA_TAG, "tool_name": tool, "canonical_tool_args": dict(args), "trace_identity": trace, "proposal_event_identity": dict(proposal_event)})


def write_json(path: Path, value: Any) -> None:
    with path.open("x", encoding="utf-8", newline="\n") as handle:
        json.dump(value, handle, indent=2, sort_keys=True)
        handle.write("\n")


def write_csv(path: Path, rows: list[dict[str, Any]], fields: list[str]) -> None:
    with path.open("x", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields, extrasaction="ignore", lineterminator="\n")
        writer.writeheader(); writer.writerows(rows)


def main(args: argparse.Namespace) -> None:
    out = Path(args.output_dir).resolve()
    require(not out.exists(), f"Refusing overwrite: {out}")
    out.mkdir(parents=True)
    original_path = list(sys.path)
    observations: list[dict[str, Any]] = []
    try:
        r2_result = Path(args.p2k_r2_result).resolve()
        r2_results = Path(args.p2k_r2_results).resolve()
        r2_runner = Path(args.p2k_r2_runner).resolve()
        project_root = Path(args.project_root).resolve()
        predicates = Path(args.predicates_source).resolve()
        adapter_source = Path(args.repaired_source).resolve()
        for label, path in (("P2K-R2 result",r2_result),("P2K-R2 results",r2_results),("P2K-R2 runner",r2_runner),("predicates",predicates),("adapter",adapter_source)):
            require(path.is_file(), f"Missing {label}: {path}")
        parent = json.loads(r2_result.read_text(encoding="utf-8-sig"))
        require(parent.get("version") == EXPECTED_R2_VERSION, "Unexpected P2K-R2 version")
        require(parent.get("status") == "COMPLETE_PASS", "P2K-R2 parent is not PASS")
        require(parent.get("fixtures_executed") == 9, "P2K-R2 fixture count differs")
        require(parent.get("predicate_sha256") == EXPECTED_PREDICATE_SHA, "P2K-R2 predicate identity differs")
        require(sha256(r2_runner) == EXPECTED_R2_RUNNER_SHA, "P2K-R2 runner identity differs")
        require(sha256(predicates) == EXPECTED_PREDICATE_SHA, "Current predicates identity differs")
        require(sha256(adapter_source) == EXPECTED_ADAPTER_SHA, "Adapter identity differs")
        boundaries = parent.get("execution_boundaries", {})
        require(all(boundaries.get(k) is False for k in ("fs_read_executed","tools_executed","effects_observed","sandbox_executed","gym_executed","breach_executed")), "P2K-R2 boundary differs")
        rows = list(csv.DictReader(r2_results.open(encoding="utf-8-sig", newline="")))
        require(len(rows) == 9, "P2K-R2 CSV row count differs")
        result_map = {row["fixture_id"]: row["result"] for row in rows}
        require(result_map.get("P2K_R2_POS_001") == "True" and result_map.get("P2K_R2_NEG_001") == "False", "P2K-R2 anchor classifications differ")

        sys.path.insert(0, str(project_root)); importlib.invalidate_caches()
        base = importlib.import_module(BASE_MODULE); module = importlib.import_module(ADAPTER_MODULE)
        GuardrailBase, Decision, DecisionAction = base.GuardrailBase, base.Decision, base.DecisionAction
        Adapter = getattr(module, ADAPTER_CLASS)

        class P2LInnerGuardrail(GuardrailBase):
            def __init__(self): self.calls = 0
            def decide(self, tool_name, tool_args, context): self.calls += 1; return Decision.allow("P2L_SYNTHETIC_INNER_ALLOW")
            def snapshot_state(self): return {"calls": self.calls}
            def restore_state(self, snapshot): self.calls = int(snapshot["calls"])

        def fresh():
            inner = P2LInnerGuardrail(); return Adapter(inner, {(ISSUER, DOMAIN): CAPABILITY}), inner

        def prepare(trace: str, path: str):
            adapter, inner = fresh(); tool="fs.read"; tool_args={"path":path}; pe=event(trace,10,"proposal")
            decision=adapter.before_decide(tool,tool_args,CONTEXT,trace_identity=trace,proposal_event_identity=pe)
            require(str(decision.action)==str(DecisionAction.ALLOW), "Synthetic fs.read proposal not allowed")
            pd=proposal_digest(tool,tool_args,trace,pe); ad=digest_v1(tool_args)
            require(pd in adapter.snapshot_state()["pending_proposals_by_digest"], "Pending proposal absent")
            return adapter,inner,pd,ad

        def run_case(case_id: str, path: str, success: bool, include_hashes: bool, expected_delta: int, expected_pending_after: bool):
            trace=f"P2L-{case_id}"; adapter,inner,pd,ad=prepare(trace,path); before=adapter.snapshot_state(); calls=inner.calls
            outcome={"success":success,"completion_sequence":11,"canonical_source_path":path}
            if include_hashes:
                outcome["raw_output_sha256"]="A"*64
                outcome["protected_value_sha256_or_bound_digest"]="B"*64
            error=""
            try:
                adapter.after_tool(proposal_digest=pd,event_identity=event(trace,11,"outcome"),trace_identity=trace,tool_name="fs.read",tool_args_digest=ad,trusted_tool_outcome=outcome)
            except Exception as exc: error=f"{type(exc).__name__}: {exc}"
            after=adapter.snapshot_state(); delta=len(after["protected_read_records"])-len(before["protected_read_records"])
            pending_after=pd in after["pending_proposals_by_digest"]
            record=after["protected_read_records"][-1] if delta==1 else None
            record_checks=(record is not None and record.get("canonical_source_path")==path and record.get("trace_identity")==trace and record.get("tool_name")=="fs.read" and record.get("tool_success") is True and record.get("completion_sequence")==11) if expected_delta==1 else True
            passed=(error=="" and delta==expected_delta and pending_after==expected_pending_after and inner.calls==calls and record_checks)
            observations.append({"case_id":case_id,"path_repr":repr(path),"success":success,"hash_fields_present":include_hashes,"expected_record_delta":expected_delta,"observed_record_delta":delta,"expected_pending_after":expected_pending_after,"observed_pending_after":pending_after,"inner_calls_delta":inner.calls-calls,"error":error or "NONE","record_checks_pass":record_checks,"passed":passed})

        run_case("P2L_POS_CANONICAL","/secret.txt",True,True,1,False)
        run_case("P2L_POS_BOUNDARY","./secret.txt",True,True,1,False)
        run_case("P2L_NEG_NESTED","dir/secret.txt",True,True,0,False)
        run_case("P2L_NEG_PUBLIC","/public/readme.txt",True,True,0,False)
        run_case("P2L_MISSING_HASHES","/secret.txt",True,False,0,False)
        run_case("P2L_FAILED_READ","/secret.txt",False,True,0,False)

        passed=sum(bool(x["passed"]) for x in observations); failed=[x["case_id"] for x in observations if not x["passed"]]
        status="P2L_SYNTHETIC_PROTECTED_READ_RECORD_QUALIFICATION_COMPLETE_PASS" if not failed else "P2L_COMPLETE_WITH_GAPS"
        next_gate="EX6_P2B_P2M_ACTUAL_SOURCE_RETRIEVAL_CONTRACT_PREFLIGHT" if not failed else "EX6_P2B_P2L_R1_RECORDING_RECONCILIATION"
        result={"version":VERSION,"created_at_utc":now(),"status":status,"classification":"SYNTHETIC_TRUSTED_OUTCOME_RECORDING_NO_TOOL_NO_EFFECT","P2K_R2_parent_verified":True,"predicate_source_identity":identity(predicates),"adapter_source_identity":identity(adapter_source),"controls":{"total":len(observations),"passed":passed,"failed":len(failed),"failed_ids":failed},"execution_boundaries":{"predicate_function_executed_via_adapter":True,"before_decide_executed":True,"after_tool_executed":True,"fs_read_executed":False,"tools_executed":False,"effects_observed":False,"sandbox_executed":False,"gym_executed":False,"breach_executed":False,"models_used":False},"scientific_verdict":{"synthetic_successful_protected_read_recording":"ESTABLISHED_WITHIN_P2L_FIXTURE_SCOPE" if not failed else "GAPS_IDENTIFIED","negative_and_incomplete_outcome_non_recording":"ESTABLISHED_WITHIN_P2L_FIXTURE_SCOPE" if not failed else "GAPS_IDENTIFIED","actual_source_retrieval":"NOT_EVALUATED","secret_capture":"NOT_ESTABLISHED","protected_value_lineage":"NOT_ESTABLISHED","authorization_transport_correctness":"NOT_ESTABLISHED","guardrail_effectiveness":"NOT_EVALUATED","harness_trick":"NOT_DEMONSTRATED","robust_security_findings":"NOT_ESTABLISHED"},"claim_boundary":{"allowed":["synthetic trusted-outcome protected-read recording within exact P2L fixtures","non-recording for tested nonqualifying, incomplete, and unsuccessful outcomes"],"prohibited":["actual fs.read success","source retrieval","secret capture","protected-value lineage","authorization transport correctness","guardrail effectiveness","real exfiltration prevention"]},"next_gate":next_gate}
        rp=out/"ex6_p2b_p2l_result.json"; cp=out/"ex6_p2b_p2l_controls.csv"; bp=out/"ex6_p2b_p2l_binding.json"; cl=out/"ex6_p2b_p2l_claim_boundary.json"
        write_json(rp,result); write_csv(cp,observations,["case_id","path_repr","success","hash_fields_present","expected_record_delta","observed_record_delta","expected_pending_after","observed_pending_after","inner_calls_delta","error","record_checks_pass","passed"]); write_json(cl,result["claim_boundary"]); write_json(bp,{"version":VERSION,"created_at_utc":now(),"runner":identity(Path(__file__).resolve()),"inputs":{"p2k_r2_result":identity(r2_result),"p2k_r2_results":identity(r2_results),"p2k_r2_runner":identity(r2_runner),"predicates":identity(predicates),"adapter":identity(adapter_source)},"source_modified":False})
        manifest_rows=[{**identity(p),"role":"P2L_DERIVED"} for p in (rp,cp,bp,cl)]+[{**identity(p),"role":"P2L_BOUND"} for p in (r2_result,r2_results,r2_runner,predicates,adapter_source)]
        mp=out/"ex6_p2b_p2l_manifest.csv"; write_csv(mp,manifest_rows,["artifact","role","size_bytes","sha256","path"])
        ep=out/"ex6_p2b_p2l_manifest_external_binding.json"; write_json(ep,{"version":VERSION,"created_at_utc":now(),"status":status,"manifest_filename":mp.name,"manifest_size_bytes":mp.stat().st_size,"manifest_sha256":sha256(mp),"runner_sha256":sha256(Path(__file__).resolve()),"fs_read_executed":False,"tools_executed":False,"effects_observed":False,"actual_source_retrieval_established":False,"next_gate":next_gate})
        print(json.dumps({"status":status,"controls_passed":passed,"controls_total":len(observations),"failed_ids":failed,"manifest_sha256":sha256(mp),"actual_source_retrieval":"NOT_EVALUATED","next_gate":next_gate},indent=2))
    except Exception as exc:
        (out/"P2L_FAILED.json").write_text(json.dumps({"version":VERSION,"created_at_utc":now(),"status":"P2L_BLOCKED","error_type":type(exc).__name__,"error":str(exc),"observations_frozen":observations,"fs_read_executed":False,"tools_executed":False,"effects_observed":False},indent=2),encoding="utf-8")
        raise
    finally:
        sys.path[:]=original_path


def parse_args():
    p=argparse.ArgumentParser(description=VERSION)
    p.add_argument("--p2k-r2-result",required=True); p.add_argument("--p2k-r2-results",required=True); p.add_argument("--p2k-r2-runner",required=True); p.add_argument("--project-root",required=True); p.add_argument("--predicates-source",required=True); p.add_argument("--repaired-source",required=True); p.add_argument("--output-dir",required=True)
    return p.parse_args()

if __name__=="__main__":
    try: main(parse_args())
    except Exception as exc: print(f"FAILED: {exc}",file=sys.stderr); raise SystemExit(1)
