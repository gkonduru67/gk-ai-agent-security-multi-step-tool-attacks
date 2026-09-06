#!/usr/bin/env python3
"""Reviewed actual-read lineage synthesis v1.0.

Read-only cross-artifact synthesis. Reconciles:
  A) historical V1.4 actual fs.read -> V2.1 outcome hook -> V2.1 ledger evidence;
  B) corrected V2.2 static evidence; and
  C) controlled V2.2 direct/registry runtime evidence.

The runner does not import project modules, execute Sandbox/tools/fs.read/HTTP,
invoke guardrails/predicates/breach/models, or modify any source/evidence.
It preserves the historical V1.4 gate as 20/21 with AR21-017 failed, while
separately qualifying the narrower positive AR21-014/014A/015/016 lineage
subclaim. It never transfers that V2.1 actual-read subclaim to V2.2.
"""
from __future__ import annotations
import argparse, csv, hashlib, json, sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

VERSION = "REVIEWED_ACTUAL_READ_LINEAGE_SYNTHESIS_v1.0"
EXPECTED = {
    # Current V2.2 controlled runtime
    "runtime_manifest": (5809, "788F755CA351472BFE0E85E02BD93F06029D14018B330869578218B8EE85CCE0"),
    "runtime_result": (11185, "C1EF3868C88BE7DE96A6D9D29FF2900567F921D017864351A7988D841E8017FD"),
    "runtime_checks": (13725, "233A9A1DD37455DEA6871D765F201C00871D6B5D5FFD3190862FB0E6D80729A9"),
    "runtime_cases": (2901, "6158B07DC05931C5F4088EBDC5847C0912FAE3B6758ABC41B6CAE631CB95CAA2"),
    "runtime_substitution": (287, "22BA55254065B11379D36E1B93CE713997612B9E2F9C5A9DA6C5C68BC2E94928"),
    "runtime_claim": (888, "1ED09C13780C1B88BF136EB1DEDCB525C847A5D957BED813DE98D3052D6005D8"),
    "runtime_binding": (6663, "66BE7959FD02001237F3D6DF0DF95958F63FBACE3F9746DFF0DDA6A129F6AA2A"),
    # Corrected V2.2 static parent
    "static_manifest": (4291, "4F832E0895AF3BF49EE8BB14A448862CCF8CD67AF852C93B92C93FF7606E56C0"),
    "static_result": (12456, "F6C1BA9931AF97307D869A53894796A92317056B3DD15543A78B843218A33CC9"),
    "static_checks": (14629, "3A5F3617C25876E8F9AF52441F6BE26B6703590781ED17110B398A154386F3A9"),
    "static_binding": (4383, "FE60D3F530D2E9A7B31C54E0630B960D0DB703179F0450F7EAA9B7A0B12A1063"),
    # Historical V1.4 actual-read evidence
    "historical_manifest": (5282, "FE1350E6779772CDAC9CA4C16D058E53398F1EACA6062F2E0DE2D65B2E4D5AB1"),
    "historical_result": (5209, "20BF135D72E5AF4AC7518E2478A6A4D216642586B608B881262021B84CB4851C"),
    "historical_checks": (11677, "AD2E9AEF89CCCDC6744A3B9205A17CD40AD4EB95023737B77D9FDC88A271AD3E"),
    "historical_events": (1648, "51F7EF65E61F64E68A64C80E9975FF1B41560DC8391F70B1A91A65050A3FD22F"),
    "historical_lineage": (1748, "23C6D8232299310C08D05D4759B1694A582F48135E5CA519AF90CE43C7D8EA3B"),
    "historical_negative_controls": (1941, "B1717B3C27A1F20ED7D22515A8997503A96A9D9C36AE7DEA43135E6135639D77"),
    "historical_fixture": (667, "077A3153BCC82E11A2F3CB5C84C2644E9F783FBE9538ECEB7652BAE840A61DAA"),
    "historical_cleanup": (193, "28271CC6F271C3AC3DE3996AEB9AD340DB23374B109200014DB5B67CBE1F3F88"),
    "historical_claim": (668, "B8749514658CEACC27E63ACB2190FBD5189087D4B626905B6EA3845358F4D339"),
    "historical_binding": (4938, "5E7186A5B615C36591D50268BDAD4B94FE6427091341CD98179137BA773F4EBF"),
}
HISTORICAL_MANIFEST_INTERNAL_SHA = EXPECTED["historical_manifest"][1]
HISTORICAL_RAW_SHA = "C04E5B40CDCF012EF34A974A81A70CD80C98054FAC5856E4A0BACC3D0905CADB"
HISTORICAL_RECORD_ID = "A5EDD32314DF3362F14FA2776209D15210540759C2D5707406298427ED2FB6DD"
V21_LEDGER_SHA = "18146742E6866C491A032AA96EFC248FFED05706895D32FDE724145D0878009C"
V21_HOOK_SHA = "F2DE8D42EE5DBCD3BA4CACD8E98DCCB2EBA63F82EC8683D129C503CCED1CE770"
V22_OUTCOME_SHA = "D5819673ECBB6B3330B27F2C5046F8EB1720924E41236DBF265D631BE7050118"


def now(): return datetime.now(timezone.utc).isoformat()
def require(v,m):
    if not v: raise ValueError(m)
def sha(path):
    h=hashlib.sha256()
    with Path(path).open("rb") as f:
        for block in iter(lambda:f.read(1024*1024),b""):h.update(block)
    return h.hexdigest().upper()
def ident(path):
    p=Path(path).resolve();return {"artifact":p.name,"path":str(p),"size_bytes":p.stat().st_size,"sha256":sha(p)}
def rj(path):return json.loads(Path(path).read_text(encoding="utf-8-sig"))
def rc(path):
    with Path(path).open(encoding="utf-8-sig",newline="") as f:return list(csv.DictReader(f))
def wj(path,val):
    with Path(path).open("x",encoding="utf-8",newline="\n") as f:json.dump(val,f,indent=2,sort_keys=True,ensure_ascii=False,default=str);f.write("\n")
def wc(path,rows,fields):
    with Path(path).open("x",encoding="utf-8",newline="") as f:w=csv.DictWriter(f,fieldnames=fields,extrasaction="ignore",lineterminator="\n");w.writeheader();w.writerows(rows)
def add(rows,cid,cat,ok,obs,exp,layer):
    rows.append({"check_id":cid,"category":cat,"passed":bool(ok),"observed":json.dumps(obs,sort_keys=True,default=str),"expected":json.dumps(exp,sort_keys=True,default=str),"failure_layer":layer})
def event_list(obj):
    if isinstance(obj,list):return obj
    if isinstance(obj,dict):
        for key in ("events","ordered_events","trace"):
            if isinstance(obj.get(key),list):return obj[key]
    return []
def find_check(rows,cid):return next((r for r in rows if r.get("check_id")==cid),None)
def bool_csv(v):return str(v).lower()=="true"

def main(a):
    out=Path(a.output_dir).resolve();require(not out.exists(),f"Refusing overwrite: {out}");out.mkdir(parents=True);checks=[]
    scope={"V2_2_imported":False,"V2_2_modified":False,"V2_1_modified":False,"SDK_modified":False,"Sandbox_instantiated":False,"tools_executed":False,"actual_fs_read_executed":False,"filesystem_fixture_read":False,"HTTP_executed":False,"guardrail_executed":False,"official_predicate_executed":False,"breach_executed":False,"models_used":False,"threads_executed":False,"external_effects_observed":False}
    try:
        paths={
          "runtime_manifest":Path(a.runtime_manifest).resolve(),"runtime_result":Path(a.runtime_result).resolve(),"runtime_checks":Path(a.runtime_checks).resolve(),"runtime_cases":Path(a.runtime_cases).resolve(),"runtime_substitution":Path(a.runtime_substitution).resolve(),"runtime_claim":Path(a.runtime_claim).resolve(),"runtime_binding":Path(a.runtime_binding).resolve(),
          "static_manifest":Path(a.static_manifest).resolve(),"static_result":Path(a.static_result).resolve(),"static_checks":Path(a.static_checks).resolve(),"static_binding":Path(a.static_binding).resolve(),
          "historical_manifest":Path(a.historical_manifest).resolve(),"historical_result":Path(a.historical_result).resolve(),"historical_checks":Path(a.historical_checks).resolve(),"historical_events":Path(a.historical_events).resolve(),"historical_lineage":Path(a.historical_lineage).resolve(),"historical_negative_controls":Path(a.historical_negative_controls).resolve(),"historical_fixture":Path(a.historical_fixture).resolve(),"historical_cleanup":Path(a.historical_cleanup).resolve(),"historical_claim":Path(a.historical_claim).resolve(),"historical_binding":Path(a.historical_binding).resolve(),"historical_external_binding":Path(a.historical_external_binding).resolve(),
        }
        for n,p in paths.items():require(p.is_file(),f"Missing {n}: {p}")
        for i,(n,(size,digest)) in enumerate(EXPECTED.items(),1):
            x=ident(paths[n]);add(checks,f"RAS-{i:03d}","identity",x["size_bytes"]==size and x["sha256"]==digest,x,{"size_bytes":size,"sha256":digest},"FIXTURE")
        external_identity=ident(paths["historical_external_binding"]);external=rj(paths["historical_external_binding"])
        add(checks,"RAS-022","historical_external_binding",external.get("manifest_sha256")==HISTORICAL_MANIFEST_INTERNAL_SHA and external.get("checks_total")==21 and external.get("checks_passed")==20 and external.get("checks_failed")==1 and external.get("failed_ids")==["AR21-017"],
            {"identity":external_identity,"manifest_sha256":external.get("manifest_sha256"),"counts":[external.get("checks_passed"),external.get("checks_total")],"failed_ids":external.get("failed_ids")},
            {"manifest_sha256":HISTORICAL_MANIFEST_INTERNAL_SHA,"counts":[20,21],"failed_ids":["AR21-017"]},"EVIDENCE")

        rr=rj(paths["runtime_result"]);rcs=rc(paths["runtime_checks"]);cases=rc(paths["runtime_cases"]);sub=rj(paths["runtime_substitution"])
        runtime_ok=rr.get("checks")=={"failed":0,"failed_ids":[],"passed":38,"total":38} and rr.get("case_count")==17 and rr.get("outcome")=="CONTROLLED_V2_2_MALFORMED_HOOK_RUNTIME_QUALIFICATION_PASS" and len(rcs)==38 and all(bool_csv(x.get("passed")) for x in rcs)
        add(checks,"RAS-023","current_runtime",runtime_ok,{"checks":rr.get("checks"),"case_count":rr.get("case_count"),"outcome":rr.get("outcome"),"rows":len(rcs)},"38/38; 17 cases; PASS","EVIDENCE")
        static=rj(paths["static_result"]);scs=rc(paths["static_checks"])
        static_ok=static.get("checks")=={"failed":0,"failed_ids":[],"passed":20,"total":20} and static.get("reviewed_disposition")=="INDEPENDENT_V2_2_HOOK_STATIC_QUALIFICATION_PASS_AFTER_QUALIFIER_CORRECTION" and len(scs)==20 and all(bool_csv(x.get("passed")) for x in scs)
        add(checks,"RAS-024","static_parent",static_ok,{"checks":static.get("checks"),"disposition":static.get("reviewed_disposition"),"rows":len(scs)},"20/20 corrected static disposition","EVIDENCE")

        hr=rj(paths["historical_result"]);hcs=rc(paths["historical_checks"]);events_obj=rj(paths["historical_events"]);lineage=rj(paths["historical_lineage"]);neg=rc(paths["historical_negative_controls"]);fixture=rj(paths["historical_fixture"]);cleanup=rj(paths["historical_cleanup"]);hclaim=rj(paths["historical_claim"]);hbind=rj(paths["historical_binding"])
        historical_gate_exact=hr.get("checks")=={"failed":1,"failed_ids":["AR21-017"],"passed":20,"total":21} and hr.get("outcome")=="CONTROLLED_ACTUAL_FS_READ_HOOK_AND_LEDGER_QUALIFICATION_GAP" and len(hcs)==21 and [x.get("check_id") for x in hcs if not bool_csv(x.get("passed"))]==["AR21-017"]
        add(checks,"RAS-025","historical_gate",historical_gate_exact,{"checks":hr.get("checks"),"outcome":hr.get("outcome"),"rows":len(hcs),"failed":[x.get("check_id") for x in hcs if not bool_csv(x.get("passed"))]},"historical gate preserved 20/21 with AR21-017 only","EVIDENCE")

        # Positive historical subclaims are allowed only if their exact rows passed.
        positive_ids=["AR21-014A","AR21-014","AR21-015","AR21-016"]
        positive_rows={cid:find_check(hcs,cid) for cid in positive_ids}
        positive_pass=all(r is not None and bool_csv(r.get("passed")) for r in positive_rows.values())
        add(checks,"RAS-026","historical_positive_subclaim",positive_pass,{cid:(r.get("passed") if r else None) for cid,r in positive_rows.items()},"all four exact positive checks passed","PROVENANCE")

        # Ordered event identity and stage order.
        evs=event_list(events_obj);names=[e.get("event") for e in evs];layers=[e.get("layer") for e in evs]
        expected_names=["fs.read_invocation","tool_result","hook_context","hook_result"]
        ordered_ok=names==expected_names and layers==sorted(layers) and len(set(layers))==len(layers)
        add(checks,"RAS-027","historical_events",ordered_ok,{"events":names,"layers":layers},{"events":expected_names,"strictly_ordered":True},"PROVENANCE")
        by_name={e.get("event"):e for e in evs}
        tool_result=(by_name.get("tool_result") or {}).get("result",{})
        hook_ctx=by_name.get("hook_context") or {}
        hook_result=by_name.get("hook_result") or {}
        event_content_ok=(tool_result.get("ok") is True and tool_result.get("error") is None and tool_result.get("output")==hook_ctx.get("tool_output") and hook_ctx.get("tool_name")=="fs.read" and hook_ctx.get("tool_args")=={"path":"secret.txt"} and (hook_ctx.get("trusted_context") or {}).get("ok") is True and (hook_result.get("metadata") or {}).get("successful_protected_read_recorded_v21") is True)
        add(checks,"RAS-028","historical_events",event_content_ok,{"tool_result":tool_result,"hook_context":hook_ctx,"hook_result":hook_result},"exact tool result -> POST_TOOL_CALL V2.1 hook context -> success metadata","PROVENANCE")

        record=lineage.get("record",{})
        hash_chain=[lineage.get("fixture_sha256"),lineage.get("tool_output_sha256"),lineage.get("ledger_raw_sha256"),record.get("raw_output_sha256")]
        lineage_ok=(lineage.get("fixture_equals_tool") is True and lineage.get("tool_equals_hook") is True and lineage.get("hook_equals_ledger") is True and hash_chain==[HISTORICAL_RAW_SHA]*4 and record.get("record_identity")==HISTORICAL_RECORD_ID and lineage.get("record_identity_expected")==HISTORICAL_RECORD_ID and lineage.get("record_identity_observed")==HISTORICAL_RECORD_ID and record.get("record_sequence")==1 and record.get("tool_name")=="fs.read" and record.get("canonical_path")=="secret.txt" and record.get("explicit_ok") is True)
        add(checks,"RAS-029","historical_lineage",lineage_ok,{"hash_chain":hash_chain,"record_identity":record.get("record_identity"),"sequence":record.get("record_sequence"),"path":record.get("canonical_path")},{"hash_chain":[HISTORICAL_RAW_SHA]*4,"record_identity":HISTORICAL_RECORD_ID,"sequence":1,"path":"secret.txt"},"PROVENANCE")
        fixture_ok=fixture.get("sha256")==HISTORICAL_RAW_SHA and fixture.get("size_bytes")==75 and fixture.get("relative_path")=="secret.txt" and fixture.get("marker") in fixture.get("content","")
        add(checks,"RAS-030","historical_fixture",fixture_ok,{"size":fixture.get("size_bytes"),"sha":fixture.get("sha256"),"path":fixture.get("relative_path"),"marker_present":fixture.get("marker") in fixture.get("content","")},{"size":75,"sha":HISTORICAL_RAW_SHA,"path":"secret.txt","marker_present":True},"SECRET_CAPTURE")

        # V1.4 implementation identity versus V2.2 identity is intentionally different.
        hist_inputs=hbind.get("inputs",{});hist_hook=(hist_inputs.get("hook") or {})
        implementation_gap=(hist_hook.get("sha256")==V21_HOOK_SHA and hist_hook.get("artifact")=="trusted_read_outcome_hook_v2_1.py" and V22_OUTCOME_SHA!=V21_HOOK_SHA)
        add(checks,"RAS-031","cross_version",implementation_gap,{"historical_hook":hist_hook,"V2_2_outcome_sha256":V22_OUTCOME_SHA},{"historical":"trusted_read_outcome_hook_v2_1.py","different_from_V2_2":True},"CROSS_VERSION_LINEAGE_GAP")
        shared_ledger=(hist_inputs.get("ledger") or {}).get("sha256")==V21_LEDGER_SHA and (rr.get("scientific_verdict") or {}).get("controlled_hook_to_ledger_wiring")=="ESTABLISHED_WITH_SUBSTITUTED_PATH_GATE"
        add(checks,"RAS-032","shared_component",shared_ledger,{"historical_ledger":hist_inputs.get("ledger"),"current_wiring":(rr.get("scientific_verdict") or {}).get("controlled_hook_to_ledger_wiring")},{"shared_ledger_sha":V21_LEDGER_SHA,"current_wiring":"ESTABLISHED_WITH_SUBSTITUTED_PATH_GATE"},"PROVENANCE")

        # Current V2.2 claims and explicit substitution boundary.
        current_findings=rr.get("scientific_verdict",{})
        current_ok=(current_findings.get("direct_malformed_proposal_contract")=="ESTABLISHED" and current_findings.get("registry_modified_context_transport")=="ESTABLISHED" and current_findings.get("controlled_hook_to_ledger_wiring")=="ESTABLISHED_WITH_SUBSTITUTED_PATH_GATE" and current_findings.get("actual_source_retrieval")=="NOT_EVALUATED")
        add(checks,"RAS-033","current_claims",current_ok,current_findings,{"direct":"ESTABLISHED","registry":"ESTABLISHED","wiring":"ESTABLISHED_WITH_SUBSTITUTED_PATH_GATE","actual_source":"NOT_EVALUATED"},"CLAIM_BOUNDARY")
        substitution_ok=sub.get("used") is True and sub.get("restored") is True and sub.get("official_predicate_executed") is False and sub.get("claim_limit")=="hook-to-ledger wiring only" and set(sub.get("cases",[]))=={"O5","O6","O6_DUP"}
        add(checks,"RAS-034","substitution_boundary",substitution_ok,sub,{"used":True,"restored":True,"official_predicate_executed":False,"claim_limit":"hook-to-ledger wiring only","cases":["O5","O6","O6_DUP"]},"CLAIM_BOUNDARY")
        o6=[x for x in cases if x.get("case_id") in {"O6","O6_DUP"}]
        duplicate_ok=len(o6)==2 and [int(x.get("ledger_delta","0")) for x in o6]==[1,1] and all(x.get("dependency_mode")=="CONTROLLED_PATH_GATE_TRUE" for x in o6)
        add(checks,"RAS-035","duplicate_boundary",duplicate_ok,o6,{"two_deliveries":True,"deltas":[1,1],"do_not_count_as_distinct_reads":True},"PROVENANCE")

        # Historical negative-control gap stays visible; do not use negative controls to erase positive subclaim.
        negative_rows=[x for x in neg if str(x.get("match")).lower()!="true"]
        historical_gap_visible=(len(negative_rows)==2 and {x.get("control") for x in negative_rows}=={"malformed_tool_args","non_string_output"})
        add(checks,"RAS-036","historical_gap",historical_gap_visible,negative_rows,{"failed_controls":["malformed_tool_args","non_string_output"],"historical_gate_remains_gap":True},"AUTHORIZATION_TRANSPORT")
        cleanup_ok=cleanup.get("cleanup_success") is True and cleanup.get("root_exists_after_cleanup") is False
        add(checks,"RAS-037","cleanup",cleanup_ok,cleanup,{"cleanup_success":True,"root_exists_after_cleanup":False},"FIXTURE")
        historical_scope=(hbind.get("execution_boundaries",{}).get("actual_fixture_fs_read_executed") is True and hbind.get("execution_boundaries",{}).get("hook_registered") is False and hbind.get("execution_boundaries",{}).get("Sandbox_instantiated") is False)
        add(checks,"RAS-038","historical_scope",historical_scope,hbind.get("execution_boundaries",{}),{"actual_fixture_fs_read_executed":True,"hook_registered":False,"Sandbox_instantiated":False},"CLAIM_BOUNDARY")

        # Reviewed disposition: matched V2.2 actual-read evidence is required.
        cross_version_portable=False
        matched_required=positive_pass and lineage_ok and implementation_gap and current_ok and substitution_ok and not cross_version_portable
        add(checks,"RAS-039","disposition",matched_required,{"historical_positive":positive_pass,"historical_lineage":lineage_ok,"different_hook_implementation":implementation_gap,"current_V2_2_actual_source":current_findings.get("actual_source_retrieval"),"cross_version_portable":cross_version_portable},"MATCHED_V2_2_ACTUAL_READ_QUALIFICATION_REQUIRED","CROSS_VERSION_LINEAGE_GAP")
        unchanged=all(ident(paths[n])["size_bytes"]==v[0] and sha(paths[n])==v[1] for n,v in EXPECTED.items())
        add(checks,"RAS-040","immutability",unchanged,"all hash-bound inputs unchanged",True,"FIXTURE")

        failed=[x["check_id"] for x in checks if not x["passed"]]
        if not failed: outcome="MATCHED_V2_2_ACTUAL_READ_QUALIFICATION_REQUIRED"
        elif any(x in failed for x in ("RAS-027","RAS-028","RAS-029")): outcome="HISTORICAL_ACTUAL_READ_IDENTITY_GAP"
        elif any(x in failed for x in ("RAS-031","RAS-039")): outcome="CROSS_VERSION_LINEAGE_GAP"
        else: outcome="NOT_ESTABLISHED"
        status="REVIEWED_ACTUAL_READ_LINEAGE_SYNTHESIS_COMPLETE_PASS" if not failed else "REVIEWED_ACTUAL_READ_LINEAGE_SYNTHESIS_COMPLETE_WITH_GAPS"
        claims={"historical_fixture_bound_positive_lineage":"ESTABLISHED_FOR_V1_4_POSITIVE_PATH_ONLY" if positive_pass and lineage_ok else "NOT_ESTABLISHED","historical_gate_overall":"REMAINS_20_OF_21_WITH_AR21_017","V2_2_malformed_proposal_runtime_contract":"ESTABLISHED","V2_2_registry_transport":"ESTABLISHED","V2_2_controlled_hook_to_ledger_wiring":"ESTABLISHED_WITH_SUBSTITUTED_PATH_GATE","V2_2_actual_fs_read_to_ledger_lineage":"NOT_ESTABLISHED","cross_version_actual_read_parity":"NOT_ESTABLISHED","duplicate_O6_records":"TWO_DELIVERIES_NOT_TWO_SOURCE_READS","matched_V2_2_actual_read_required":True}
        claim_boundary={"allowed":["one V1.4 fixture-bound positive fs.read -> V2.1 hook -> V2.1 ledger chain is supported by passed AR21-014A/014/015/016 and exact lineage artifacts","historical V1.4 gate remains 20 of 21 with AR21-017 failed","V2.2 malformed proposal runtime and registry transport are established","V2.2 substituted-path hook-to-ledger wiring is established","V2.2 actual-read lineage requires a new matched qualification"],"prohibited":["call historical V1.4 gate a full pass","present V1.4 actual read as V2.2 actual read","present O6 as actual source retrieval","present substituted path gate as official matcher","count O6 and O6_DUP as two source reads","claim Sandbox, HTTP, guardrail, predicate, breach, real-agent exfiltration, or robust security"]}
        result={"version":VERSION,"created_at_utc":now(),"status":status,"classification":"READ_ONLY_CROSS_ARTIFACT_LINEAGE_SYNTHESIS","checks":{"total":len(checks),"passed":len(checks)-len(failed),"failed":len(failed),"failed_ids":failed},"outcome":outcome,"reviewed_claims":claims,"historical_positive_lineage":{"implementation":"trusted_read_outcome_hook_v2_1.py","implementation_sha256":V21_HOOK_SHA,"ledger_sha256":V21_LEDGER_SHA,"fixture_raw_sha256":HISTORICAL_RAW_SHA,"record_identity":HISTORICAL_RECORD_ID,"event_order":names,"scope":"V1.4 positive fixture only"},"V2_2_evidence":{"outcome_hook_sha256":V22_OUTCOME_SHA,"actual_source_retrieval":"NOT_EVALUATED","controlled_wiring":"ESTABLISHED_WITH_SUBSTITUTED_PATH_GATE","registry_transport":"ESTABLISHED"},"execution_boundaries":scope,"scientific_verdict":{"historical_positive_actual_read_to_V2_1_ledger":"ESTABLISHED_FOR_V1_4_POSITIVE_FIXTURE_ONLY","historical_gate_overall":"GAP_AR21_017","V2_2_actual_read_to_ledger":"NOT_ESTABLISHED","cross_version_parity":"NOT_ESTABLISHED","matched_V2_2_actual_read":"REQUIRED","harness_trick":"NOT_DEMONSTRATED","robust_security_findings":"NOT_ESTABLISHED"},"claim_boundary":claim_boundary,"next_gate":"CONTROLLED_MATCHED_V2_2_ACTUAL_READ_QUALIFICATION" if not failed else "ACTUAL_READ_LINEAGE_SYNTHESIS_GAP_REVIEW"}
        outputs={"result":out/"reviewed_actual_read_lineage_synthesis_result.json","checks":out/"reviewed_actual_read_lineage_synthesis_checks.csv","matrix":out/"reviewed_actual_read_lineage_claim_matrix.csv","identity":out/"reviewed_actual_read_lineage_identity_map.json","claim":out/"reviewed_actual_read_lineage_claim_boundary.json","binding":out/"reviewed_actual_read_lineage_binding.json"}
        claim_rows=[{"claim":"historical_positive_actual_read_to_V2_1_ledger","status":claims["historical_fixture_bound_positive_lineage"],"basis":"AR21-014A/014/015/016 + ordered events + lineage","portable_to_V2_2":"false"},{"claim":"historical_gate_overall","status":claims["historical_gate_overall"],"basis":"AR21-017 failed","portable_to_V2_2":"false"},{"claim":"V2_2_malformed_proposal_runtime_contract","status":"ESTABLISHED","basis":"controlled runtime 38/38","portable_to_V2_2":"true"},{"claim":"V2_2_registry_transport","status":"ESTABLISHED","basis":"R1/R2/R3","portable_to_V2_2":"true"},{"claim":"V2_2_controlled_hook_to_ledger_wiring","status":"ESTABLISHED_WITH_SUBSTITUTED_PATH_GATE","basis":"O5/O6/O6_DUP","portable_to_V2_2":"controlled wiring only"},{"claim":"V2_2_actual_fs_read_to_ledger_lineage","status":"NOT_ESTABLISHED","basis":"no V2.2 actual fs.read","portable_to_V2_2":"false"},{"claim":"cross_version_actual_read_parity","status":"NOT_ESTABLISHED","basis":"V2.1 and V2.2 hook identities differ","portable_to_V2_2":"false"},{"claim":"matched_V2_2_actual_read_qualification","status":"REQUIRED","basis":"earliest unresolved layer: matched source retrieval -> outcome hook -> ledger","portable_to_V2_2":"next gate"}]
        wj(outputs["result"],result);wc(outputs["checks"],checks,["check_id","category","passed","observed","expected","failure_layer"]);wc(outputs["matrix"],claim_rows,["claim","status","basis","portable_to_V2_2"]);wj(outputs["identity"],{"historical_external_binding":external_identity,"inputs":{n:ident(p) for n,p in paths.items()},"historical_record_identity":HISTORICAL_RECORD_ID,"historical_raw_sha256":HISTORICAL_RAW_SHA,"V2_1_hook_sha256":V21_HOOK_SHA,"V2_2_outcome_sha256":V22_OUTCOME_SHA});wj(outputs["claim"],claim_boundary);wj(outputs["binding"],{"version":VERSION,"created_at_utc":now(),"runner":ident(Path(__file__).resolve()),"inputs":{n:ident(p) for n,p in paths.items()},"execution_boundaries":scope})
        manifest_rows=[{**ident(p),"role":"REVIEWED_LINEAGE_SYNTHESIS_DERIVED"} for p in outputs.values()]+[{**ident(p),"role":"REVIEWED_LINEAGE_SYNTHESIS_BOUND_INPUT"} for p in paths.values()]
        manifest=out/"reviewed_actual_read_lineage_synthesis_manifest.csv";wc(manifest,manifest_rows,["artifact","role","size_bytes","sha256","path"])
        external_out=out/"reviewed_actual_read_lineage_synthesis_manifest_external_binding.json";wj(external_out,{"version":VERSION,"created_at_utc":now(),"status":status,"manifest_filename":manifest.name,"manifest_size_bytes":manifest.stat().st_size,"manifest_sha256":sha(manifest),"runner_sha256":sha(Path(__file__).resolve()),"checks_total":len(checks),"checks_passed":len(checks)-len(failed),"checks_failed":len(failed),"failed_ids":failed,"outcome":outcome,"historical_gate":"20_OF_21_AR21_017_FAILED","historical_positive_subclaim":"ESTABLISHED_FOR_V1_4_POSITIVE_FIXTURE_ONLY","V2_2_actual_read_lineage":"NOT_ESTABLISHED","next_gate":result["next_gate"]})
        print(json.dumps({"status":status,"checks":f"{len(checks)-len(failed)}/{len(checks)}","failed_ids":failed,"outcome":outcome,"historical_gate":"20_OF_21_AR21_017_FAILED","historical_positive_subclaim":"ESTABLISHED_FOR_V1_4_POSITIVE_FIXTURE_ONLY","V2_2_actual_read_lineage":"NOT_ESTABLISHED","manifest_sha256":sha(manifest),"next_gate":result["next_gate"]},indent=2))
    except Exception as exc:
        (out/"REVIEWED_ACTUAL_READ_LINEAGE_SYNTHESIS_FAILED.json").write_text(json.dumps({"version":VERSION,"created_at_utc":now(),"status":"BLOCKED","error_type":type(exc).__name__,"error":str(exc),"checks_frozen":checks,"execution_boundaries":scope},indent=2,default=str),encoding="utf-8");raise

def parse():
    p=argparse.ArgumentParser(description=VERSION)
    names=("runtime-manifest","runtime-result","runtime-checks","runtime-cases","runtime-substitution","runtime-claim","runtime-binding","static-manifest","static-result","static-checks","static-binding","historical-manifest","historical-result","historical-checks","historical-events","historical-lineage","historical-negative-controls","historical-fixture","historical-cleanup","historical-claim","historical-binding","historical-external-binding","output-dir")
    for n in names:p.add_argument("--"+n,required=True)
    return p.parse_args()
if __name__=="__main__":
    try:main(parse())
    except Exception as exc:print(f"FAILED: {exc}",file=sys.stderr);raise SystemExit(1)
