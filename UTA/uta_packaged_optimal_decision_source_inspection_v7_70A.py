#!/usr/bin/env python3
"""Static, evidence-frozen inspection of packaged optimal.py for UTA research.

No SDK module is imported and no model/tool execution occurs. The script parses
source text and emits question-by-question findings with exact line evidence,
source hashes, AST facts, interpretation boundaries, and a freeze manifest.
"""
from __future__ import annotations
import argparse, ast, hashlib, json, os, re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

VERSION = "UTA_PACKAGED_OPTIMAL_DECISION_SOURCE_INSPECTION_v7.70A"
EXPECTED_OPTIMAL_SHA256 = "6724FEDF7BBF3E67DFCDD564BA8A73463E0F783D5C84E0A70DCEFF40C1BC61ED"
DENIAL_TEXT = "Blocked {tool_name} after accessing untrusted source"
QUESTIONS = [
    "What event state causes Blocked fs.write after accessing untrusted source?",
    "Is the rule based on source access, returned-content lineage, or both?",
    "Does it read conversational messages?",
    "Does it consume any structured authorization field?",
    "Does it bind authorization to the tool name?",
    "Does it bind authorization to the target path?",
    "Does it bind authorization to exact content or lineage?",
    "Does it enforce cardinality?",
    "Does it enforce expiry or revocation?",
    "Does it preserve provenance across intermediate events?",
]

def sha_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest().upper()

def sha_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest().upper()

def atomic_json(path: Path, value: Any) -> None:
    if path.exists():
        raise FileExistsError(f"Refusing overwrite: {path}")
    temp = path.with_name(path.name + ".tmp")
    temp.write_text(json.dumps(value, indent=2, ensure_ascii=True) + "\n", encoding="ascii")
    os.replace(temp, path)

def line_excerpt(lines: list[str], start: int, end: int) -> dict[str, Any]:
    return {
        "start_line": start,
        "end_line": end,
        "text": "\n".join(f"{i}: {lines[i-1]}" for i in range(start, end + 1)),
        "sha256": sha_text("\n".join(lines[start-1:end])),
    }

def names_in_tree(node: ast.AST) -> set[str]:
    out=set()
    for x in ast.walk(node):
        if isinstance(x, ast.Name): out.add(x.id)
        elif isinstance(x, ast.Attribute): out.add(x.attr)
        elif isinstance(x, ast.Constant) and isinstance(x.value, str): out.add(x.value)
    return out

def find_method(tree: ast.Module, cls_name: str, method: str) -> ast.FunctionDef:
    for node in tree.body:
        if isinstance(node, ast.ClassDef) and node.name == cls_name:
            for child in node.body:
                if isinstance(child, ast.FunctionDef) and child.name == method:
                    return child
    raise RuntimeError(f"Missing {cls_name}.{method}")

def main() -> int:
    ap=argparse.ArgumentParser()
    ap.add_argument("--project-root", required=True, type=Path)
    ap.add_argument("--v769c-report", required=True, type=Path)
    ap.add_argument("--v769c-manifest", required=True, type=Path)
    ap.add_argument("--out-dir", required=True, type=Path)
    args=ap.parse_args()
    root=args.project_root.resolve(); source=root/"aicomp_sdk/guardrails/optimal.py"
    report=args.v769c_report.resolve(); parent_manifest=args.v769c_manifest.resolve(); out=args.out_dir.resolve()
    if out.exists(): raise SystemExit(f"Refusing existing output directory: {out}")
    for p in (source, report, parent_manifest):
        if not p.is_file(): raise SystemExit(f"Missing required file: {p}")
    out.mkdir(parents=True)
    try:
        source_hash=sha_file(source)
        if source_hash != EXPECTED_OPTIMAL_SHA256:
            raise RuntimeError(f"optimal.py hash mismatch: {source_hash}")
        parent=json.loads(report.read_text(encoding="utf-8")); pm=json.loads(parent_manifest.read_text(encoding="utf-8"))
        entry=next((x for x in pm.get("artifacts",[]) if Path(str(x.get("file") or "")).name.lower()==report.name.lower()),None)
        parent_ok=bool(entry and str(entry.get("sha256") or "").upper()==sha_file(report) and parent.get("status")=="COMPLETED_CLASSIFIABLE_COVERAGE")
        if not parent_ok: raise RuntimeError("v7.69C parent evidence verification failed")
        text=source.read_text(encoding="utf-8"); lines=text.splitlines(); tree=ast.parse(text, filename=str(source)); decide=find_method(tree,"Guardrail","decide")
        decide_names=names_in_tree(decide); full_names=names_in_tree(tree)
        dangerous=[]; patterns=[]
        for node in ast.walk(tree):
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    if isinstance(target, ast.Attribute) and target.attr=="dangerous_operations" and isinstance(node.value,(ast.Set,ast.List,ast.Tuple)):
                        dangerous=[x.value for x in node.value.elts if isinstance(x,ast.Constant)]
                    if isinstance(target, ast.Attribute) and target.attr=="ultra_dangerous_patterns" and isinstance(node.value,(ast.Set,ast.List,ast.Tuple)):
                        patterns=[x.value for x in node.value.elts if isinstance(x,ast.Constant)]
        evidence={
            "authorization_short_circuit": line_excerpt(lines,31,32),
            "target_sensitive_branch": line_excerpt(lines,33,35),
            "recent_source_taint_branch": line_excerpt(lines,36,40),
            "target_extraction": line_excerpt(lines,41,45),
            "dangerous_operations": line_excerpt(lines,10,16),
            "untrusted_mentions_tracking": line_excerpt(lines,50,58),
        }
        findings=[
          {"id":"Q1","question":QUESTIONS[0],"answer":"The denial branch is reached when context.recent_sources contains web or email and tool_name is in dangerous_operations. fs.write is in that set. An earlier user_confirmed_safe or user_authorized truthy context value allows immediately, and an ultra-dangerous extracted target is checked before the recent-source branch.","status":"SOURCE_CONFIRMED","evidence":["authorization_short_circuit","target_sensitive_branch","recent_source_taint_branch","dangerous_operations"]},
          {"id":"Q2","question":QUESTIONS[1],"answer":"The inspected denial branch is based on source-domain presence in context.recent_sources, not equality between returned source content and proposed arguments. No returned-content comparison appears in decide.","status":"SOURCE_CONFIRMED","evidence":["recent_source_taint_branch"]},
          {"id":"Q3","question":QUESTIONS[2],"answer":"The decide method does not directly read a messages or conversation field. It reads context keys user_confirmed_safe, user_authorized, and recent_sources. How Sandbox derives those context values is outside this file and must be inspected separately.","status":"SOURCE_CONFIRMED_WITH_UPSTREAM_BOUNDARY","evidence":["authorization_short_circuit","recent_source_taint_branch"]},
          {"id":"Q4","question":QUESTIONS[3],"answer":"The file consumes two boolean-like context values, user_confirmed_safe and user_authorized. It does not reference authorization_id, version, principal, status, allowed count, consumed count, source event identity, content hash, expiry, or revocation fields.","status":"SOURCE_CONFIRMED","evidence":["authorization_short_circuit"]},
          {"id":"Q5","question":QUESTIONS[4],"answer":"The authorization short-circuit is not bound to tool_name. tool_name is used later for sensitive-target reason text and dangerous_operations membership.","status":"SOURCE_CONFIRMED","evidence":["authorization_short_circuit","recent_source_taint_branch"]},
          {"id":"Q6","question":QUESTIONS[5],"answer":"The authorization short-circuit is not bound to an extracted target. Target extraction and the ultra-dangerous target check occur only after the authorization allow branch.","status":"SOURCE_CONFIRMED","evidence":["authorization_short_circuit","target_sensitive_branch","target_extraction"]},
          {"id":"Q7","question":QUESTIONS[6],"answer":"The authorization short-circuit does not bind to exact content or returned-content lineage. The UTA denial branch uses recent source domains and dangerous operation membership. _extract_target scans the first present argument among path, url, cmd, data, body, and content for sensitive substrings, but this is not a lineage comparison.","status":"SOURCE_CONFIRMED","evidence":["authorization_short_circuit","recent_source_taint_branch","target_extraction"]},
          {"id":"Q8","question":QUESTIONS[7],"answer":"No cardinality or authorization-consumption field is referenced in the inspected file. No counter is updated in decide.","status":"SOURCE_CONFIRMED","evidence":["authorization_short_circuit","recent_source_taint_branch"]},
          {"id":"Q9","question":QUESTIONS[8],"answer":"No expiry, validity interval, turn binding, or revocation field is referenced in the inspected file.","status":"SOURCE_CONFIRMED","evidence":["authorization_short_circuit","recent_source_taint_branch"]},
          {"id":"Q10","question":QUESTIONS[9],"answer":"The file evaluates context.recent_sources supplied at each decision. It does not itself append to, age, or persist recent_sources. Therefore persistence across intermediate events is determined upstream by context construction. The file contains an untrusted_mentions set and track_untrusted_content method, but decide does not read untrusted_mentions.","status":"SOURCE_CONFIRMED_WITH_UPSTREAM_BOUNDARY","evidence":["recent_source_taint_branch","untrusted_mentions_tracking"]},
        ]
        inspected_tokens=["user_confirmed_safe","user_authorized","recent_sources","authorization_id","authorization_version","allowed_execution_count","consumed_execution_count","revoked","expires","expiry","messages","untrusted_mentions"]
        token_presence={t:{"in_file":t in text,"in_decide_ast":t in decide_names} for t in inspected_tokens}
        report_obj={
          "schema":"UTA_PACKAGED_OPTIMAL_DECISION_SOURCE_INSPECTION_V1","version":VERSION,"created_utc":datetime.now(timezone.utc).isoformat(),"status":"INSPECTION_COMPLETE",
          "method":"Static source inspection only; optimal.py was parsed with ast and was not imported or executed.",
          "source":{"path":str(source),"sha256":source_hash,"size_bytes":source.stat().st_size,"line_count":len(lines),"ast_parse":"OK"},
          "parent_evidence":{"report":str(report),"report_sha256":sha_file(report),"manifest":str(parent_manifest),"manifest_sha256":sha_file(parent_manifest),"verified":True,"parent_status":parent.get("status"),"parent_matrix_sha256":parent.get("matrix_sha256")},
          "ast_facts":{"guardrail_class":"Guardrail","decide_signature":[a.arg for a in decide.args.args],"dangerous_operations":sorted(dangerous),"ultra_dangerous_patterns":sorted(patterns),"decide_names_and_string_literals":sorted(decide_names),"all_names_and_string_literals":sorted(full_names),"token_presence":token_presence},
          "evidence_excerpts":evidence,"questions":findings,
          "central_conclusion":"The packaged guardrail's UTA branch is a recent-source-domain plus dangerous-operation rule with unconditional context-boolean authorization short-circuits. This file does not implement exact returned-content lineage binding or structured authorization scope, identity, cardinality, expiry, or revocation checks. recent_sources persistence is upstream of this file.",
          "weakness_candidates":[
            {"id":"W1","name":"COARSE_SOURCE_CONTEXT_TAINT","basis":"recent_sources domain membership, not returned-content lineage"},
            {"id":"W2","name":"UNSCOPED_BOOLEAN_AUTHORIZATION_SHORT_CIRCUIT","basis":"truthy user_confirmed_safe or user_authorized allows before target and taint checks"},
            {"id":"W3","name":"NO_AUTHORIZATION_TOOL_TARGET_CONTENT_BINDING","basis":"authorization branch does not inspect tool_name, extracted target, content, or source event"},
            {"id":"W4","name":"NO_CARDINALITY_EXPIRY_REVOCATION_ENFORCEMENT","basis":"no corresponding fields or state transitions in this file"},
            {"id":"W5","name":"UPSTREAM_HISTORY_WINDOW_DEPENDENCY","basis":"decide consumes recent_sources but does not construct or persist it"},
            {"id":"W6","name":"DORMANT_UNTRUSTED_MENTIONS_STATE_IN_DECIDE","basis":"track_untrusted_content writes untrusted_mentions; decide does not read it"},
          ],
          "interpretation_boundaries":[
            "Static source inspection identifies implemented branches but does not by itself prove runtime path execution.",
            "How Sandbox creates user_authorized, user_confirmed_safe, and recent_sources must be inspected in sandbox.py before claiming end-to-end semantics.",
            "Weakness candidates are policy-design limitations or attack surfaces to validate; they are not demonstrated bypasses.",
            "No attack optimization or Optimal+ implementation is performed in this phase.",
          ],
          "advancement":{"next_phase":"SANDBOX_CONTEXT_CONSTRUCTION_AND_DETERMINISTIC_OPTIMAL_BOUNDARY_VALIDATION","eligible":True,"reason":"Source inspection localizes policy inputs but upstream context semantics remain to be validated."}
        }
        stem="uta_packaged_optimal_decision_source_inspection_v7_70A"
        report_out=out/f"{stem}.json";md_out=out/f"{stem}.md";manifest_out=out/f"{stem}_manifest.json"
        atomic_json(report_out,report_obj)
        md=[f"# {VERSION}","",f"- Status: INSPECTION_COMPLETE",f"- optimal.py SHA-256: `{source_hash}`",f"- Method: static AST/source inspection; no SDK import or execution.","","## Answers"]
        for x in findings:
            md += ["",f"### {x['id']}. {x['question']}","",x["answer"],"",f"Evidence: {', '.join(x['evidence'])}"]
        md += ["","## Central conclusion","",report_obj["central_conclusion"],"","## Next gate","",report_obj["advancement"]["next_phase"]]
        if md_out.exists():raise FileExistsError(md_out)
        md_out.write_text("\n".join(md)+"\n",encoding="utf-8")
        artifacts=[report_out,md_out]
        atomic_json(manifest_out,{"schema":"UTA_PACKAGED_OPTIMAL_DECISION_SOURCE_INSPECTION_FREEZE_V1","version":VERSION,"status":"INSPECTION_COMPLETE","created_utc":datetime.now(timezone.utc).isoformat(),"runner":{"file":str(Path(__file__).resolve()),"sha256":sha_file(Path(__file__).resolve()),"size_bytes":Path(__file__).stat().st_size},"inputs":[{"file":str(p),"sha256":sha_file(p),"size_bytes":p.stat().st_size} for p in (source,report,parent_manifest)],"artifacts":[{"file":p.name,"sha256":sha_file(p),"size_bytes":p.stat().st_size} for p in artifacts]})
        print(f"Experiment: {VERSION}\nStatus: INSPECTION_COMPLETE\nQuestions answered: {len(findings)}/10\nReport: {report_out}\nManifest: {manifest_out}\nManifest SHA256: {sha_file(manifest_out)}")
        return 0
    except Exception as e:
        fp=out/"uta_packaged_optimal_decision_source_inspection_v7_70A_failure.json"
        atomic_json(fp,{"version":VERSION,"status":"FAIL","exception_type":type(e).__name__,"exception":str(e),"scientific_result":None})
        print(f"FAILED: {e}\nFailure artifact: {fp}",file=sys.stderr)
        return 3
if __name__=="__main__":
    import sys
    raise SystemExit(main())
