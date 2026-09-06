#!/usr/bin/env python3
"""Read-only inventory of historical Jupyter notebooks for EXFILTRATION preflight.

The program never executes or writes a notebook. It hashes each original file
before parsing and again afterward, creates fail-if-exists evidence packages in
both project and log roots, and uses only the Python standard library.
"""
from __future__ import annotations
import argparse, ast, csv, datetime as dt, hashlib, json, logging, os, re, shutil, socket, sys
from collections import Counter
from pathlib import Path
from typing import Any

VERSION = "EXFIL_HISTORICAL_INVENTORY_v1.0.0"
VRE = re.compile(r"(?i)(?<![A-Za-z0-9])v?1[._-]1[._-]0*(\d{1,3})(?!\d)")
TERMS = ("exfil", "fs.read", "http.post", "secret", "protected", "predicate", "breach", "guardrail", "source", "sink", "payload", "fixture", "encoded", "base64", "provenance")
CONTROL = ("synthetic_predicate_positive", "source_only", "sink_only", "read_then_post", "unrelated_post", "encoded_derivation", "guardrail_block", "failed_source_attribution", "wrong_source_value", "post_without_successful_effect")
FAIL = ("traceback", "exception", "error", "failed", "denied", "blocked", "timeout", "invalid argument")
SUCCESS = ("success", "succeeded", "tool_result", "tool result", "status_code", "status code", " 200", "effect_observed")
FILE_RE = re.compile(r"(?i)(?P<p>(?:[A-Z]:[/\\]|\.{0,2}[/\\])[^\s\"'`<>|]+?\.(?:py|ipynb|json|ya?ml|csv|tsv|txt|log|md|parquet|pkl|pickle|bin|db|sqlite|xml))")
LITERAL_RE = re.compile(r"(?i)(?P<p>[A-Za-z0-9_.-]+\.(?:py|ipynb|json|ya?ml|csv|tsv|txt|log|md|parquet|pkl|pickle|bin|db|sqlite|xml))")

NB_FIELDS = "run_id script_version relative_path filename version_token version_patch sha256_before sha256_after hash_stable size_bytes mtime_ns nbformat nbformat_minor kernel_name kernel_display_name language_name language_version cell_count code_cell_count markdown_cell_count raw_cell_count other_cell_count executed_code_cell_count unexecuted_code_cell_count code_cells_with_outputs output_count error_cell_count execution_count_min execution_count_max duplicate_execution_counts out_of_order_execution_counts exfiltration_related_cell_count reference_count scientific_status status_rationale manual_review_required parse_status parse_error_sha256".split()
CELL_FIELDS = "run_id notebook_relative_path notebook_sha256 cell_index cell_type execution_count source_sha256 source_char_count output_count output_types outputs_sha256 has_error_output error_names exfiltration_related matched_terms concise_purpose evidence_scope".split()
REF_FIELDS = "run_id notebook_relative_path notebook_sha256 cell_index reference_type reference_text normalized_reference resolution_base resolved_path exists_at_inventory_time referenced_file_sha256 referenced_file_size hash_status".split()
HASH_FIELDS = "run_id relative_path filename version_token size_bytes mtime_ns sha256_before sha256_after hash_stable".split()
MANIFEST_FIELDS = "run_id artifact_role relative_path size_bytes sha256".split()

def sha_file(p: Path) -> str:
    h = hashlib.sha256()
    with p.open("rb") as f:
        for b in iter(lambda: f.read(1024 * 1024), b""): h.update(b)
    return h.hexdigest().upper()

def sha_bytes(b: bytes) -> str: return hashlib.sha256(b).hexdigest().upper()
def txt(v: Any) -> str: return v if isinstance(v, str) else "".join(map(str, v)) if isinstance(v, list) else "" if v is None else str(v)
def clean(s: str, n: int = 240) -> str:
    s = re.sub(r"[\x00-\x1f\x7f]+", " ", s); s = re.sub(r"\s+", " ", s).strip()
    s = re.sub(r"(?i)(secret|token|password|api[_-]?key)\s*[:=]\s*\S+", r"\1=<REDACTED>", s)
    s = re.sub(r"\b[A-Za-z0-9+/=_-]{48,}\b", "<LONG_TOKEN_REDACTED>", s)
    return s[:n]
def write_csv(p: Path, fields: list[str], rows: list[dict[str, Any]]) -> None:
    with p.open("x", encoding="utf-8-sig", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fields, extrasaction="raise"); w.writeheader()
        for r in rows: w.writerow({k: r.get(k, "") for k in fields})
def imports(src: str) -> set[str]:
    out = set()
    try: tree = ast.parse(src)
    except (SyntaxError, ValueError): return out
    for n in ast.walk(tree):
        if isinstance(n, ast.Import): out |= {a.name for a in n.names}
        elif isinstance(n, ast.ImportFrom) and n.module: out.add(n.module)
    return out
def out_text(o: dict[str, Any]) -> str:
    d = o.get("data", {}); vals = list(d.values()) if isinstance(d, dict) else []
    return "\n".join(txt(x) for x in [o.get("name"), o.get("ename"), o.get("evalue"), o.get("text"), o.get("traceback"), *vals])
def version(name: str):
    m = VRE.search(name); return (m.group(0), int(m.group(1))) if m else ("", None)
def ref_type(s: str) -> str:
    x = Path(s.replace("\\", "/")).suffix.lower()
    if x == ".py": return "LOCAL_SCRIPT_OR_MODULE"
    if x == ".ipynb": return "NOTEBOOK"
    if x in {".json", ".yaml", ".yml", ".txt", ".xml", ".db", ".sqlite"}: return "FIXTURE_OR_INPUT_CANDIDATE"
    return "INPUT_OR_OUTPUT_ARTIFACT_CANDIDATE"
def resolve_ref(s: str, nb: Path, project: Path):
    norm = s.strip().strip(".,;:)]}").replace("\\", os.sep).replace("/", os.sep); p = Path(norm)
    candidates = [("ABSOLUTE", p)] if p.is_absolute() else [("NOTEBOOK_PARENT", nb.parent / p), ("PROJECT_ROOT", project / p)]
    for base, c in candidates:
        c = c.resolve(strict=False)
        if c.is_file(): return norm, base, c
    return (norm, candidates[0][0], candidates[0][1].resolve(strict=False)) if candidates else (norm, "UNRESOLVED", p)
def purpose(src: str, terms: list[str]) -> str:
    lines = [x.strip().lstrip("#").strip() for x in src.splitlines() if x.strip() and not x.strip().startswith(("```", "import ", "from "))][:2]
    return clean(("; ".join(lines) or "No concise source description available") + " [matched: " + ", ".join(terms[:8]) + "]")
def classify(sig: dict[str, bool], errors: int, relevant: int):
    if sig["control"]: return "CONTROL", "Explicit control marker found in preserved notebook evidence."
    if all(sig[k] for k in ("read", "post", "data", "read_success", "post_success", "predicate", "breach")):
        return "CANDIDATE_FINDING", "Candidate markers coexist; ordered-trace and referenced-artifact verification remain mandatory."
    if relevant and (errors or sig["failure"]): return "FAILED_DIAGNOSTIC", "EXFILTRATION-relevant evidence contains preserved error or failure markers."
    return "PARTIAL", "Preserved evidence does not establish every mandatory protected-source-to-http.post gate."

def main() -> int:
    ap = argparse.ArgumentParser(description="Create a read-only historical notebook inventory")
    ap.add_argument("--project-root", required=True, type=Path)
    ap.add_argument("--notebook-root", type=Path, help="Default: <project-root>/backup_versions")
    ap.add_argument("--logs-root", type=Path, default=Path(r"C:\x_ai_logs\EXFILTRATION"))
    ap.add_argument("--start-patch", type=int, default=4); ap.add_argument("--end-patch", type=int, default=16)
    ap.add_argument("--run-id", help="Unique ID; default is UTC timestamp")
    a = ap.parse_args(); project = a.project_root.expanduser().resolve(); nbroot = (a.notebook_root or project / "backup_versions").expanduser().resolve(); logs = a.logs_root.expanduser().resolve()
    if not project.is_dir(): ap.error(f"Project root not found: {project}")
    if not nbroot.is_dir(): ap.error(f"Notebook root not found: {nbroot}")
    if a.start_patch > a.end_patch: ap.error("--start-patch must be <= --end-patch")
    rid = a.run_id or dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    if not re.fullmatch(r"[A-Za-z0-9_.-]+", rid): ap.error("Invalid --run-id")
    log_parent = logs / "historical_inventory"; project_parent = project / "EXFILTRATION" / "historical_inventory"
    log_pkg = log_parent / f"inventory_{rid}"; project_pkg = project_parent / f"inventory_{rid}"
    if log_pkg.exists() or project_pkg.exists(): ap.error(f"Refusing to overwrite run_id={rid}")
    log_pkg.mkdir(parents=True, exist_ok=False); project_pkg.mkdir(parents=True, exist_ok=False)
    debug = log_pkg / f"exfil_historical_inventory_debug_{rid}.log"
    logging.basicConfig(level=logging.INFO, format="%(asctime)sZ %(levelname)s %(message)s", handlers=[logging.FileHandler(debug, mode="x", encoding="utf-8"), logging.StreamHandler()])
    log = logging.getLogger("inventory")
    nbs, cells, refs, hashes = [], [], [], []
    selected, excluded = [], []
    for p in sorted(nbroot.rglob("*.ipynb"), key=lambda x: str(x).lower()):
        _, patch = version(p.name)
        (selected if patch is not None and a.start_patch <= patch <= a.end_patch else excluded).append(p)
    if not selected: log.error("No matching notebooks found"); return 2
    initial = {p: (sha_file(p), p.stat().st_size, p.stat().st_mtime_ns) for p in selected}
    exit_code = 0
    for p in selected:
        rel = str(p.relative_to(nbroot)); token, patch = version(p.name); before, size, mtime = initial[p]; log.info("Inspecting %s", rel)
        parse_status, parse_error, doc = "OK", "", {}
        try:
            doc = json.loads(p.read_bytes().decode("utf-8-sig")); assert isinstance(doc, dict) and isinstance(doc.get("cells", []), list)
        except Exception as e:
            parse_status = "ERROR:" + type(e).__name__; parse_error = sha_bytes(str(e).encode()); doc = {"cells": [], "metadata": {}}
        meta = doc.get("metadata", {}) or {}; cs = doc.get("cells", []); counts = Counter(); execs = []; errors = relevant = refcount = 0
        sig = {k: False for k in ("control", "read", "post", "data", "read_success", "post_success", "predicate", "breach", "failure")}
        for i, c in enumerate(cs):
            if not isinstance(c, dict): continue
            typ = str(c.get("cell_type", "other")); counts[typ] += 1; src = txt(c.get("source")); ec = c.get("execution_count")
            if isinstance(ec, int): execs.append(ec)
            outs = c.get("outputs", []) if typ == "code" else []; outs = outs if isinstance(outs, list) else []
            otypes = [str(o.get("output_type", "unknown")) for o in outs if isinstance(o, dict)]; enames = [str(o.get("ename", "UnknownError")) for o in outs if isinstance(o, dict) and o.get("output_type") == "error"]
            errors += bool(enames); counts["with_outputs"] += bool(outs); counts["outputs"] += len(outs)
            observable = (src + "\n" + "\n".join(out_text(o) for o in outs if isinstance(o, dict))).lower(); matched = sorted(t for t in TERMS if t in observable); isrel = bool(matched); relevant += isrel
            normalized = observable.replace("-", "_").replace(" ", "_"); sig["control"] |= any(x in normalized for x in CONTROL); sig["read"] |= "fs.read" in observable or "fs_read" in observable; sig["post"] |= "http.post" in observable or "http_post" in observable; sig["data"] |= bool(re.search(r"[\"']?data[\"']?\s*[:=]", observable)); sig["read_success"] |= sig["read"] and any(x in observable for x in SUCCESS); sig["post_success"] |= sig["post"] and any(x in observable for x in SUCCESS); sig["predicate"] |= "predicate" in observable and any(x in observable for x in SUCCESS); sig["breach"] |= bool(re.search(r"breach\s*[:=]\s*(true|1)", observable)); sig["failure"] |= any(x in observable for x in FAIL)
            cells.append({"run_id": rid, "notebook_relative_path": rel, "notebook_sha256": before, "cell_index": i, "cell_type": typ, "execution_count": ec if ec is not None else "", "source_sha256": sha_bytes(src.encode()), "source_char_count": len(src), "output_count": len(outs), "output_types": json.dumps(otypes, separators=(",", ":")), "outputs_sha256": sha_bytes(json.dumps(outs, sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode()) if outs else "", "has_error_output": bool(enames), "error_names": json.dumps(enames, separators=(",", ":")), "exfiltration_related": isrel, "matched_terms": json.dumps(matched, separators=(",", ":")), "concise_purpose": purpose(src, matched) if isrel else "", "evidence_scope": "SOURCE_AND_EMBEDDED_OUTPUT_STRUCTURE" if outs else "SOURCE_ONLY"})
            found = {(ref_type(m.group("p")), m.group("p")) for rx in (FILE_RE, LITERAL_RE) for m in rx.finditer(src)}
            for mod in imports(src):
                candidate = mod.replace(".", os.sep) + ".py"; _, _, rp = resolve_ref(candidate, p, project)
                if rp.is_file(): found.add(("LOCAL_IMPORTED_MODULE", candidate))
            for rt, raw in sorted(found):
                norm, base, rp = resolve_ref(raw, p, project); exists = rp.is_file(); rh = rs = ""; hs = "NOT_FOUND"
                if exists:
                    try: rh, rs, hs = sha_file(rp), rp.stat().st_size, "HASHED"
                    except OSError as e: hs = "HASH_ERROR:" + type(e).__name__
                refs.append({"run_id": rid, "notebook_relative_path": rel, "notebook_sha256": before, "cell_index": i, "reference_type": rt, "reference_text": clean(raw, 500), "normalized_reference": clean(norm, 500), "resolution_base": base, "resolved_path": str(rp), "exists_at_inventory_time": exists, "referenced_file_sha256": rh, "referenced_file_size": rs, "hash_status": hs}); refcount += 1
        status, rationale = classify(sig, errors, relevant)
        if parse_status != "OK": status, rationale = "PARTIAL", "Notebook JSON could not be parsed; only file identity is established."
        after = sha_file(p); st = p.stat(); stable = before == after and size == st.st_size and mtime == st.st_mtime_ns
        if not stable: exit_code = 3; log.error("Notebook changed during inventory: %s", rel)
        kernel = meta.get("kernelspec", {}) if isinstance(meta, dict) else {}; lang = meta.get("language_info", {}) if isinstance(meta, dict) else {}; dup = sorted(k for k, v in Counter(execs).items() if v > 1)
        nbs.append({"run_id": rid, "script_version": VERSION, "relative_path": rel, "filename": p.name, "version_token": token, "version_patch": patch, "sha256_before": before, "sha256_after": after, "hash_stable": stable, "size_bytes": size, "mtime_ns": mtime, "nbformat": doc.get("nbformat", ""), "nbformat_minor": doc.get("nbformat_minor", ""), "kernel_name": kernel.get("name", "") if isinstance(kernel, dict) else "", "kernel_display_name": kernel.get("display_name", "") if isinstance(kernel, dict) else "", "language_name": lang.get("name", "") if isinstance(lang, dict) else "", "language_version": lang.get("version", "") if isinstance(lang, dict) else "", "cell_count": len(cs), "code_cell_count": counts["code"], "markdown_cell_count": counts["markdown"], "raw_cell_count": counts["raw"], "other_cell_count": len(cs)-counts["code"]-counts["markdown"]-counts["raw"], "executed_code_cell_count": len(execs), "unexecuted_code_cell_count": counts["code"]-len(execs), "code_cells_with_outputs": counts["with_outputs"], "output_count": counts["outputs"], "error_cell_count": errors, "execution_count_min": min(execs) if execs else "", "execution_count_max": max(execs) if execs else "", "duplicate_execution_counts": json.dumps(dup), "out_of_order_execution_counts": any(a>b for a,b in zip(execs, execs[1:])), "exfiltration_related_cell_count": relevant, "reference_count": refcount, "scientific_status": status, "status_rationale": rationale, "manual_review_required": True, "parse_status": parse_status, "parse_error_sha256": parse_error})
        hashes.append({"run_id": rid, "relative_path": rel, "filename": p.name, "version_token": token, "size_bytes": size, "mtime_ns": mtime, "sha256_before": before, "sha256_after": after, "hash_stable": stable})
    names = {"notebooks": f"exfil_historical_notebooks_{rid}.csv", "cells": f"exfil_historical_cells_{rid}.csv", "references": f"exfil_historical_references_{rid}.csv", "hashes": f"exfil_historical_notebook_sha256_{rid}.csv", "preflight": f"exfil_historical_inventory_preflight_{rid}.json", "summary": f"exfil_historical_inventory_summary_{rid}.md", "manifest": f"exfil_historical_inventory_manifest_{rid}.csv"}
    write_csv(log_pkg/names["notebooks"], NB_FIELDS, nbs); write_csv(log_pkg/names["cells"], CELL_FIELDS, cells); write_csv(log_pkg/names["references"], REF_FIELDS, refs); write_csv(log_pkg/names["hashes"], HASH_FIELDS, hashes)
    preflight = {"run_id": rid, "script_version": VERSION, "created_utc": dt.datetime.now(dt.timezone.utc).isoformat(), "host": socket.gethostname(), "python_version": sys.version, "project_root": str(project), "notebook_root": str(nbroot), "logs_root": str(logs), "version_range": {"start_patch": a.start_patch, "end_patch": a.end_patch}, "selected_notebook_count": len(selected), "excluded_ipynb_count": len(excluded), "excluded_ipynb_relative_paths": [str(p.relative_to(nbroot)) for p in excluded], "read_only_method": "binary read + JSON parse in memory; no notebook writer or kernel invoked", "raw_cell_or_output_content_copied": False, "notebook_hash_stability_passed": all(x["hash_stable"] for x in hashes), "parse_error_count": sum(x["parse_status"] != "OK" for x in nbs), "status_counts": dict(Counter(x["scientific_status"] for x in nbs)), "status_labels_are_machine_assisted_triage": True, "exit_code": exit_code}
    with (log_pkg/names["preflight"]).open("x", encoding="utf-8") as f: json.dump(preflight, f, indent=2, sort_keys=True); f.write("\n")
    lines = ["# EXFILTRATION Historical Notebook Inventory", "", f"- Run ID: `{rid}`", f"- Script version: `{VERSION}`", f"- Selected notebooks: **{len(nbs)}**", f"- Notebook byte identity stable: **{preflight['notebook_hash_stability_passed']}**", "", "## Scientific boundary", "", "Statuses are machine-assisted triage. CANDIDATE_FINDING is not confirmation. Ordered trace, fixture, SDK predicate source, referenced artifacts, effect, predicate, and breach require independent verification.", ""]
    for x in nbs: lines += [f"## {x['filename']}", f"- SHA-256: `{x['sha256_before']}`", f"- Status: `{x['scientific_status']}`", f"- Rationale: {x['status_rationale']}", f"- EXFILTRATION-related cells: {x['exfiltration_related_cell_count']}", ""]
    with (log_pkg/names["summary"]).open("x", encoding="utf-8", newline="\n") as f: f.write("\n".join(lines))
    manifest = []
    for p in sorted(log_pkg.iterdir(), key=lambda x: x.name.lower()):
        if p.is_file() and p.name != names["manifest"]: manifest.append({"run_id": rid, "artifact_role": p.stem, "relative_path": p.name, "size_bytes": p.stat().st_size, "sha256": sha_file(p)})
    write_csv(log_pkg/names["manifest"], MANIFEST_FIELDS, manifest)
    for src in sorted(log_pkg.iterdir(), key=lambda x: x.name.lower()):
        if src.is_file():
            dst = project_pkg/src.name; shutil.copy2(src, dst)
            if sha_file(src) != sha_file(dst): raise RuntimeError(f"Mirror hash mismatch: {src.name}")
    print(f"Canonical package: {log_pkg}"); print(f"Verified mirror: {project_pkg}"); return exit_code
if __name__ == "__main__": raise SystemExit(main())
