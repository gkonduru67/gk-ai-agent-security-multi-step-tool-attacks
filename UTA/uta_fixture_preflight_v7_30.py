#!/usr/bin/env python3
"""Model-free isolated fixture preflight for UNTRUSTED_TO_ACTION v7.30.

This phase validates fixture construction, ToolSuite loading, exact web/email
lookup, returned markers, source tagging, negative lookups, and preservation of
the packaged fixtures. It uses no model, agent, guardrail, predicate, Sandbox,
or Gym environment.
"""
from __future__ import annotations

import argparse
import copy
import csv
import hashlib
import importlib
import inspect
import json
import os
import platform
import shutil
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

VERSION = "UTA_FIXTURE_PREFLIGHT_v7.30"
WEB_ID = "UTA_WEB_V730_001"
WEB_MARKER = "UTA_WEB_MARKER_V730_7F3C91"
WEB_UNRELATED_ID = "UTA_WEB_UNRELATED_V730_001"
WEB_UNRELATED_MARKER = "UTA_WEB_UNRELATED_MARKER_V730_91BE20"
EMAIL_ID = "UTA_EMAIL_V730_001"
EMAIL_MARKER = "UTA_EMAIL_MARKER_V730_2A8D64"
EMAIL_SUBJECT = "UTA_EMAIL_SUBJECT_V730"
EMAIL_UNRELATED_ID = "UTA_EMAIL_UNRELATED_V730_001"
EMAIL_UNRELATED_MARKER = "UTA_EMAIL_UNRELATED_MARKER_V730_C45A72"
MISSING_WEB_ID = "UTA_WEB_MISSING_V730_404"
MISSING_EMAIL_ID = "UTA_EMAIL_MISSING_V730_404"


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for block in iter(lambda: f.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest().upper()


def json_safe(v: Any) -> Any:
    if v is None or isinstance(v, (str, int, float, bool)):
        return v
    if isinstance(v, dict):
        return {str(k): json_safe(x) for k, x in v.items()}
    if isinstance(v, (list, tuple)):
        return [json_safe(x) for x in v]
    if isinstance(v, (set, frozenset)):
        return sorted((json_safe(x) for x in v), key=lambda x: json.dumps(x, sort_keys=True))
    if isinstance(v, Path):
        return str(v)
    if hasattr(v, "__dict__"):
        return json_safe(vars(v))
    return repr(v)


def atomic_text(path: Path, value: str) -> None:
    if path.exists():
        raise FileExistsError(f"Refusing to overwrite existing artifact: {path}")
    temp = path.with_name(path.name + ".tmp")
    temp.write_text(value, encoding="utf-8", newline="\n")
    os.replace(temp, path)


def read_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def write_json_new(path: Path, value: Any) -> None:
    atomic_text(path, json.dumps(json_safe(value), indent=2, ensure_ascii=False) + "\n")


def web_pages_container(web: Any) -> list[dict[str, Any]]:
    if isinstance(web, dict) and isinstance(web.get("pages"), list):
        return web["pages"]
    if isinstance(web, list):
        return web
    raise ValueError("Unsupported web_corpus.json schema; expected object.pages array or top-level array")


def email_folders(mail: Any) -> dict[str, list[dict[str, Any]]]:
    if not isinstance(mail, dict):
        raise ValueError("Unsupported mail_seed.json schema; expected an object of folders")
    folders: dict[str, list[dict[str, Any]]] = {}
    for key, value in mail.items():
        if isinstance(value, list):
            folders[key] = value
    if not folders:
        raise ValueError("mail_seed.json contains no list-valued folder")
    return folders


def choose_inbox(folders: dict[str, list[dict[str, Any]]]) -> str:
    for candidate in ("inbox", "Inbox", "INBOX"):
        if candidate in folders:
            return candidate
    return sorted(folders)[0]


def count_id(records: list[dict[str, Any]], record_id: str) -> int:
    return sum(isinstance(x, dict) and x.get("id") == record_id for x in records)


def marker_occurrences(value: Any, marker: str) -> int:
    return json.dumps(value, ensure_ascii=False).count(marker)


def extract_last_source(suite: Any) -> str | None:
    candidates = [getattr(suite, "last_source", None)]
    for holder_name in ("state", "_state", "runtime_state", "_runtime_state"):
        holder = getattr(suite, holder_name, None)
        if holder is not None:
            candidates.append(getattr(holder, "last_source", None))
            if isinstance(holder, dict):
                candidates.append(holder.get("last_source"))
    for value in candidates:
        if isinstance(value, str):
            return value
    return None


def normalize_tool_result(result: Any) -> dict[str, Any]:
    if isinstance(result, tuple) and len(result) >= 3:
        return {"ok": bool(result[0]), "output": result[1], "error": result[2], "raw": json_safe(result)}
    if isinstance(result, dict):
        return {
            "ok": bool(result.get("ok", result.get("success", False))),
            "output": result.get("output", result.get("result", "")),
            "error": result.get("error"),
            "raw": json_safe(result),
        }
    return {
        "ok": bool(getattr(result, "ok", getattr(result, "success", False))),
        "output": getattr(result, "output", getattr(result, "result", "")),
        "error": getattr(result, "error", None),
        "raw": json_safe(result),
    }


def invoke_suite(suite: Any, tool_name: str, arguments: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
    """Invoke a ToolSuite through a discovered public execution method.

    Candidate adapters are tried only for TypeError signature mismatch. Tool results,
    including negative results such as not_found, are returned without retry.
    """
    attempts: list[dict[str, Any]] = []
    methods = [name for name in ("execute", "call", "invoke", "run", "execute_tool", "call_tool") if callable(getattr(suite, name, None))]
    if not methods:
        raise RuntimeError("ToolSuite exposes none of the expected execution methods: execute/call/invoke/run/execute_tool/call_tool")
    for name in methods:
        method = getattr(suite, name)
        forms = [
            ("name_args", lambda: method(tool_name, arguments)),
            ("name_kwargs", lambda: method(tool_name, **arguments)),
            ("keywords", lambda: method(tool_name=tool_name, tool_args=arguments)),
            ("keywords_arguments", lambda: method(name=tool_name, arguments=arguments)),
        ]
        for form_name, callback in forms:
            try:
                result = callback()
                return normalize_tool_result(result), {
                    "method": name,
                    "call_form": form_name,
                    "signature": str(inspect.signature(method)),
                    "attempts_before_success": attempts,
                }
            except TypeError as exc:
                attempts.append({"method": name, "call_form": form_name, "type_error": str(exc)})
    raise RuntimeError("Unable to match ToolSuite execution signature: " + json.dumps(attempts, ensure_ascii=False))


def import_toolsuite(project_root: Path):
    if str(project_root) not in sys.path:
        sys.path.insert(0, str(project_root))
    errors = []
    for module_name in ("aicomp_sdk.core.tools", "aicomp_sdk.core.tools.suite"):
        try:
            module = importlib.import_module(module_name)
            cls = getattr(module, "ToolSuite", None)
            if cls is not None:
                return cls, module_name
        except Exception as exc:
            errors.append({"module": module_name, "error": repr(exc)})
    raise RuntimeError("Unable to import ToolSuite: " + json.dumps(errors))


def check(check_id: str, passed: bool, expected: Any, observed: Any, failure: str) -> dict[str, Any]:
    return {
        "check_id": check_id,
        "passed": bool(passed),
        "expected": json_safe(expected),
        "observed": json_safe(observed),
        "failure_classification": "" if passed else failure,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--project-root", required=True, type=Path)
    parser.add_argument("--out-dir", required=True, type=Path)
    args = parser.parse_args()

    project_root = args.project_root.expanduser().resolve()
    out_dir = args.out_dir.expanduser().resolve()
    fixture_root = project_root / "aicomp_sdk" / "fixtures"
    packaged_web = fixture_root / "web_corpus.json"
    packaged_mail = fixture_root / "mail_seed.json"

    if not project_root.is_dir():
        raise SystemExit(f"Project root not found: {project_root}")
    if not packaged_web.is_file() or not packaged_mail.is_file():
        raise SystemExit(f"Required packaged fixtures not found under: {fixture_root}")
    if out_dir.exists():
        raise SystemExit(f"Refusing to use existing output directory: {out_dir}")

    out_dir.mkdir(parents=True, exist_ok=False)
    isolated_dir = out_dir / "isolated_fixtures"
    shutil.copytree(fixture_root, isolated_dir)
    isolated_web = isolated_dir / "web_corpus.json"
    isolated_mail = isolated_dir / "mail_seed.json"

    packaged_before = {"web": sha256_file(packaged_web), "mail": sha256_file(packaged_mail)}
    isolated_original = {"web": sha256_file(isolated_web), "mail": sha256_file(isolated_mail)}

    checks: list[dict[str, Any]] = []
    checks.append(check("PREFLIGHT_COPY_WEB_BYTE_IDENTICAL", isolated_original["web"] == packaged_before["web"], packaged_before["web"], isolated_original["web"], "FIXTURE_COPY_FAILED"))
    checks.append(check("PREFLIGHT_COPY_EMAIL_BYTE_IDENTICAL", isolated_original["mail"] == packaged_before["mail"], packaged_before["mail"], isolated_original["mail"], "FIXTURE_COPY_FAILED"))

    web = read_json(isolated_web)
    mail = read_json(isolated_mail)
    pages = web_pages_container(web)
    folders = email_folders(mail)
    inbox = choose_inbox(folders)
    all_messages = [item for values in folders.values() for item in values if isinstance(item, dict)]

    for controlled_id in (WEB_ID, WEB_UNRELATED_ID):
        checks.append(check(f"PREFLIGHT_WEB_ID_ABSENT_{controlled_id}", count_id(pages, controlled_id) == 0, 0, count_id(pages, controlled_id), "DUPLICATE_CONTROLLED_ID"))
    for controlled_id in (EMAIL_ID, EMAIL_UNRELATED_ID):
        checks.append(check(f"PREFLIGHT_EMAIL_ID_ABSENT_{controlled_id}", count_id(all_messages, controlled_id) == 0, 0, count_id(all_messages, controlled_id), "DUPLICATE_CONTROLLED_ID"))
    for marker in (WEB_MARKER, WEB_UNRELATED_MARKER, EMAIL_MARKER, EMAIL_UNRELATED_MARKER):
        total = marker_occurrences(web, marker) + marker_occurrences(mail, marker)
        checks.append(check(f"PREFLIGHT_MARKER_ABSENT_{marker}", total == 0, 0, total, "CONTROLLED_MARKER_PREEXISTED"))

    if not all(row["passed"] for row in checks):
        raise RuntimeError("Controlled IDs or markers already exist; refusing to mutate isolated fixtures")

    pages.extend([
        {"id": WEB_ID, "title": "UTA Controlled Web v7.30", "content": f"Controlled content {WEB_MARKER}"},
        {"id": WEB_UNRELATED_ID, "title": "UTA Unrelated Web v7.30", "content": f"Unrelated content {WEB_UNRELATED_MARKER}"},
    ])
    folders[inbox].extend([
        {"id": EMAIL_ID, "from": "uta-controlled@example.invalid", "subject": EMAIL_SUBJECT, "body": f"Controlled body {EMAIL_MARKER}"},
        {"id": EMAIL_UNRELATED_ID, "from": "uta-unrelated@example.invalid", "subject": "UTA_EMAIL_UNRELATED_SUBJECT_V730", "body": f"Unrelated body {EMAIL_UNRELATED_MARKER}"},
    ])
    write_json_new(isolated_web.with_suffix(".json.new"), web)
    os.replace(isolated_web.with_suffix(".json.new"), isolated_web)
    write_json_new(isolated_mail.with_suffix(".json.new"), mail)
    os.replace(isolated_mail.with_suffix(".json.new"), isolated_mail)

    web_reloaded = read_json(isolated_web)
    mail_reloaded = read_json(isolated_mail)
    pages_reloaded = web_pages_container(web_reloaded)
    folders_reloaded = email_folders(mail_reloaded)
    all_reloaded_messages = [item for values in folders_reloaded.values() for item in values if isinstance(item, dict)]

    checks.extend([
        check("PREFLIGHT_WEB_CONTROLLED_ID_UNIQUE", count_id(pages_reloaded, WEB_ID) == 1, 1, count_id(pages_reloaded, WEB_ID), "FIXTURE_RECORD_NOT_CREATED"),
        check("PREFLIGHT_WEB_UNRELATED_ID_UNIQUE", count_id(pages_reloaded, WEB_UNRELATED_ID) == 1, 1, count_id(pages_reloaded, WEB_UNRELATED_ID), "FIXTURE_RECORD_NOT_CREATED"),
        check("PREFLIGHT_EMAIL_CONTROLLED_ID_UNIQUE", count_id(all_reloaded_messages, EMAIL_ID) == 1, 1, count_id(all_reloaded_messages, EMAIL_ID), "FIXTURE_RECORD_NOT_CREATED"),
        check("PREFLIGHT_EMAIL_UNRELATED_ID_UNIQUE", count_id(all_reloaded_messages, EMAIL_UNRELATED_ID) == 1, 1, count_id(all_reloaded_messages, EMAIL_UNRELATED_ID), "FIXTURE_RECORD_NOT_CREATED"),
    ])

    ToolSuite, import_module_name = import_toolsuite(project_root)
    suite = ToolSuite(isolated_dir, isolate_fs=True)

    post_init_state = getattr(suite, "_state", None)
    state_web = getattr(post_init_state, "web", None)
    state_mail = getattr(post_init_state, "mail", None)
    loaded_web_count = count_id(web_pages_container(state_web), WEB_ID) if state_web is not None else 0
    loaded_mail_folders = email_folders(state_mail) if state_mail is not None else {}
    loaded_messages = [item for values in loaded_mail_folders.values() for item in values if isinstance(item, dict)]
    loaded_email_count = count_id(loaded_messages, EMAIL_ID)
    checks.extend([
        check("PREFLIGHT_WEB_PRESENT_AFTER_TOOLSUITE_INIT", loaded_web_count == 1, 1, loaded_web_count, "FIXTURE_RECORD_NOT_LOADED"),
        check("PREFLIGHT_EMAIL_PRESENT_AFTER_TOOLSUITE_INIT", loaded_email_count == 1, 1, loaded_email_count, "FIXTURE_RECORD_NOT_LOADED"),
    ])

    calls: dict[str, Any] = {}
    def perform(label: str, tool: str, arguments: dict[str, Any]) -> dict[str, Any]:
        result, adapter = invoke_suite(suite, tool, arguments)
        observed_source = extract_last_source(suite)
        record = {"tool": tool, "arguments": arguments, "result": result, "observed_source": observed_source, "adapter": adapter}
        calls[label] = record
        return record

    web_exact = perform("web_exact", "web.open", {"id": WEB_ID})
    web_unrelated = perform("web_unrelated", "web.open", {"id": WEB_UNRELATED_ID})
    web_missing = perform("web_missing", "web.open", {"id": MISSING_WEB_ID})
    email_exact = perform("email_exact", "email.read", {"id": EMAIL_ID})
    email_unrelated = perform("email_unrelated", "email.read", {"id": EMAIL_UNRELATED_ID})
    email_missing = perform("email_missing", "email.read", {"id": MISSING_EMAIL_ID})

    def output_text(call: dict[str, Any]) -> str:
        value = call["result"].get("output", "")
        return value if isinstance(value, str) else json.dumps(json_safe(value), ensure_ascii=False)

    checks.extend([
        check("PREFLIGHT_WEB_EXACT_SUCCEEDS", web_exact["result"]["ok"] is True, True, web_exact["result"]["ok"], "SOURCE_READ_FAILED"),
        check("PREFLIGHT_WEB_MARKER_RETURNED", WEB_MARKER in output_text(web_exact), WEB_MARKER, output_text(web_exact), "SOURCE_MARKER_NOT_RETURNED"),
        check("PREFLIGHT_WEB_SOURCE_TAG", web_exact["observed_source"] == "web", "web", web_exact["observed_source"], "SOURCE_TAG_MISMATCH"),
        check("PREFLIGHT_WEB_UNRELATED_SUCCEEDS", web_unrelated["result"]["ok"] is True, True, web_unrelated["result"]["ok"], "WRONG_SOURCE_RECORD_SELECTED"),
        check("PREFLIGHT_WEB_UNRELATED_HAS_OWN_MARKER", WEB_UNRELATED_MARKER in output_text(web_unrelated) and WEB_MARKER not in output_text(web_unrelated), WEB_UNRELATED_MARKER, output_text(web_unrelated), "WRONG_SOURCE_RECORD_SELECTED"),
        check("PREFLIGHT_WEB_MISSING_FAILS", web_missing["result"]["ok"] is False, False, web_missing["result"]["ok"], "SOURCE_RECORD_NOT_FOUND"),
        check("PREFLIGHT_WEB_MISSING_NOT_FOUND", web_missing["result"].get("error") == "not_found", "not_found", web_missing["result"].get("error"), "SOURCE_RECORD_NOT_FOUND"),
        check("PREFLIGHT_EMAIL_EXACT_SUCCEEDS", email_exact["result"]["ok"] is True, True, email_exact["result"]["ok"], "SOURCE_READ_FAILED"),
        check("PREFLIGHT_EMAIL_MARKER_RETURNED", EMAIL_MARKER in output_text(email_exact), EMAIL_MARKER, output_text(email_exact), "SOURCE_MARKER_NOT_RETURNED"),
        check("PREFLIGHT_EMAIL_SUBJECT_RETURNED", EMAIL_SUBJECT in output_text(email_exact), EMAIL_SUBJECT, output_text(email_exact), "WRONG_SOURCE_RECORD_SELECTED"),
        check("PREFLIGHT_EMAIL_SOURCE_TAG", email_exact["observed_source"] == "email", "email", email_exact["observed_source"], "SOURCE_TAG_MISMATCH"),
        check("PREFLIGHT_EMAIL_UNRELATED_SUCCEEDS", email_unrelated["result"]["ok"] is True, True, email_unrelated["result"]["ok"], "WRONG_SOURCE_RECORD_SELECTED"),
        check("PREFLIGHT_EMAIL_UNRELATED_HAS_OWN_MARKER", EMAIL_UNRELATED_MARKER in output_text(email_unrelated) and EMAIL_MARKER not in output_text(email_unrelated), EMAIL_UNRELATED_MARKER, output_text(email_unrelated), "WRONG_SOURCE_RECORD_SELECTED"),
        check("PREFLIGHT_EMAIL_MISSING_FAILS", email_missing["result"]["ok"] is False, False, email_missing["result"]["ok"], "SOURCE_RECORD_NOT_FOUND"),
        check("PREFLIGHT_EMAIL_MISSING_NOT_FOUND", email_missing["result"].get("error") == "not_found", "not_found", email_missing["result"].get("error"), "SOURCE_RECORD_NOT_FOUND"),
    ])

    packaged_after = {"web": sha256_file(packaged_web), "mail": sha256_file(packaged_mail)}
    checks.extend([
        check("PREFLIGHT_PACKAGED_WEB_UNCHANGED", packaged_after["web"] == packaged_before["web"], packaged_before["web"], packaged_after["web"], "PACKAGED_FIXTURE_MODIFIED"),
        check("PREFLIGHT_PACKAGED_EMAIL_UNCHANGED", packaged_after["mail"] == packaged_before["mail"], packaged_before["mail"], packaged_after["mail"], "PACKAGED_FIXTURE_MODIFIED"),
    ])

    failed = [row for row in checks if not row["passed"]]
    status = "PASS" if not failed else "FAIL"
    classification = "FIXTURE_PREFLIGHT_PASS" if not failed else failed[0]["failure_classification"]

    raw_path = out_dir / "uta_fixture_preflight_v7_30_raw.json"
    csv_path = out_dir / "uta_fixture_preflight_v7_30_summary.csv"
    manifest_path = out_dir / "uta_fixture_preflight_v7_30_freeze_manifest.json"
    script_path = Path(__file__).resolve()

    raw = {
        "schema": "UTA_FIXTURE_PREFLIGHT_V1",
        "phase": {
            "name": VERSION,
            "model": None,
            "agent": None,
            "guardrail": None,
            "predicate_recomputed": False,
            "breach_recomputed": False,
        },
        "generated_utc": datetime.now(timezone.utc).isoformat(),
        "status": status,
        "classification": classification,
        "purpose": [
            "Create isolated fixture copies",
            "Validate fixture schemas",
            "Instantiate ToolSuite against copies",
            "Retrieve exact controlled web and email records",
            "Verify source tags and returned markers",
            "Confirm packaged fixtures remain unchanged",
        ],
        "configuration": {
            "project_root": str(project_root),
            "packaged_fixture_root": str(fixture_root),
            "isolated_fixture_root": str(isolated_dir),
            "toolsuite_import_module": import_module_name,
            "controlled_records": {
                "web": {"id": WEB_ID, "marker": WEB_MARKER, "marker_field": "content"},
                "email": {"id": EMAIL_ID, "marker": EMAIL_MARKER, "marker_field": "body", "subject": EMAIL_SUBJECT, "folder": inbox},
                "unrelated_web": {"id": WEB_UNRELATED_ID, "marker": WEB_UNRELATED_MARKER},
                "unrelated_email": {"id": EMAIL_UNRELATED_ID, "marker": EMAIL_UNRELATED_MARKER},
            },
        },
        "hashes": {
            "packaged_before": packaged_before,
            "packaged_after": packaged_after,
            "isolated_before_control_insertion": isolated_original,
            "isolated_controlled": {"web": sha256_file(isolated_web), "mail": sha256_file(isolated_mail)},
        },
        "calls": calls,
        "checks": checks,
        "summary": {"check_count": len(checks), "passed": len(checks)-len(failed), "failed": len(failed)},
        "interpretation_boundaries": [
            "This phase validates fixture construction, loading, direct tool lookup, result markers, and source tags only.",
            "No agent selected a tool or proposed a downstream action.",
            "No guardrail decision, predicate, breach, Sandbox, Gym, hosted, or production claim is supported.",
            "Marker matching is an experimental transport oracle, not the official UTA predicate.",
        ],
    }
    write_json_new(raw_path, raw)

    with csv_path.open("x", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=["experiment_version","check_id","passed","expected","observed","failure_classification"])
        writer.writeheader()
        for row in checks:
            writer.writerow({
                "experiment_version": VERSION,
                "check_id": row["check_id"],
                "passed": row["passed"],
                "expected": json.dumps(row["expected"], ensure_ascii=False),
                "observed": json.dumps(row["observed"], ensure_ascii=False),
                "failure_classification": row["failure_classification"],
            })

    fixture_files = sorted(p for p in isolated_dir.rglob("*") if p.is_file())
    manifest = {
        "schema": "UTA_FIXTURE_PREFLIGHT_FREEZE_V1",
        "experiment_version": VERSION,
        "created_utc": datetime.now(timezone.utc).isoformat(),
        "inputs": [
            {"relative_path": packaged_web.relative_to(project_root).as_posix(), "size_bytes": packaged_web.stat().st_size, "sha256": packaged_before["web"]},
            {"relative_path": packaged_mail.relative_to(project_root).as_posix(), "size_bytes": packaged_mail.stat().st_size, "sha256": packaged_before["mail"]},
            {"relative_path": script_path.name, "size_bytes": script_path.stat().st_size, "sha256": sha256_file(script_path)},
        ],
        "isolated_fixture_outputs": [
            {"relative_path": p.relative_to(out_dir).as_posix(), "size_bytes": p.stat().st_size, "sha256": sha256_file(p)} for p in fixture_files
        ],
        "outputs": [
            {"file_name": raw_path.name, "size_bytes": raw_path.stat().st_size, "sha256": sha256_file(raw_path)},
            {"file_name": csv_path.name, "size_bytes": csv_path.stat().st_size, "sha256": sha256_file(csv_path)},
        ],
        "runtime": {"python": sys.version, "platform": platform.platform(), "model": None, "agent": None, "guardrail": None},
        "result": raw["summary"] | {"status": status, "classification": classification},
        "limitations": raw["interpretation_boundaries"],
    }
    write_json_new(manifest_path, manifest)

    print(f"Experiment: {VERSION}")
    print(f"Status: {status}")
    print(f"Classification: {classification}")
    print(f"Checks: {len(checks)}")
    print(f"Passed: {len(checks)-len(failed)}")
    print(f"Failed: {len(failed)}")
    for row in failed:
        print(f"  FAILED {row['check_id']}: {row['failure_classification']}")
    print(f"Raw JSON: {raw_path}")
    print(f"CSV summary: {csv_path}")
    print(f"Freeze manifest: {manifest_path}")
    print(f"Freeze manifest SHA256: {sha256_file(manifest_path)}")
    return 0 if not failed else 2


if __name__ == "__main__":
    raise SystemExit(main())
