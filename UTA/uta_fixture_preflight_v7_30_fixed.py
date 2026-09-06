#!/usr/bin/env python3
"""UTA model-free isolated fixture preflight v7.30, corrected build.

Corrections versus the original v7.30:
- Imports ToolSuite only from aicomp_sdk.core.tools.suite first.
- Discovers and records the actual ToolSuite constructor signature.
- Tries only constructor forms compatible with common SDK revisions.
- Uses the public ToolSuite.call(tool_name, **arguments) shape first, while
  retaining narrow fallbacks for source-tree revisions.
- Resolves state from state or _state without assuming one property name.
- Writes a diagnostic JSON if construction or invocation fails.

No model, agent, guardrail, predicate, Sandbox, Gym, or fixture-transport claim
outside the direct ToolSuite preflight is used.
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import importlib
import inspect
import json
import os
import platform
import shutil
import sys
import traceback
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

VERSION = "UTA_FIXTURE_PREFLIGHT_v7.30_FIXED"
WEB_ID = "UTA_WEB_V730_001"
WEB_MARKER = "UTA_WEB_MARKER_V730_7F3C91"
WEB_OTHER_ID = "UTA_WEB_UNRELATED_V730_001"
WEB_OTHER_MARKER = "UTA_WEB_UNRELATED_MARKER_V730_91BE20"
EMAIL_ID = "UTA_EMAIL_V730_001"
EMAIL_MARKER = "UTA_EMAIL_MARKER_V730_2A8D64"
EMAIL_SUBJECT = "UTA_EMAIL_SUBJECT_V730"
EMAIL_OTHER_ID = "UTA_EMAIL_UNRELATED_V730_001"
EMAIL_OTHER_MARKER = "UTA_EMAIL_UNRELATED_MARKER_V730_C45A72"
WEB_MISSING_ID = "UTA_WEB_MISSING_V730_404"
EMAIL_MISSING_ID = "UTA_EMAIL_MISSING_V730_404"


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for block in iter(lambda: f.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest().upper()


def safe(v: Any) -> Any:
    if v is None or isinstance(v, (str, int, float, bool)):
        return v
    if isinstance(v, Path):
        return str(v)
    if isinstance(v, dict):
        return {str(k): safe(x) for k, x in v.items()}
    if isinstance(v, (list, tuple)):
        return [safe(x) for x in v]
    if isinstance(v, (set, frozenset)):
        values = [safe(x) for x in v]
        return sorted(values, key=lambda x: json.dumps(x, sort_keys=True, ensure_ascii=False))
    if hasattr(v, "__dict__"):
        return safe(vars(v))
    return repr(v)


def atomic_write(path: Path, content: str) -> None:
    if path.exists():
        raise FileExistsError(f"Refusing to overwrite existing artifact: {path}")
    temp = path.with_name(path.name + ".tmp")
    temp.write_text(content, encoding="utf-8", newline="\n")
    os.replace(temp, path)


def write_json(path: Path, value: Any) -> None:
    atomic_write(path, json.dumps(safe(value), indent=2, ensure_ascii=False) + "\n")


def load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def pages_of(web: Any) -> list[dict[str, Any]]:
    if isinstance(web, dict) and isinstance(web.get("pages"), list):
        return web["pages"]
    if isinstance(web, list):
        return web
    raise ValueError("web_corpus.json must be a top-level array or object with a pages array")


def folders_of(mail: Any) -> dict[str, list[dict[str, Any]]]:
    if not isinstance(mail, dict):
        raise ValueError("mail_seed.json must be an object")
    folders = {str(k): v for k, v in mail.items() if isinstance(v, list)}
    if not folders:
        raise ValueError("mail_seed.json has no list-valued folder")
    return folders


def inbox_name(folders: dict[str, list[dict[str, Any]]]) -> str:
    for name in ("inbox", "Inbox", "INBOX"):
        if name in folders:
            return name
    return sorted(folders)[0]


def count_id(records: list[dict[str, Any]], value: str) -> int:
    return sum(isinstance(row, dict) and row.get("id") == value for row in records)


def flattened_messages(mail: Any) -> list[dict[str, Any]]:
    return [row for rows in folders_of(mail).values() for row in rows if isinstance(row, dict)]


def import_toolsuite(project_root: Path) -> tuple[type, str, list[dict[str, str]]]:
    if str(project_root) not in sys.path:
        sys.path.insert(0, str(project_root))
    diagnostics: list[dict[str, str]] = []
    # Direct implementation module first to avoid ambiguous re-exports.
    for module_name in ("aicomp_sdk.core.tools.suite", "aicomp_sdk.core.tools"):
        try:
            module = importlib.import_module(module_name)
            candidate = getattr(module, "ToolSuite", None)
            if inspect.isclass(candidate):
                return candidate, module_name, diagnostics
            diagnostics.append({"module": module_name, "error": "ToolSuite class not exported"})
        except Exception as exc:
            diagnostics.append({"module": module_name, "error": repr(exc)})
    raise RuntimeError("ToolSuite import failed: " + json.dumps(diagnostics, ensure_ascii=False))


def construct_toolsuite(cls: type, fixtures_dir: Path) -> tuple[Any, dict[str, Any]]:
    signature = inspect.signature(cls)
    attempts: list[dict[str, Any]] = []
    forms = [
        ("positional_with_isolate_fs", lambda: cls(fixtures_dir, isolate_fs=True)),
        ("keyword_fixtures_dir_with_isolate_fs", lambda: cls(fixtures_dir=fixtures_dir, isolate_fs=True)),
        ("positional_only", lambda: cls(fixtures_dir)),
        ("keyword_fixtures_dir_only", lambda: cls(fixtures_dir=fixtures_dir)),
    ]
    for label, callback in forms:
        try:
            suite = callback()
            return suite, {
                "class": f"{cls.__module__}.{cls.__qualname__}",
                "signature": str(signature),
                "successful_form": label,
                "prior_type_errors": attempts,
            }
        except TypeError as exc:
            attempts.append({"form": label, "type_error": str(exc)})
    raise RuntimeError(
        "No ToolSuite constructor form matched. Signature=" + str(signature) +
        "; attempts=" + json.dumps(attempts, ensure_ascii=False)
    )


def normalize_result(result: Any) -> dict[str, Any]:
    if isinstance(result, tuple) and len(result) >= 3:
        return {"ok": bool(result[0]), "output": result[1], "error": result[2], "raw": safe(result)}
    if isinstance(result, dict):
        return {
            "ok": bool(result.get("ok", result.get("success", False))),
            "output": result.get("output", result.get("result", "")),
            "error": result.get("error"),
            "raw": safe(result),
        }
    return {
        "ok": bool(getattr(result, "ok", getattr(result, "success", False))),
        "output": getattr(result, "output", getattr(result, "result", "")),
        "error": getattr(result, "error", None),
        "raw": safe(result),
    }


def call_tool(suite: Any, tool_name: str, arguments: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
    attempts: list[dict[str, str]] = []
    candidates: list[tuple[str, Any]] = []
    for method_name in ("call", "execute", "invoke", "run", "call_tool", "execute_tool"):
        method = getattr(suite, method_name, None)
        if callable(method):
            candidates.append((method_name, method))
    if not candidates:
        raise RuntimeError("ToolSuite exposes no recognized call method")

    for method_name, method in candidates:
        call_forms = [
            ("tool_name_kwargs", lambda m=method: m(tool_name, **arguments)),
            ("tool_name_dict", lambda m=method: m(tool_name, arguments)),
            ("keywords_tool_args", lambda m=method: m(tool_name=tool_name, tool_args=arguments)),
            ("keywords_name_arguments", lambda m=method: m(name=tool_name, arguments=arguments)),
        ]
        for form, callback in call_forms:
            try:
                result = callback()
                return normalize_result(result), {
                    "method": method_name,
                    "signature": str(inspect.signature(method)),
                    "successful_form": form,
                    "prior_type_errors": attempts,
                }
            except TypeError as exc:
                attempts.append({"method": method_name, "form": form, "error": str(exc)})
    raise RuntimeError("No ToolSuite call signature matched: " + json.dumps(attempts, ensure_ascii=False))


def state_of(suite: Any) -> Any:
    for name in ("state", "_state", "runtime_state", "_runtime_state"):
        value = getattr(suite, name, None)
        if value is not None:
            return value
    return None


def state_member(state: Any, name: str) -> Any:
    if state is None:
        return None
    if isinstance(state, dict):
        return state.get(name)
    return getattr(state, name, None)


def last_source_of(suite: Any) -> str | None:
    direct = getattr(suite, "last_source", None)
    if isinstance(direct, str):
        return direct
    value = state_member(state_of(suite), "last_source")
    return value if isinstance(value, str) else None


def output_text(call_record: dict[str, Any]) -> str:
    value = call_record["result"].get("output", "")
    return value if isinstance(value, str) else json.dumps(safe(value), ensure_ascii=False)


def make_check(check_id: str, passed: bool, expected: Any, observed: Any, failure: str) -> dict[str, Any]:
    return {
        "check_id": check_id,
        "passed": bool(passed),
        "expected": safe(expected),
        "observed": safe(observed),
        "failure_classification": "" if passed else failure,
    }


def write_failure_diagnostic(out_dir: Path, stage: str, exc: BaseException, context: dict[str, Any]) -> None:
    path = out_dir / "uta_fixture_preflight_v7_30_failure_diagnostic.json"
    payload = {
        "experiment_version": VERSION,
        "status": "SCRIPT_OR_ENVIRONMENT_FAILURE",
        "stage": stage,
        "exception_type": type(exc).__name__,
        "exception": str(exc),
        "traceback": traceback.format_exc(),
        "context": context,
        "scientific_result": None,
    }
    if not path.exists():
        write_json(path, payload)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--project-root", required=True, type=Path)
    parser.add_argument("--out-dir", required=True, type=Path)
    args = parser.parse_args()

    root = args.project_root.expanduser().resolve()
    out = args.out_dir.expanduser().resolve()
    fixtures = root / "aicomp_sdk" / "fixtures"
    packaged_web = fixtures / "web_corpus.json"
    packaged_mail = fixtures / "mail_seed.json"

    if not root.is_dir():
        raise SystemExit(f"Project root not found: {root}")
    if not packaged_web.is_file() or not packaged_mail.is_file():
        raise SystemExit(f"Required packaged fixtures not found: {fixtures}")
    if out.exists():
        raise SystemExit(f"Refusing to use existing output directory: {out}")
    out.mkdir(parents=True, exist_ok=False)

    stage = "INITIALIZE"
    context: dict[str, Any] = {"project_root": str(root), "fixture_root": str(fixtures)}
    try:
        stage = "HASH_PACKAGED_FIXTURES"
        before = {"web": sha256(packaged_web), "mail": sha256(packaged_mail)}

        stage = "COPY_FIXTURES"
        isolated = out / "isolated_fixtures"
        shutil.copytree(fixtures, isolated)
        iso_web = isolated / "web_corpus.json"
        iso_mail = isolated / "mail_seed.json"
        copied = {"web": sha256(iso_web), "mail": sha256(iso_mail)}

        checks: list[dict[str, Any]] = [
            make_check("COPY_WEB_IDENTICAL", copied["web"] == before["web"], before["web"], copied["web"], "FIXTURE_COPY_FAILED"),
            make_check("COPY_EMAIL_IDENTICAL", copied["mail"] == before["mail"], before["mail"], copied["mail"], "FIXTURE_COPY_FAILED"),
        ]

        stage = "VALIDATE_AND_INSERT_CONTROLLED_RECORDS"
        web = load_json(iso_web)
        mail = load_json(iso_mail)
        pages = pages_of(web)
        folders = folders_of(mail)
        inbox = inbox_name(folders)
        messages = flattened_messages(mail)

        ids = [(pages, WEB_ID), (pages, WEB_OTHER_ID), (messages, EMAIL_ID), (messages, EMAIL_OTHER_ID)]
        for records, record_id in ids:
            count = count_id(records, record_id)
            checks.append(make_check(f"ID_ABSENT_{record_id}", count == 0, 0, count, "DUPLICATE_CONTROLLED_ID"))
        serialized = json.dumps({"web": web, "mail": mail}, ensure_ascii=False)
        for marker in (WEB_MARKER, WEB_OTHER_MARKER, EMAIL_MARKER, EMAIL_OTHER_MARKER):
            count = serialized.count(marker)
            checks.append(make_check(f"MARKER_ABSENT_{marker}", count == 0, 0, count, "CONTROLLED_MARKER_PREEXISTED"))
        if any(not row["passed"] for row in checks):
            raise RuntimeError("Pre-existing controlled ID or marker detected")

        pages.extend([
            {"id": WEB_ID, "title": "UTA Controlled Web v7.30", "content": f"Controlled {WEB_MARKER}"},
            {"id": WEB_OTHER_ID, "title": "UTA Unrelated Web v7.30", "content": f"Unrelated {WEB_OTHER_MARKER}"},
        ])
        folders[inbox].extend([
            {"id": EMAIL_ID, "from": "uta-controlled@example.invalid", "subject": EMAIL_SUBJECT, "body": f"Controlled {EMAIL_MARKER}"},
            {"id": EMAIL_OTHER_ID, "from": "uta-unrelated@example.invalid", "subject": "UTA_EMAIL_UNRELATED_SUBJECT_V730", "body": f"Unrelated {EMAIL_OTHER_MARKER}"},
        ])
        temp_web = iso_web.with_name(iso_web.name + ".new")
        temp_mail = iso_mail.with_name(iso_mail.name + ".new")
        write_json(temp_web, web)
        write_json(temp_mail, mail)
        os.replace(temp_web, iso_web)
        os.replace(temp_mail, iso_mail)

        stage = "IMPORT_TOOLSUITE"
        ToolSuite, imported_from, import_diagnostics = import_toolsuite(root)
        context["toolsuite_imported_from"] = imported_from
        context["toolsuite_import_diagnostics"] = import_diagnostics

        stage = "CONSTRUCT_TOOLSUITE"
        suite, constructor = construct_toolsuite(ToolSuite, isolated)
        context["toolsuite_constructor"] = constructor

        stage = "VERIFY_LOADED_STATE"
        state = state_of(suite)
        loaded_web = state_member(state, "web")
        loaded_mail = state_member(state, "mail")
        loaded_web_count = count_id(pages_of(loaded_web), WEB_ID) if loaded_web is not None else 0
        loaded_email_count = count_id(flattened_messages(loaded_mail), EMAIL_ID) if loaded_mail is not None else 0
        checks.extend([
            make_check("WEB_PRESENT_AFTER_INIT", loaded_web_count == 1, 1, loaded_web_count, "FIXTURE_RECORD_NOT_LOADED"),
            make_check("EMAIL_PRESENT_AFTER_INIT", loaded_email_count == 1, 1, loaded_email_count, "FIXTURE_RECORD_NOT_LOADED"),
        ])

        stage = "CALL_TOOLS"
        calls: dict[str, Any] = {}
        def perform(label: str, name: str, arguments: dict[str, Any]) -> dict[str, Any]:
            result, adapter = call_tool(suite, name, arguments)
            record = {"tool": name, "arguments": arguments, "result": result, "source": last_source_of(suite), "adapter": adapter}
            calls[label] = record
            return record

        web_exact = perform("web_exact", "web.open", {"id": WEB_ID})
        web_other = perform("web_unrelated", "web.open", {"id": WEB_OTHER_ID})
        web_missing = perform("web_missing", "web.open", {"id": WEB_MISSING_ID})
        email_exact = perform("email_exact", "email.read", {"id": EMAIL_ID})
        email_other = perform("email_unrelated", "email.read", {"id": EMAIL_OTHER_ID})
        email_missing = perform("email_missing", "email.read", {"id": EMAIL_MISSING_ID})

        stage = "EVALUATE_GATES"
        checks.extend([
            make_check("WEB_EXACT_SUCCEEDS", web_exact["result"]["ok"] is True, True, web_exact["result"]["ok"], "SOURCE_READ_FAILED"),
            make_check("WEB_MARKER_RETURNED", WEB_MARKER in output_text(web_exact), WEB_MARKER, output_text(web_exact), "SOURCE_MARKER_NOT_RETURNED"),
            make_check("WEB_SOURCE_TAG", web_exact["source"] == "web", "web", web_exact["source"], "SOURCE_TAG_MISMATCH"),
            make_check("WEB_OTHER_OWN_MARKER", web_other["result"]["ok"] and WEB_OTHER_MARKER in output_text(web_other) and WEB_MARKER not in output_text(web_other), WEB_OTHER_MARKER, output_text(web_other), "WRONG_SOURCE_RECORD_SELECTED"),
            make_check("WEB_MISSING_FAILS", web_missing["result"]["ok"] is False, False, web_missing["result"]["ok"], "SOURCE_RECORD_NOT_FOUND"),
            make_check("WEB_MISSING_NOT_FOUND", web_missing["result"]["error"] == "not_found", "not_found", web_missing["result"]["error"], "SOURCE_RECORD_NOT_FOUND"),
            make_check("EMAIL_EXACT_SUCCEEDS", email_exact["result"]["ok"] is True, True, email_exact["result"]["ok"], "SOURCE_READ_FAILED"),
            make_check("EMAIL_MARKER_RETURNED", EMAIL_MARKER in output_text(email_exact), EMAIL_MARKER, output_text(email_exact), "SOURCE_MARKER_NOT_RETURNED"),
            make_check("EMAIL_SUBJECT_RETURNED", EMAIL_SUBJECT in output_text(email_exact), EMAIL_SUBJECT, output_text(email_exact), "WRONG_SOURCE_RECORD_SELECTED"),
            make_check("EMAIL_SOURCE_TAG", email_exact["source"] == "email", "email", email_exact["source"], "SOURCE_TAG_MISMATCH"),
            make_check("EMAIL_OTHER_OWN_MARKER", email_other["result"]["ok"] and EMAIL_OTHER_MARKER in output_text(email_other) and EMAIL_MARKER not in output_text(email_other), EMAIL_OTHER_MARKER, output_text(email_other), "WRONG_SOURCE_RECORD_SELECTED"),
            make_check("EMAIL_MISSING_FAILS", email_missing["result"]["ok"] is False, False, email_missing["result"]["ok"], "SOURCE_RECORD_NOT_FOUND"),
            make_check("EMAIL_MISSING_NOT_FOUND", email_missing["result"]["error"] == "not_found", "not_found", email_missing["result"]["error"], "SOURCE_RECORD_NOT_FOUND"),
        ])

        stage = "VERIFY_PACKAGED_FIXTURES_UNCHANGED"
        after = {"web": sha256(packaged_web), "mail": sha256(packaged_mail)}
        checks.extend([
            make_check("PACKAGED_WEB_UNCHANGED", after["web"] == before["web"], before["web"], after["web"], "PACKAGED_FIXTURE_MODIFIED"),
            make_check("PACKAGED_EMAIL_UNCHANGED", after["mail"] == before["mail"], before["mail"], after["mail"], "PACKAGED_FIXTURE_MODIFIED"),
        ])

        failed = [row for row in checks if not row["passed"]]
        status = "PASS" if not failed else "FAIL"
        classification = "FIXTURE_PREFLIGHT_PASS" if not failed else failed[0]["failure_classification"]

        raw_path = out / "uta_fixture_preflight_v7_30_raw.json"
        csv_path = out / "uta_fixture_preflight_v7_30_summary.csv"
        manifest_path = out / "uta_fixture_preflight_v7_30_freeze_manifest.json"
        raw = {
            "schema": "UTA_FIXTURE_PREFLIGHT_V1",
            "experiment_version": VERSION,
            "generated_utc": datetime.now(timezone.utc).isoformat(),
            "status": status,
            "classification": classification,
            "phase": {"model": None, "agent": None, "guardrail": None, "predicate_recomputed": False, "breach_recomputed": False},
            "configuration": {
                "project_root": str(root), "packaged_fixture_root": str(fixtures), "isolated_fixture_root": str(isolated),
                "toolsuite_imported_from": imported_from, "toolsuite_constructor": constructor, "email_folder": inbox,
            },
            "hashes": {"packaged_before": before, "packaged_after": after, "copied_before_insertion": copied,
                       "controlled_isolated": {"web": sha256(iso_web), "mail": sha256(iso_mail)}},
            "calls": calls,
            "checks": checks,
            "summary": {"check_count": len(checks), "passed": len(checks)-len(failed), "failed": len(failed)},
            "interpretation_boundaries": [
                "Fixture loading and direct ToolSuite transport only.",
                "No model, agent, guardrail, predicate, breach, Sandbox, Gym, hosted, or production claim.",
                "Marker matching is an experimental transport oracle, not the official UTA predicate.",
            ],
        }
        write_json(raw_path, raw)

        with csv_path.open("x", encoding="utf-8", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=["experiment_version", "check_id", "passed", "expected", "observed", "failure_classification"])
            writer.writeheader()
            for row in checks:
                writer.writerow({"experiment_version": VERSION, "check_id": row["check_id"], "passed": row["passed"],
                                 "expected": json.dumps(row["expected"], ensure_ascii=False),
                                 "observed": json.dumps(row["observed"], ensure_ascii=False),
                                 "failure_classification": row["failure_classification"]})

        fixture_files = sorted(p for p in isolated.rglob("*") if p.is_file())
        script = Path(__file__).resolve()
        manifest = {
            "schema": "UTA_FIXTURE_PREFLIGHT_FREEZE_V1",
            "experiment_version": VERSION,
            "created_utc": datetime.now(timezone.utc).isoformat(),
            "inputs": [
                {"relative_path": packaged_web.relative_to(root).as_posix(), "size_bytes": packaged_web.stat().st_size, "sha256": before["web"]},
                {"relative_path": packaged_mail.relative_to(root).as_posix(), "size_bytes": packaged_mail.stat().st_size, "sha256": before["mail"]},
                {"relative_path": script.name, "size_bytes": script.stat().st_size, "sha256": sha256(script)},
            ],
            "isolated_fixture_outputs": [
                {"relative_path": p.relative_to(out).as_posix(), "size_bytes": p.stat().st_size, "sha256": sha256(p)} for p in fixture_files
            ],
            "outputs": [
                {"file_name": raw_path.name, "size_bytes": raw_path.stat().st_size, "sha256": sha256(raw_path)},
                {"file_name": csv_path.name, "size_bytes": csv_path.stat().st_size, "sha256": sha256(csv_path)},
            ],
            "runtime": {"python": sys.version, "platform": platform.platform(), "model": None, "agent": None, "guardrail": None},
            "result": {"status": status, "classification": classification, **raw["summary"]},
            "limitations": raw["interpretation_boundaries"],
        }
        write_json(manifest_path, manifest)

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
        print(f"Freeze manifest SHA256: {sha256(manifest_path)}")
        return 0 if not failed else 2

    except Exception as exc:
        context["failed_stage"] = stage
        write_failure_diagnostic(out, stage, exc, context)
        print(f"Preflight failed at stage: {stage}", file=sys.stderr)
        print(f"{type(exc).__name__}: {exc}", file=sys.stderr)
        print(f"Diagnostic: {out / 'uta_fixture_preflight_v7_30_failure_diagnostic.json'}", file=sys.stderr)
        return 3


if __name__ == "__main__":
    raise SystemExit(main())
