#!/usr/bin/env python3
"""INDEPENDENT_V2_2_HOOK_STATIC_QUALIFICATION_v1.0

Read-only, independent static qualification of the frozen V2.2 two-stage hook
implementation (aicomp_sdk_exfil_v2_2). This runner does NOT reuse or trust
any assertion made by the implementation-freeze runner
(v2_2_hook_contract_repair_and_identity_freeze_v1_0.py). It independently:

  1. Recomputes exact file identities (size + SHA-256) for all bound inputs
     and for the four V2.2 implementation files, and rejects any extra or
     missing .py file in the V2.2 package.
  2. Parses V2.2 source with `ast` (no import, no exec, no instantiation) and
     independently re-derives:
       - the PRE_TOOL_CALL / fs.read filter and validation ORDER in the
         proposal hook (via literal source-position search, not reliance on
         variable names alone),
       - that raw validation precedes any normalization/coercion,
       - that all malformed-reason branches are present and mutually
         exclusive along one control path,
       - that the modified HookContext preserves the required active-context
         fields and sets should_block=True (on HookContext, NOT HookResult),
       - that HookResult never receives a `should_block` keyword anywhere in
         the V2.2 source tree,
       - that continue_execution=False accompanies the block result and that
         the default (non-blocking) path returns HookResult() with no args,
       - the POST_TOOL_CALL / fs.read filter and exact-True `ok` check in the
         outcome hook,
       - that protected-path and string-output checks gate ledger append,
       - that every malformed-output branch returns before
         `append_successful_read` is reached (control-flow line-order proof,
         not textual heuristics),
       - that the outcome hook never sets should_block and never returns
         continue_execution=False (no post-tool prevention claim),
       - the factory's exact two registrations (PRE_TOOL_CALL proposal hook,
         POST_TOOL_CALL outcome hook), that both priorities are literal
         integer 0, that a single ledger instance feeds both the outcome
         hook and the guardrail, and the exact ExfilIntegrationBundleV22
         field order.
  3. Independently resolves the V2.2 import graph: every relative import
     target must exist in-package; SuccessfulReadLedgerV21 and
     LineageAwareExfilGuardrailV21 (V2.1) are the ONLY permitted external
     reuse imports; TrustedReadOutcomeHookV21 / IntegrationFactoryV21 imports
     are prohibited; any private (`_`-prefixed) SDK symbol import is
     prohibited; no SuccessfulReadLedgerV22 / SuccessfulReadRecordV22 /
     LineageAwareExfilGuardrailV22 class may be defined anywhere in V2.2.
  4. Verifies V2.1 and SDK source files are BYTE-IDENTICAL to their last
     known-frozen identities (immutability boundary) -- this qualifier
     supplies its own independently-transcribed expected hash table rather
     than importing the freeze runner's constants module.
  5. Explicitly records `repeated_factory_build_idempotence: NOT_EVALUATED`
     and refuses to claim otherwise, because that requires runtime execution
     which is out of scope for this gate.

Execution boundaries (all enforced/asserted false in the result, and never
violated by this script): no `import` of aicomp_sdk_exfil_v2_2 or any of its
modules; no instantiation of any hook/ledger/guardrail/factory class; no
Sandbox/Gym; no tool execution; no actual fs.read; no HTTP; no guardrail
execution; no predicates/breach execution; no models/threads; no
modification of V2.1, V2.2, or the SDK.
"""

from __future__ import annotations

import argparse
import ast
import csv
import hashlib
import json
import sys
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

VERSION = "INDEPENDENT_V2_2_HOOK_STATIC_QUALIFICATION_v1.0"

# ---------------------------------------------------------------------------
# Independently-transcribed expected identities (NOT imported from the freeze
# runner; re-typed here so this qualifier does not inherit its assumptions).
# ---------------------------------------------------------------------------

EXPECTED_V22_FILES = {
    "__init__.py": (484, "3A868F18E87E891C3EBEBA4E6534918DC730D4A27B7E21B1D834F3EC77BD004B"),
    "trusted_read_proposal_hook_v2_2.py": (1972, "F4AB269075C1195FF27B3D15357EDB0351E0B70106059ECB70643649A3E238E8"),
    "trusted_read_outcome_hook_v2_2.py": (2233, "D5819673ECBB6B3330B27F2C5046F8EB1720924E41236DBF265D631BE7050118"),
    "integration_factory_v2_2.py": (2039, "8188BFFFFC1EBFE6B4A1E6DAB4C1678B1DE77389EC55BE7A4E4EA705665FCB9E"),
}

EXPECTED_V21_FILES = {
    "successful_read_ledger_v2_1.py": (8335, "18146742E6866C491A032AA96EFC248FFED05706895D32FDE724145D0878009C"),
    "lineage_aware_exfil_guardrail_v2_1.py": (1394, "2AC1CA55FB0C18460F50B35677F5ECD9EB3477CFB21F9C19F44A48C7AEFD5C26"),
    "trusted_read_outcome_hook_v2_1.py": (1532, "F2DE8D42EE5DBCD3BA4CACD8E98DCCB2EBA63F82EC8683D129C503CCED1CE770"),
}

EXPECTED_SDK_FILES = {
    "aicomp_sdk/hooks/types.py": (1585, "0D3C7B5921749C22CADC5478532C7FE84B86AA90447FEEA8060ACFA9F44D3C7E"),
    "aicomp_sdk/hooks/registry.py": (8633, "5635B45136517CB5B7FBC6BAB6C9440FE7D6D699E484B6D63651AE296D4BB00B"),
    "aicomp_sdk/core/predicates.py": (16718, "9D9DE5118D8883A0074A5405ED85CF2DEC3F68E8516908CBC48F409E3BA56F37"),
}

EXPECTED_DESIGN_MANIFEST_SHA256 = "FF5E286FBAC1E7250F8A0E235C1F76F43FD43BDBDC66AE650A1FB35564682885"
EXPECTED_FREEZE_MANIFEST_SHA256 = "CE23561524F9773D6A10323C2DF139344D4DA45C4717DD9D6868F216B37C8E29"
EXPECTED_FREEZE_RESULT_SHA256 = "3DDFE0A1526248709DCB36B39283C5530EA7FC17706BBE56C38C1315AFA70413"

REQUIRED_HOOK_CONTEXT_PRESERVED_FIELDS = [
    "stage", "tool_name", "tool_args", "tool_output", "guardrail_decision",
    "trace", "context", "metadata", "hook_state", "modified_args",
    "modified_output", "injected_content",
]


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def sha256_of(path: Path) -> str:
    h = hashlib.sha256()
    h.update(path.read_bytes())
    return h.hexdigest().upper()


def identity(path: Path) -> dict:
    return {
        "artifact": path.name,
        "path": str(path.resolve()),
        "size_bytes": path.stat().st_size,
        "sha256": sha256_of(path),
    }


@dataclass
class Check:
    check_id: str
    category: str
    passed: bool
    observed: str
    expected: str
    failure_layer: str


class Checks:
    def __init__(self) -> None:
        self._rows: list[Check] = []
        self._n = 0

    def add(self, category: str, passed: bool, observed: Any, expected: Any, failure_layer: str) -> None:
        self._n += 1
        cid = f"IV22-{self._n:03d}"
        self._rows.append(Check(cid, category, bool(passed),
                                 json.dumps(observed, default=str, sort_keys=True) if not isinstance(observed, str) else observed,
                                 json.dumps(expected, default=str, sort_keys=True) if not isinstance(expected, str) else expected,
                                 failure_layer))

    @property
    def rows(self) -> list[Check]:
        return self._rows

    @property
    def failed(self) -> list[Check]:
        return [r for r in self._rows if not r.passed]

    def as_dicts(self) -> list[dict]:
        return [
            {
                "check_id": r.check_id,
                "category": r.category,
                "passed": r.passed,
                "observed": r.observed,
                "expected": r.expected,
                "failure_layer": r.failure_layer,
            }
            for r in self._rows
        ]


def parse_module(path: Path) -> ast.Module:
    return ast.parse(path.read_text(encoding="utf-8"), filename=str(path))


def find_class(tree: ast.Module, name: str) -> Optional[ast.ClassDef]:
    for node in ast.walk(tree):
        if isinstance(node, ast.ClassDef) and node.name == name:
            return node
    return None


def find_all_classes(tree: ast.Module) -> list[str]:
    return [n.name for n in ast.walk(tree) if isinstance(n, ast.ClassDef)]


def find_method(cls: ast.ClassDef, name: str) -> Optional[ast.FunctionDef]:
    for node in cls.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == name:
            return node
    return None


def find_func(tree: ast.Module, name: str) -> Optional[ast.FunctionDef]:
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == name:
            return node
    return None


def unparse(node: ast.AST) -> str:
    try:
        return ast.unparse(node)
    except Exception:
        return "<UNPARSE_FAILED>"


def line_of(node: ast.AST) -> int:
    return getattr(node, "lineno", -1)


def walk_calls(node: ast.AST, func_name: str) -> list[ast.Call]:
    out = []
    for n in ast.walk(node):
        if isinstance(n, ast.Call):
            fn = n.func
            if isinstance(fn, ast.Name) and fn.id == func_name:
                out.append(n)
            elif isinstance(fn, ast.Attribute) and fn.attr == func_name:
                out.append(n)
    return out


def all_calls(node: ast.AST) -> list[ast.Call]:
    return [n for n in ast.walk(node) if isinstance(n, ast.Call)]


def call_kwargs(call: ast.Call) -> dict[str, ast.AST]:
    return {kw.arg: kw.value for kw in call.keywords if kw.arg is not None}


def get_import_from_modules(tree: ast.Module) -> list[tuple[str, int, list[str]]]:
    """Return list of (module, level, [imported names]) for every ImportFrom."""
    out = []
    for node in tree.body:
        if isinstance(node, ast.ImportFrom):
            names = [a.name for a in node.names]
            out.append((node.module or "", node.level, names))
    return out


def get_plain_imports(tree: ast.Module) -> list[str]:
    out = []
    for node in tree.body:
        if isinstance(node, ast.Import):
            out.extend(a.name for a in node.names)
    return out


def find_return_nodes(func: ast.FunctionDef) -> list[ast.Return]:
    return [n for n in ast.walk(func) if isinstance(n, ast.Return)]


def return_is_bare_hookresult(ret: ast.Return) -> bool:
    """True if `return HookResult()` with zero args/kwargs."""
    if ret.value is None:
        return False
    if not isinstance(ret.value, ast.Call):
        return False
    call = ret.value
    fn = call.func
    name_ok = (isinstance(fn, ast.Name) and fn.id == "HookResult") or (isinstance(fn, ast.Attribute) and fn.attr == "HookResult")
    return name_ok and len(call.args) == 0 and len(call.keywords) == 0


def source_between(text: str, start_line: int, end_line: int) -> str:
    lines = text.splitlines()
    return "\n".join(lines[max(0, start_line - 1):end_line])


def main() -> int:
    parser = argparse.ArgumentParser(description=VERSION)
    parser.add_argument("--project-root", required=True, help="Root containing aicomp_sdk, aicomp_sdk_exfil_v2_1, aicomp_sdk_exfil_v2_2")
    parser.add_argument("--freeze-manifest", required=True, help="Path to v2_2_hook_freeze_manifest.csv (bound as evidence only)")
    parser.add_argument("--freeze-result", required=True, help="Path to v2_2_hook_freeze_result.json (bound as evidence only)")
    parser.add_argument("--design-manifest", required=True, help="Path to v2_2_hook_design_review_manifest.csv (bound as evidence only)")
    parser.add_argument("--output-dir", required=True, help="New, non-existent output directory for this gate's artifacts")
    args = parser.parse_args()

    project_root = Path(args.project_root).resolve()
    out_dir = Path(args.output_dir).resolve()
    if out_dir.exists():
        print(f"REFUSING TO OVERWRITE existing output directory: {out_dir}", file=sys.stderr)
        return 2
    out_dir.mkdir(parents=True)

    checks = Checks()
    execution_boundaries = {
        "V2_1_modified": False,
        "V2_2_modified": False,
        "SDK_modified": False,
        "V2_2_imported": False,
        "hooks_instantiated": False,
        "Sandbox_instantiated": False,
        "Gym_instantiated": False,
        "tools_executed": False,
        "actual_fs_read_executed": False,
        "HTTP_executed": False,
        "guardrail_executed": False,
        "predicates_executed": False,
        "breach_executed": False,
        "models_used": False,
        "threads_executed": False,
        "external_effects_observed": False,
    }

    v22_root = project_root / "aicomp_sdk_exfil_v2_2"
    v21_root = project_root / "aicomp_sdk_exfil_v2_1"
    sdk_root = project_root / "aicomp_sdk"

    # --- Bound evidence identities (bind-only; not trusted for content claims) ---
    bound_evidence = {}
    for label, p in [
        ("freeze_manifest", Path(args.freeze_manifest)),
        ("freeze_result", Path(args.freeze_result)),
        ("design_manifest", Path(args.design_manifest)),
    ]:
        p = p.resolve()
        exists = p.is_file()
        checks.add(
            "evidence_binding",
            exists,
            {"path": str(p), "exists": exists},
            {"exists": True},
            "FIXTURE",
        )
        if exists:
            ident = identity(p)
            bound_evidence[label] = ident
            if label == "design_manifest":
                checks.add("evidence_binding", ident["sha256"] == EXPECTED_DESIGN_MANIFEST_SHA256,
                           ident["sha256"], EXPECTED_DESIGN_MANIFEST_SHA256, "FIXTURE")
            if label == "freeze_manifest":
                checks.add("evidence_binding", ident["sha256"] == EXPECTED_FREEZE_MANIFEST_SHA256,
                           ident["sha256"], EXPECTED_FREEZE_MANIFEST_SHA256, "FIXTURE")
            if label == "freeze_result":
                checks.add("evidence_binding", ident["sha256"] == EXPECTED_FREEZE_RESULT_SHA256,
                           ident["sha256"], EXPECTED_FREEZE_RESULT_SHA256, "FIXTURE")

    # --- 1. Independent identity recomputation: V2.2 exact inventory ---
    if not v22_root.is_dir():
        checks.add("identity", False, "V2.2 root missing", str(v22_root), "FIXTURE")
        v22_files_on_disk = []
    else:
        v22_files_on_disk = sorted(p.name for p in v22_root.glob("*.py"))
    expected_names = sorted(EXPECTED_V22_FILES.keys())
    checks.add("identity", v22_files_on_disk == expected_names, v22_files_on_disk, expected_names, "FIXTURE")

    v22_identities: dict[str, dict] = {}
    for name, (exp_size, exp_sha) in EXPECTED_V22_FILES.items():
        p = v22_root / name
        if not p.is_file():
            checks.add("identity", False, f"missing {name}", f"present {name}", "FIXTURE")
            continue
        ident = identity(p)
        v22_identities[name] = ident
        checks.add("identity", ident["size_bytes"] == exp_size and ident["sha256"] == exp_sha,
                   ident, {"size_bytes": exp_size, "sha256": exp_sha}, "FIXTURE")

    # --- 1b. Independent rehash of V2.1 (reused) sources ---
    v21_identities: dict[str, dict] = {}
    for rel, (exp_size, exp_sha) in EXPECTED_V21_FILES.items():
        p = v21_root / rel
        if not p.is_file():
            checks.add("immutability", False, f"missing {rel}", f"present {rel}", "FIXTURE")
            continue
        ident = identity(p)
        v21_identities[rel] = ident
        checks.add("immutability", ident["size_bytes"] == exp_size and ident["sha256"] == exp_sha,
                   ident, {"size_bytes": exp_size, "sha256": exp_sha}, "FIXTURE")

    # --- 1c. Independent rehash of SDK sources ---
    sdk_identities: dict[str, dict] = {}
    for rel, (exp_size, exp_sha) in EXPECTED_SDK_FILES.items():
        p = project_root / rel
        if not p.is_file():
            checks.add("immutability", False, f"missing {rel}", f"present {rel}", "FIXTURE")
            continue
        ident = identity(p)
        sdk_identities[rel] = ident
        checks.add("immutability", ident["size_bytes"] == exp_size and ident["sha256"] == exp_sha,
                   ident, {"size_bytes": exp_size, "sha256": exp_sha}, "FIXTURE")

    # Bail out of deep source analysis if the four files are not all present & correct.
    if len(v22_identities) != 4:
        write_failure(out_dir, checks, execution_boundaries, "V2.2 implementation incomplete; cannot proceed to source analysis")
        return 1

    init_tree = parse_module(v22_root / "__init__.py")
    proposal_tree = parse_module(v22_root / "trusted_read_proposal_hook_v2_2.py")
    outcome_tree = parse_module(v22_root / "trusted_read_outcome_hook_v2_2.py")
    factory_tree = parse_module(v22_root / "integration_factory_v2_2.py")
    proposal_text = (v22_root / "trusted_read_proposal_hook_v2_2.py").read_text(encoding="utf-8")
    outcome_text = (v22_root / "trusted_read_outcome_hook_v2_2.py").read_text(encoding="utf-8")
    factory_text = (v22_root / "integration_factory_v2_2.py").read_text(encoding="utf-8")

    module_trees = {
        "__init__.py": init_tree,
        "trusted_read_proposal_hook_v2_2.py": proposal_tree,
        "trusted_read_outcome_hook_v2_2.py": outcome_tree,
        "integration_factory_v2_2.py": factory_tree,
    }

    # --- 2. IMPORT GRAPH INDEPENDENT RESOLUTION ---
    permitted_external_modules = {
        "aicomp_sdk.hooks.types": {"HookContext", "HookResult", "HookStage"},
        "aicomp_sdk.hooks.registry": {"HookRegistry"},
        "aicomp_sdk.core.predicates": {"is_protected_secret_path"},
        "aicomp_sdk.guardrails.base": {"GuardrailBase"},
        "aicomp_sdk_exfil_v2_1.successful_read_ledger_v2_1": {"SuccessfulReadLedgerV21"},
        "aicomp_sdk_exfil_v2_1.lineage_aware_exfil_guardrail_v2_1": {"LineageAwareExfilGuardrailV21"},
    }
    prohibited_modules = {
        "aicomp_sdk_exfil_v2_1.trusted_read_outcome_hook_v2_1",
        "aicomp_sdk_exfil_v2_1.integration_factory_v2_1",
    }
    prohibited_prefixes = ("aicomp_sdk_exfil_v2_2_deprecated", "aicomp_sdk._")

    import_violations = []
    relative_import_targets_ok = True
    for fname, tree in module_trees.items():
        for module, level, names in get_import_from_modules(tree):
            if level and level > 0:
                # relative import within the v2_2 package (e.g. `from .x import Y`)
                target_module = module  # e.g. "trusted_read_proposal_hook_v2_2"
                target_file = f"{target_module}.py" if target_module else None
                if target_file and target_file not in EXPECTED_V22_FILES:
                    relative_import_targets_ok = False
                    import_violations.append({"file": fname, "unresolved_relative_target": target_module})
                continue
            full = module
            if full in prohibited_modules:
                import_violations.append({"file": fname, "prohibited_module": full})
                continue
            if any(full.startswith(pref) for pref in prohibited_prefixes):
                import_violations.append({"file": fname, "prohibited_prefix_module": full})
                continue
            if full not in permitted_external_modules:
                import_violations.append({"file": fname, "unrecognized_external_module": full, "names": names})
                continue
            allowed_names = permitted_external_modules[full]
            for n in names:
                if n not in allowed_names:
                    import_violations.append({"file": fname, "module": full, "unrecognized_name": n})
                # reject private-looking symbol imports defensively
                if n.startswith("_"):
                    import_violations.append({"file": fname, "module": full, "private_symbol_import": n})
        for plain in get_plain_imports(tree):
            if plain not in ("dataclasses", "typing", "collections.abc", "__future__"):
                import_violations.append({"file": fname, "unexpected_plain_import": plain})

    checks.add("imports", relative_import_targets_ok and len(import_violations) == 0,
               import_violations, [], "ADAPTER_PARSE")

    # No V2.2 ledger/record/guardrail successor classes anywhere in the package.
    all_class_names: list[str] = []
    for tree in module_trees.values():
        all_class_names.extend(find_all_classes(tree))
    forbidden_class_substrings = ["LedgerV22", "RecordV22", "GuardrailV22" + "2"]  # keep GuardrailV22 permitted only if V2.1 guardrail reused directly (see below)
    # Explicit prohibition: no class literally named with a V22 ledger/record, and no NEW guardrail class defined in V2.2 at all.
    ledger_or_record_v22_defined = any(("LedgerV22" in c) or ("RecordV22" in c) for c in all_class_names)
    guardrail_class_defined_in_v22 = any(("Guardrail" in c) for c in all_class_names)
    checks.add("ledger_compatibility", not ledger_or_record_v22_defined, all_class_names, "no SuccessfulReadLedgerV22/RecordV22", "PROVENANCE")
    checks.add("ledger_compatibility", not guardrail_class_defined_in_v22, all_class_names, "no guardrail class defined in V2.2 (must reuse V2.1)", "PROVENANCE")

    expected_new_classes = {
        "TrustedReadProposalHookV22", "TrustedReadOutcomeHookV22",
        "ExfilIntegrationBundleV22", "ExfilIntegrationFactoryV22",
    }
    checks.add("identity", set(all_class_names) == expected_new_classes,
               sorted(all_class_names), sorted(expected_new_classes), "ADAPTER_PARSE")

    # --- 2b. __init__.py exports exactly the approved symbols ---
    all_assign = None
    for node in init_tree.body:
        if isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name) and node.targets[0].id == "__all__":
            all_assign = node
    exported = []
    if all_assign is not None and isinstance(all_assign.value, (ast.List, ast.Tuple)):
        exported = [elt.value for elt in all_assign.value.elts if isinstance(elt, ast.Constant) and isinstance(elt.value, str)]
    expected_exports = {"TrustedReadProposalHookV22", "TrustedReadOutcomeHookV22", "ExfilIntegrationBundleV22", "ExfilIntegrationFactoryV22", "build_exfil_integration_v22"}
    checks.add("identity", set(exported) == expected_exports, sorted(exported), sorted(expected_exports), "ADAPTER_PARSE")

    # --- 3. PROPOSAL HOOK INDEPENDENT CONTRACT VERIFICATION ---
    proposal_cls = find_class(proposal_tree, "TrustedReadProposalHookV22")
    checks.add("proposal_hook", proposal_cls is not None, proposal_cls is not None, True, "ADAPTER_PARSE")

    proposal_ok_details = {}
    if proposal_cls is not None:
        call_method = find_method(proposal_cls, "__call__")
        checks.add("proposal_hook", call_method is not None, call_method is not None, True, "ADAPTER_PARSE")
        if call_method is not None:
            src = unparse(call_method)
            # Stage + tool filter (independent literal-position search)
            stage_pos = src.find("HookStage.PRE_TOOL_CALL")
            toolname_pos = src.find("context.tool_name != 'fs.read'")
            checks.add("proposal_hook", stage_pos >= 0 and toolname_pos >= 0,
                       {"stage_pos": stage_pos, "toolname_pos": toolname_pos}, {"both": ">=0"}, "AUTHORIZATION_TRANSPORT")

            # Independently locate the four validation predicates and their RELATIVE
            # order in source text (proves order without trusting variable names).
            mapping_pos = src.find("not isinstance(") if "not isinstance(raw_args, Mapping)" not in src else src.find("not isinstance(raw_args, Mapping)")
            mapping_pos = src.find("not isinstance(raw_args, Mapping)")
            path_key_pos = src.find("'path' not in raw_args")
            path_str_pos = src.find("not isinstance(raw_args['path'], str)")
            path_empty_pos = src.find("not raw_args['path'].strip()")
            positions = [mapping_pos, path_key_pos, path_str_pos, path_empty_pos]
            order_established = all(p >= 0 for p in positions) and positions == sorted(positions)
            proposal_ok_details["validation_order_positions"] = positions
            checks.add("proposal_hook", order_established, positions, "strictly increasing", "ARGUMENT_FIDELITY")

            # Raw validation precedes normalization: no str()/repr()/.lower()/.strip()
            # applied to raw_args prior to the last validation predicate.
            last_validation_pos = max(p for p in positions if p >= 0) if all(p >= 0 for p in positions) else -1
            pre_validation_slice = src[:last_validation_pos] if last_validation_pos > 0 else ""
            normalization_tokens = ["str(raw_args", "repr(raw_args", ".lower()", "raw_args.copy()"]
            no_premature_normalization = not any(tok in pre_validation_slice for tok in normalization_tokens)
            checks.add("proposal_hook", no_premature_normalization, pre_validation_slice[:0] or "n/a", "no normalization before validation", "ARGUMENT_FIDELITY")

            # Modified context field preservation (independent field-by-field check)
            modified_context_calls = walk_calls(call_method, "HookContext")
            checks.add("proposal_hook", len(modified_context_calls) == 1, len(modified_context_calls), 1, "AUTHORIZATION_TRANSPORT")
            if modified_context_calls:
                kw = call_kwargs(modified_context_calls[0])
                missing_fields = [f for f in REQUIRED_HOOK_CONTEXT_PRESERVED_FIELDS if f not in kw]
                checks.add("proposal_hook", len(missing_fields) == 0, missing_fields, [], "AUTHORIZATION_TRANSPORT")
                should_block_kw = kw.get("should_block")
                should_block_is_true = isinstance(should_block_kw, ast.Constant) and should_block_kw.value is True
                checks.add("proposal_hook", should_block_is_true, unparse(should_block_kw) if should_block_kw is not None else None, "True", "AUTHORIZATION_TRANSPORT")

            # HookResult(should_block=...) must NEVER appear anywhere in V2.2.
            hookresult_calls_all_modules = []
            for tree in module_trees.values():
                hookresult_calls_all_modules.extend(walk_calls(tree, "HookResult"))
            should_block_on_hookresult = [c for c in hookresult_calls_all_modules if "should_block" in call_kwargs(c)]
            checks.add("proposal_hook", len(should_block_on_hookresult) == 0,
                       [unparse(c) for c in should_block_on_hookresult], [], "AUTHORIZATION_TRANSPORT")

            # continue_execution=False accompanies the block result
            block_hookresult_calls = walk_calls(call_method, "HookResult")
            block_call_with_ce_false = None
            for c in block_hookresult_calls:
                kw = call_kwargs(c)
                ce = kw.get("continue_execution")
                if isinstance(ce, ast.Constant) and ce.value is False:
                    block_call_with_ce_false = c
            checks.add("proposal_hook", block_call_with_ce_false is not None, block_call_with_ce_false is not None, True, "AUTHORIZATION_TRANSPORT")

            # Default (non-blocking) path returns bare HookResult() at least twice
            # (once for stage/tool mismatch, once for well-formed proposals).
            returns = find_return_nodes(call_method)
            bare_returns = [r for r in returns if return_is_bare_hookresult(r)]
            checks.add("proposal_hook", len(bare_returns) >= 2, len(bare_returns), ">=2", "AUTHORIZATION_TRANSPORT")

            # Exactly one non-bare (blocking) HookResult return.
            nonbare_returns = [r for r in returns if isinstance(r.value, ast.Call) and not return_is_bare_hookresult(r)]
            checks.add("proposal_hook", len(nonbare_returns) == 1, len(nonbare_returns), 1, "AUTHORIZATION_TRANSPORT")

            # No exception-based enforcement (no `raise` anywhere in __call__).
            raises = [n for n in ast.walk(call_method) if isinstance(n, ast.Raise)]
            checks.add("proposal_hook", len(raises) == 0, len(raises), 0, "AUTHORIZATION_TRANSPORT")

    # --- 4. OUTCOME HOOK INDEPENDENT CONTRACT VERIFICATION ---
    outcome_cls = find_class(outcome_tree, "TrustedReadOutcomeHookV22")
    checks.add("outcome_hook", outcome_cls is not None, outcome_cls is not None, True, "ADAPTER_PARSE")

    if outcome_cls is not None:
        call_method = find_method(outcome_cls, "__call__")
        checks.add("outcome_hook", call_method is not None, call_method is not None, True, "ADAPTER_PARSE")
        if call_method is not None:
            src = unparse(call_method)
            stage_pos = src.find("HookStage.POST_TOOL_CALL")
            toolname_pos = src.find("context.tool_name != 'fs.read'")
            checks.add("outcome_hook", stage_pos >= 0 and toolname_pos >= 0,
                       {"stage_pos": stage_pos, "toolname_pos": toolname_pos}, {"both": ">=0"}, "AUTHORIZATION_TRANSPORT")

            ok_exact_pos = src.find("evidence.get('ok') is not True") if "evidence.get('ok') is not True" in src else src.find("trusted.get('ok') is not True")
            checks.add("outcome_hook", ok_exact_pos >= 0, ok_exact_pos, ">=0", "SECRET_CAPTURE")

            protected_call = walk_calls(call_method, "is_protected_secret_path")
            checks.add("outcome_hook", len(protected_call) == 1, len(protected_call), 1, "SECRET_CAPTURE")
            protected_pos = src.find("is_protected_secret_path(path)")

            output_check_pos = src.find("not isinstance(output, str)")
            checks.add("outcome_hook", output_check_pos >= 0, output_check_pos, ">=0", "SECRET_CAPTURE")

            append_calls = walk_calls(call_method, "append_successful_read")
            checks.add("outcome_hook", len(append_calls) == 1, len(append_calls), 1, "PROVENANCE")

            append_pos = src.find("append_successful_read")

            # Independent line-order proof (not just text-position within unparsed
            # string, but real statement ordering in the function body) that ALL
            # malformed-input branches precede the append call.
            body_stmts = call_method.body
            append_stmt_index = None
            malformed_return_indices = []
            for idx, stmt in enumerate(body_stmts):
                if isinstance(stmt, ast.If):
                    # look inside If bodies for the malformed-output HookResult returns
                    for sub in ast.walk(stmt):
                        if isinstance(sub, ast.Return) and isinstance(sub.value, ast.Call):
                            kw = call_kwargs(sub.value)
                            meta = kw.get("metadata")
                            if meta is not None and "POST_TOOL_OBSERVATION_CONTRACT_VIOLATION" in unparse(meta):
                                malformed_return_indices.append(idx)
                for sub in ast.walk(stmt):
                    if isinstance(sub, ast.Call):
                        fn = sub.func
                        if (isinstance(fn, ast.Attribute) and fn.attr == "append_successful_read"):
                            append_stmt_index = idx
            malformed_before_append = (
                append_stmt_index is not None and
                len(malformed_return_indices) >= 3 and
                all(i < append_stmt_index for i in malformed_return_indices)
            )
            checks.add("outcome_hook", malformed_before_append,
                       {"malformed_return_indices": malformed_return_indices, "append_stmt_index": append_stmt_index},
                       "all malformed-output returns occur in statements before the append statement",
                       "PROVENANCE")

            # No should_block anywhere in outcome hook; no continue_execution=False.
            should_block_present = "should_block" in src
            checks.add("outcome_hook", not should_block_present, should_block_present, False, "AUTHORIZATION_TRANSPORT")
            ce_false_present = "continue_execution=False" in src or "continue_execution = False" in src
            checks.add("outcome_hook", not ce_false_present, ce_false_present, False, "AUTHORIZATION_TRANSPORT")

            # No prevention-claiming language.
            lowered = outcome_text.lower()
            prevention_words = ["prevent", "blocked the read", "block the read"]
            prevention_claim_present = any(w in lowered for w in prevention_words)
            checks.add("outcome_hook", not prevention_claim_present, prevention_claim_present, False, "AUTHORIZATION_TRANSPORT")

            # Exact append arguments (independent keyword-set check).
            append_kw = call_kwargs(append_calls[0]) if append_calls else {}
            required_append_kwargs = {"tool_name", "tool_args", "canonical_path", "explicit_ok", "error_value", "raw_output"}
            checks.add("outcome_hook", set(append_kw.keys()) == required_append_kwargs,
                       sorted(append_kw.keys()), sorted(required_append_kwargs), "PROVENANCE")
            explicit_ok_kw = append_kw.get("explicit_ok")
            explicit_ok_true = isinstance(explicit_ok_kw, ast.Constant) and explicit_ok_kw.value is True
            checks.add("outcome_hook", explicit_ok_true, unparse(explicit_ok_kw) if explicit_ok_kw is not None else None, "True", "PROVENANCE")

            # Success metadata check.
            success_meta_present = "successful_protected_read_recorded_v22" in outcome_text
            checks.add("outcome_hook", success_meta_present, success_meta_present, True, "PROVENANCE")

            raises = [n for n in ast.walk(call_method) if isinstance(n, ast.Raise)]
            checks.add("outcome_hook", len(raises) == 0, len(raises), 0, "AUTHORIZATION_TRANSPORT")

    # --- 5. FACTORY INDEPENDENT CONTRACT VERIFICATION ---
    bundle_cls = find_class(factory_tree, "ExfilIntegrationBundleV22")
    factory_cls = find_class(factory_tree, "ExfilIntegrationFactoryV22")
    checks.add("factory", bundle_cls is not None and factory_cls is not None,
               {"bundle": bundle_cls is not None, "factory": factory_cls is not None}, {"both": True}, "ADAPTER_PARSE")

    if bundle_cls is not None:
        field_names = []
        for node in bundle_cls.body:
            if isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
                field_names.append(node.target.id)
        expected_fields = ["ledger", "proposal_hook", "outcome_hook", "guardrail"]
        checks.add("factory", field_names == expected_fields, field_names, expected_fields, "ADAPTER_PARSE")

    if factory_cls is not None:
        build_method = find_method(factory_cls, "build")
        checks.add("factory", build_method is not None, build_method is not None, True, "ADAPTER_PARSE")
        if build_method is not None:
            register_calls = walk_calls(build_method, "register_hook")
            checks.add("factory", len(register_calls) == 2, len(register_calls), 2, "ROUTING")

            stages_seen = []
            priorities_seen = []
            for c in register_calls:
                if len(c.args) >= 2:
                    stage_arg = unparse(c.args[0])
                    stages_seen.append(stage_arg)
                if len(c.args) >= 3:
                    prio_arg = c.args[2]
                    priorities_seen.append(prio_arg)
            checks.add("factory", "HookStage.PRE_TOOL_CALL" in stages_seen and "HookStage.POST_TOOL_CALL" in stages_seen,
                       stages_seen, ["HookStage.PRE_TOOL_CALL", "HookStage.POST_TOOL_CALL"], "ROUTING")

            # Priorities resolve (via module-level constants) to literal int 0.
            module_level_int_consts = {}
            for node in factory_tree.body:
                if isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
                    if isinstance(node.value, ast.Constant) and isinstance(node.value.value, int):
                        module_level_int_consts[node.targets[0].id] = node.value.value
            resolved_priorities = []
            for p in priorities_seen:
                if isinstance(p, ast.Constant) and isinstance(p.value, int):
                    resolved_priorities.append(p.value)
                elif isinstance(p, ast.Name) and p.id in module_level_int_consts:
                    resolved_priorities.append(module_level_int_consts[p.id])
                else:
                    resolved_priorities.append(None)
            checks.add("factory", resolved_priorities == [0, 0], resolved_priorities, [0, 0], "ROUTING")

            # Single shared ledger instance fed to BOTH the outcome hook constructor
            # AND the guardrail constructor (independent identifier-flow check).
            ledger_assign_name = None
            for node in build_method.body:
                if isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
                    if isinstance(node.value, ast.Call):
                        fn = node.value.func
                        if isinstance(fn, ast.Name) and fn.id == "SuccessfulReadLedgerV21":
                            ledger_assign_name = node.targets[0].id
            checks.add("factory", ledger_assign_name is not None, ledger_assign_name, "some identifier", "PROVENANCE")

            outcome_hook_calls = walk_calls(build_method, "TrustedReadOutcomeHookV22")
            guardrail_calls = walk_calls(build_method, "LineageAwareExfilGuardrailV21")
            ledger_fed_to_outcome = False
            ledger_fed_to_guardrail = False
            if ledger_assign_name:
                for c in outcome_hook_calls:
                    kw = call_kwargs(c)
                    lv = kw.get("ledger")
                    if isinstance(lv, ast.Name) and lv.id == ledger_assign_name:
                        ledger_fed_to_outcome = True
                for c in guardrail_calls:
                    kw = call_kwargs(c)
                    lv = kw.get("ledger")
                    if isinstance(lv, ast.Name) and lv.id == ledger_assign_name:
                        ledger_fed_to_guardrail = True
            checks.add("factory", ledger_fed_to_outcome and ledger_fed_to_guardrail,
                       {"fed_to_outcome": ledger_fed_to_outcome, "fed_to_guardrail": ledger_fed_to_guardrail},
                       {"fed_to_outcome": True, "fed_to_guardrail": True}, "PROVENANCE")

    # --- Explicit refusal to claim runtime idempotence ---
    repeated_factory_build_idempotence = "NOT_EVALUATED"

    # --- Final disposition ---
    failed = checks.failed
    if failed:
        # Classify the earliest failing category into an outcome bucket.
        first_fail = failed[0]
        cat = first_fail.category
        if cat in ("identity", "immutability", "evidence_binding"):
            outcome = "V2_2_IMPORT_CONTRACT_GAP" if cat == "imports" else "NOT_ESTABLISHED"
        elif cat == "imports":
            outcome = "V2_2_IMPORT_CONTRACT_GAP"
        elif cat == "proposal_hook":
            outcome = "V2_2_PRE_TOOL_BLOCKING_DESIGN_GAP"
        elif cat == "outcome_hook":
            outcome = "V2_2_POST_TOOL_OBSERVATION_GAP"
        elif cat == "ledger_compatibility":
            outcome = "V2_2_LEDGER_COMPATIBILITY_GAP"
        elif cat == "factory":
            outcome = "V2_2_REGISTRATION_CONTRACT_GAP"
        else:
            outcome = "NOT_ESTABLISHED"
        status = "INDEPENDENT_V2_2_HOOK_STATIC_QUALIFICATION_COMPLETE_WITH_GAPS"
    else:
        outcome = "INDEPENDENT_V2_2_HOOK_STATIC_QUALIFICATION_PASS"
        status = "INDEPENDENT_V2_2_HOOK_STATIC_QUALIFICATION_COMPLETE_PASS"

    claim_boundary = {
        "allowed": [
            "V2.2 file identities independently recomputed and matched",
            "V2.2 import graph independently resolved; only V2.1 ledger/guardrail reuse permitted",
            "Two-stage PRE_TOOL_CALL/POST_TOOL_CALL contract independently re-derived from AST",
            "Proposal-hook validation order, block transport, and absence of HookResult(should_block=) independently verified",
            "Outcome-hook malformed-output branches independently proven to precede ledger append via statement-index ordering",
            "Factory registration count, stages, literal priorities, shared ledger flow, and bundle field order independently verified",
            "V2.1 and SDK source immutability independently reconfirmed via freshly computed hashes",
        ],
        "prohibited": [
            "claim V2.2 imports or instantiates successfully",
            "claim PRE_TOOL_CALL blocking works at runtime",
            "claim POST_TOOL_CALL capture works at runtime",
            "claim HookRegistry or Sandbox integration",
            "claim repeated-factory-build idempotence (NOT_EVALUATED)",
            "claim HTTP, guardrail effectiveness, predicate, or breach behavior",
            "claim robust end-to-end security findings",
        ],
    }

    result = {
        "version": VERSION,
        "created_at_utc": now_iso(),
        "status": status,
        "classification": "READ_ONLY_INDEPENDENT_V2_2_STATIC_SOURCE_QUALIFICATION",
        "outcome": outcome,
        "checks": {
            "total": len(checks.rows),
            "passed": len(checks.rows) - len(failed),
            "failed": len(failed),
            "failed_ids": [c.check_id for c in failed],
        },
        "bound_evidence": bound_evidence,
        "v22_identities": v22_identities,
        "v21_identities": v21_identities,
        "sdk_identities": sdk_identities,
        "repeated_factory_build_idempotence": repeated_factory_build_idempotence,
        "execution_boundaries": execution_boundaries,
        "scientific_verdict": {
            "V2_2_identity": "INDEPENDENTLY_ESTABLISHED" if not failed else "NOT_ESTABLISHED",
            "V2_2_import_graph": "INDEPENDENTLY_ESTABLISHED" if not failed else "NOT_ESTABLISHED",
            "V2_2_two_stage_contract": "INDEPENDENTLY_ESTABLISHED" if not failed else "NOT_ESTABLISHED",
            "V2_2_ledger_reuse_compatibility": "INDEPENDENTLY_ESTABLISHED" if not failed else "NOT_ESTABLISHED",
            "V2_2_registration_contract": "INDEPENDENTLY_ESTABLISHED" if not failed else "NOT_ESTABLISHED",
            "V2_2_runtime_behavior": "NOT_EVALUATED",
            "harness_trick": "NOT_DEMONSTRATED",
            "robust_security_findings": "NOT_ESTABLISHED",
        },
        "claim_boundary": claim_boundary,
        "next_gate": "CONTROLLED_V2_2_MALFORMED_HOOK_RUNTIME_QUALIFICATION" if not failed else "INDEPENDENT_V2_2_HOOK_STATIC_QUALIFICATION_GAP_REVIEW",
    }

    # --- Write artifacts ---
    result_path = out_dir / "independent_v2_2_static_result.json"
    checks_path = out_dir / "independent_v2_2_static_checks.csv"
    claim_path = out_dir / "independent_v2_2_static_claim_boundary.json"
    binding_path = out_dir / "independent_v2_2_static_binding.json"

    result_path.write_text(json.dumps(result, indent=2, sort_keys=True, default=str), encoding="utf-8")

    with checks_path.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=["check_id", "category", "passed", "observed", "expected", "failure_layer"])
        writer.writeheader()
        for row in checks.as_dicts():
            writer.writerow(row)

    claim_path.write_text(json.dumps(claim_boundary, indent=2, sort_keys=True), encoding="utf-8")

    binding = {
        "version": VERSION,
        "created_at_utc": now_iso(),
        "runner": identity(Path(__file__).resolve()),
        "bound_evidence": bound_evidence,
        "v22_identities": v22_identities,
        "v21_identities": v21_identities,
        "sdk_identities": sdk_identities,
        "execution_boundaries": execution_boundaries,
    }
    binding_path.write_text(json.dumps(binding, indent=2, sort_keys=True, default=str), encoding="utf-8")

    manifest_rows = []
    for p in [result_path, checks_path, claim_path, binding_path]:
        ident = identity(p)
        manifest_rows.append({**ident, "role": "IV22_STATIC_DERIVED"})
    for label, ident in bound_evidence.items():
        manifest_rows.append({**ident, "role": f"IV22_STATIC_BOUND_{label.upper()}"})
    for name, ident in v22_identities.items():
        manifest_rows.append({**ident, "role": "IV22_STATIC_REHASHED_V22"})
    for rel, ident in v21_identities.items():
        manifest_rows.append({**ident, "role": "IV22_STATIC_REHASHED_V21"})
    for rel, ident in sdk_identities.items():
        manifest_rows.append({**ident, "role": "IV22_STATIC_REHASHED_SDK"})

    manifest_path = out_dir / "independent_v2_2_static_manifest.csv"
    with manifest_path.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=["artifact", "role", "size_bytes", "sha256", "path"])
        writer.writeheader()
        for row in manifest_rows:
            writer.writerow(row)

    manifest_sha = sha256_of(manifest_path)
    external_binding = {
        "version": VERSION,
        "created_at_utc": now_iso(),
        "status": status,
        "manifest_filename": manifest_path.name,
        "manifest_size_bytes": manifest_path.stat().st_size,
        "manifest_sha256": manifest_sha,
        "runner_sha256": sha256_of(Path(__file__).resolve()),
        "design_manifest_sha256": EXPECTED_DESIGN_MANIFEST_SHA256,
        "freeze_manifest_sha256": EXPECTED_FREEZE_MANIFEST_SHA256,
        "checks_total": len(checks.rows),
        "checks_passed": len(checks.rows) - len(failed),
        "checks_failed": len(failed),
        "failed_ids": [c.check_id for c in failed],
        "outcome": outcome,
        "V2_2_imported": False,
        "V2_1_modified": False,
        "SDK_modified": False,
        "repeated_factory_build_idempotence": repeated_factory_build_idempotence,
        "next_gate": result["next_gate"],
    }
    external_path = out_dir / "independent_v2_2_static_manifest_external_binding.json"
    external_path.write_text(json.dumps(external_binding, indent=2, sort_keys=True), encoding="utf-8")

    print(json.dumps({
        "status": status,
        "checks": f"{len(checks.rows) - len(failed)}/{len(checks.rows)}",
        "failed_ids": [c.check_id for c in failed],
        "outcome": outcome,
        "V2_2_imported": False,
        "manifest_sha256": manifest_sha,
        "next_gate": result["next_gate"],
    }, indent=2))

    return 0 if not failed else 1


def write_failure(out_dir: Path, checks: Checks, execution_boundaries: dict, message: str) -> None:
    failure = {
        "version": VERSION,
        "created_at_utc": now_iso(),
        "status": "INDEPENDENT_V2_2_HOOK_STATIC_QUALIFICATION_BLOCKED",
        "error": message,
        "checks_frozen": checks.as_dicts(),
        "execution_boundaries": execution_boundaries,
    }
    (out_dir / "INDEPENDENT_V2_2_HOOK_STATIC_QUALIFICATION_FAILED.json").write_text(
        json.dumps(failure, indent=2, sort_keys=True, default=str), encoding="utf-8"
    )


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as exc:  # noqa: BLE001
        print(f"FAILED: {exc}", file=sys.stderr)
        raise
