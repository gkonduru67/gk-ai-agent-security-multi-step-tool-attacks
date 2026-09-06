#!/usr/bin/env python3
"""EX6E.1B focused read-only source-body inspection v6.52.

Extracts line-bound evidence for ToolSuite._create_fs_root, filesystem read
implementation(s), predicates._is_secret_path, predicates.is_protected_secret_path,
and packaged Optimal Guardrail.decide. The inspected SDK is parsed only as text
and AST. No SDK import, Sandbox construction, tool execution, or fixture mutation
is performed. Full source bodies remain local in the evidence JSON; summary CSVs
contain hashes and bounded semantic indicators.
"""
from __future__ import annotations
import argparse, ast, csv, hashlib, json, re
from pathlib import Path
from typing import Any

VERSION = 'EX6E_1B_FOCUSED_FILESYSTEM_PREDICATE_GUARDRAIL_BODY_INSPECTION_v6.52'
EXPECTED = {
    'suite': '23C3BEE3DE98377E0D93AAC16F5D1091839E5D1420E31B78C7F88C28E06867AA',
    'fs': '4B8C54032ED807CE4C35BAB403EE622141881158E10F600A4B6D329E6D6F95B8',
    'predicates': '9D9DE5118D8883A0074A5405ED85CF2DEC3F68E8516908CBC48F409E3BA56F37',
    'optimal': '6724FEDF7BBF3E67DFCDD564BA8A73463E0F783D5C84E0A70DCEFF40C1BC61ED',
    'parent_manifest': 'BC23206397A477AA4D4E13B3924498ABEC8EF92C5AD8F3A350AAD30573E5A9E0',
}

def hf(p: Path) -> str:
    h = hashlib.sha256()
    with p.open('rb') as f:
        for b in iter(lambda: f.read(1024 * 1024), b''):
            h.update(b)
    return h.hexdigest().upper()

def hs(s: str) -> str:
    return hashlib.sha256(s.encode('utf-8')).hexdigest().upper()

def dumpx(p: Path, value: Any) -> None:
    with p.open('x', encoding='utf-8') as f:
        json.dump(value, f, indent=2, sort_keys=True, default=str)
        f.write('\n')

def csvout(p: Path, fields: list[str], rows: list[dict[str, Any]]) -> None:
    with p.open('x', encoding='utf-8-sig', newline='') as f:
        w = csv.DictWriter(f, fieldnames=fields, extrasaction='raise')
        w.writeheader(); w.writerows(rows)

def node_name(n: ast.AST) -> str:
    if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
        return n.name
    return ''

def dotted(n: ast.AST | None) -> str:
    if isinstance(n, ast.Name): return n.id
    if isinstance(n, ast.Attribute):
        p = dotted(n.value)
        return f'{p}.{n.attr}' if p else n.attr
    return ''

def find_nodes(path: Path, specifications: list[tuple[str | None, str]]) -> list[dict[str, Any]]:
    text = path.read_text(encoding='utf-8')
    tree = ast.parse(text)
    found = []
    classes = {n.name: n for n in tree.body if isinstance(n, ast.ClassDef)}
    for class_name, func_name in specifications:
        scope = classes.get(class_name).body if class_name else tree.body
        matches = [n for n in scope if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) and n.name == func_name]
        for n in matches:
            body = ast.get_source_segment(text, n) or ''
            calls = sorted({dotted(x.func) for x in ast.walk(n) if isinstance(x, ast.Call) and dotted(x.func)})
            literals = sorted({x.value for x in ast.walk(n) if isinstance(x, ast.Constant) and isinstance(x.value, str)})
            found.append({
                'source_file': path.name,
                'qualified_symbol': f'{class_name}.{func_name}' if class_name else func_name,
                'start_line': n.lineno,
                'end_line': getattr(n, 'end_lineno', n.lineno),
                'source_sha256': hs(body),
                'source_body': body,
                'calls': calls,
                'string_literals': literals,
            })
    return found

def find_read_functions(path: Path) -> list[dict[str, Any]]:
    text = path.read_text(encoding='utf-8')
    tree = ast.parse(text)
    out = []
    for n in ast.walk(tree):
        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) and ('read' in n.name.lower() or n.name.lower() in {'invoke', 'execute'}):
            body = ast.get_source_segment(text, n) or ''
            low = body.lower()
            if any(t in low for t in ('read_text', 'open(', 'path', 'fs.read', 'file')):
                parent = next((c.name for c in tree.body if isinstance(c, ast.ClassDef) and n in c.body), None)
                out.append({
                    'source_file': path.name,
                    'qualified_symbol': f'{parent}.{n.name}' if parent else n.name,
                    'start_line': n.lineno,
                    'end_line': getattr(n, 'end_lineno', n.lineno),
                    'source_sha256': hs(body),
                    'source_body': body,
                    'calls': sorted({dotted(x.func) for x in ast.walk(n) if isinstance(x, ast.Call) and dotted(x.func)}),
                    'string_literals': sorted({x.value for x in ast.walk(n) if isinstance(x, ast.Constant) and isinstance(x.value, str)}),
                })
    return out

def semantic_row(item: dict[str, Any]) -> dict[str, Any]:
    body = item['source_body']
    low = body.lower()
    return {
        'source_file': item['source_file'],
        'qualified_symbol': item['qualified_symbol'],
        'start_line': item['start_line'],
        'end_line': item['end_line'],
        'source_sha256': item['source_sha256'],
        'mentions_file_seed': 'file_seed' in low,
        'mentions_protected_directory': bool(re.search(r"['\"]protected(?:/|\\\\|['\"])", body, re.I)),
        'mentions_admin_note': 'admin_note.txt' in low,
        'mentions_secret_txt': 'secret.txt' in low,
        'checks_basename': any(x in low for x in ('.name', 'basename', 'path.name')),
        'checks_full_path': any(x in low for x in ('as_posix', 'str(path', 'str(p', 'resolve(', 'relative_to', 'parts')),
        'uses_substring_secret_match': bool(re.search(r"secret.{0,80}\bin\b|\bin\b.{0,80}secret", low, re.S)),
        'uses_exact_secret_txt_match': 'secret.txt' in low and any(x in low for x in ('==', 'endswith', 'match', 'search')),
        'reads_file_content': any(x in low for x in ('read_text', '.read(', 'open(')),
        'normalizes_or_resolves_path': any(x in low for x in ('resolve(', 'normpath', 'normalize', 'relative_to')),
        'call_names': ' | '.join(item['calls']),
        'string_literal_count': len(item['string_literals']),
    }

def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument('--suite-source', required=True, type=Path)
    ap.add_argument('--fs-source', required=True, type=Path)
    ap.add_argument('--predicate-source', required=True, type=Path)
    ap.add_argument('--optimal-source', required=True, type=Path)
    ap.add_argument('--parent-manifest', required=True, type=Path)
    ap.add_argument('--parent-binding', required=True, type=Path)
    ap.add_argument('--out-root', required=True, type=Path)
    a = ap.parse_args(); out = a.out_root.resolve()
    if out.exists(): ap.error(f'Refusing to overwrite: {out}')
    inputs = {'suite': a.suite_source, 'fs': a.fs_source, 'predicates': a.predicate_source, 'optimal': a.optimal_source, 'parent_manifest': a.parent_manifest}
    for name, p in inputs.items():
        if not p.is_file() or hf(p) != EXPECTED[name]: ap.error(f'Frozen {name} identity mismatch')
    if not a.parent_binding.is_file(): ap.error('Parent binding missing')
    binding = json.loads(a.parent_binding.read_text(encoding='utf-8'))
    if binding.get('manifest_sha256') != hf(a.parent_manifest): ap.error('Parent binding does not match parent manifest')

    bodies = []
    bodies += find_nodes(a.suite_source, [('ToolSuite', '_create_fs_root')])
    bodies += find_read_functions(a.fs_source)
    bodies += find_nodes(a.predicate_source, [(None, '_is_secret_path'), (None, 'is_protected_secret_path')])
    bodies += find_nodes(a.optimal_source, [('Guardrail', 'decide')])
    expected_symbols = {'ToolSuite._create_fs_root', '_is_secret_path', 'is_protected_secret_path', 'Guardrail.decide'}
    present = {x['qualified_symbol'] for x in bodies}
    missing = sorted(expected_symbols - present)
    if missing: ap.error('Missing required symbols: ' + ', '.join(missing))

    summary = [semantic_row(x) for x in bodies]
    by = {x['qualified_symbol']: x for x in summary}
    predicate_items = [x for x in summary if x['qualified_symbol'] in {'_is_secret_path', 'is_protected_secret_path'}]
    fs_items = [x for x in summary if x['source_file'] == a.fs_source.name]
    loader = by['ToolSuite._create_fs_root']
    optimal = by['Guardrail.decide']

    directory_authority = any(x['mentions_protected_directory'] for x in predicate_items + [optimal])
    admin_binding = any(x['mentions_admin_note'] for x in predicate_items + [optimal])
    content_based_protection = any(x['reads_file_content'] for x in predicate_items + [optimal])
    mapping_support = loader['mentions_file_seed'] or loader['normalizes_or_resolves_path']
    fs_path_resolution = any(x['normalizes_or_resolves_path'] for x in fs_items)

    if directory_authority:
        classification = 'SOURCE_BODIES_EXPLICITLY_REFERENCE_PROTECTED_DIRECTORY_SEMANTICS_RUNTIME_STILL_WITHHELD'
    elif admin_binding:
        classification = 'SOURCE_BODIES_EXPLICITLY_BIND_ADMIN_NOTE_RUNTIME_STILL_WITHHELD'
    else:
        classification = 'SOURCE_BODIES_DO_NOT_ESTABLISH_PROTECTED_DIRECTORY_OR_ADMIN_NOTE_AUTHORITY_D5_UNAVAILABLE'

    qualification = {
        'schema': 'EX6E_1B_V6_52', 'version': VERSION,
        'classification': classification,
        'execution_type': 'READ_ONLY_FOCUSED_SOURCE_BODY_INSPECTION',
        'function_body_count': len(bodies),
        'required_symbols_found': sorted(expected_symbols),
        'findings': {
            'ToolSuite_create_fs_root': {
                'line_bound': [loader['start_line'], loader['end_line']],
                'source_sha256': loader['source_sha256'],
                'maps_file_seed_or_normalizes_path': mapping_support,
                'explicit_protected_directory_semantics': loader['mentions_protected_directory'],
            },
            'filesystem_read_implementations': {
                'count': len(fs_items),
                'path_resolution_or_normalization_present': fs_path_resolution,
                'source_sha256s': [x['source_sha256'] for x in fs_items],
            },
            'predicate_path_logic': {
                'explicit_protected_directory_semantics': any(x['mentions_protected_directory'] for x in predicate_items),
                'explicit_admin_note_binding': any(x['mentions_admin_note'] for x in predicate_items),
                'secret_txt_reference': any(x['mentions_secret_txt'] for x in predicate_items),
                'content_read_for_classification': any(x['reads_file_content'] for x in predicate_items),
                'function_source_sha256s': {x['qualified_symbol']: x['source_sha256'] for x in predicate_items},
            },
            'packaged_optimal_path_branch': {
                'line_bound': [optimal['start_line'], optimal['end_line']],
                'source_sha256': optimal['source_sha256'],
                'explicit_protected_directory_semantics': optimal['mentions_protected_directory'],
                'explicit_admin_note_binding': optimal['mentions_admin_note'],
                'secret_txt_reference': optimal['mentions_secret_txt'],
                'content_read_for_classification': optimal['reads_file_content'],
            },
            'authoritative_directory_protection': 'EXPLICITLY_ESTABLISHED_IN_FOCUSED_BODIES' if directory_authority else 'NOT_ESTABLISHED_IN_FOCUSED_BODIES',
            'admin_note_authoritative_binding': 'EXPLICITLY_ESTABLISHED' if admin_binding else 'NOT_ESTABLISHED',
            'admin_note_protected_content': 'NOT_ESTABLISHED_BY_SOURCE_BODY_INSPECTION',
        },
        'D5': {
            'runtime_authorized': False,
            'source_only_runtime_preflight_eligible': bool(directory_authority or admin_binding),
            'sink_runtime_authorized': False,
            'behavior': 'NOT_TESTED',
        },
        'runtime': {'SDK_imported': False, 'Sandbox_constructed': False, 'tool_execution': False, 'model_called': False},
        'mutations': {'files_created': False, 'files_modified': False, 'files_renamed': False},
        'harness_trick': 'NOT_DEMONSTRATED',
        'security_finding': 'NOT_ESTABLISHED',
        'attack_optimization_authorized': False,
        'hardened_policy_implementation_authorized': False,
        'packaged_vs_hardened_execution_authorized': False,
    }

    out.mkdir(parents=True)
    safe = out / 'ex6e1b_function_body_summary.csv'
    csvout(safe, list(summary[0]), summary)
    evidence = out / 'ex6e1b_line_bound_source_evidence.json'
    dumpx(evidence, {'version': VERSION, 'source_bodies': bodies})
    qp = out / 'ex6e1b_qualification.json'; dumpx(qp, qualification)

    sources = [a.suite_source, a.fs_source, a.predicate_source, a.optimal_source, a.parent_manifest, a.parent_binding, Path(__file__).resolve()]
    mr = [{'artifact': p.name, 'role': 'SOURCE_OR_PARENT', 'size_bytes': p.stat().st_size, 'sha256': hf(p)} for p in sources]
    for p in (safe, evidence, qp):
        mr.append({'artifact': p.name, 'role': 'DERIVED', 'size_bytes': p.stat().st_size, 'sha256': hf(p)})
    mp = out / 'ex6e1b_manifest.csv'; csvout(mp, ['artifact', 'role', 'size_bytes', 'sha256'], mr)
    dumpx(out / 'ex6e1b_manifest_external_binding.json', {'manifest_filename': mp.name, 'manifest_size_bytes': mp.stat().st_size, 'manifest_sha256': hf(mp), 'binding_scope': 'EXTERNAL_SELF_BINDING_RECORD'})
    print(json.dumps({'version': VERSION, 'classification': classification, 'function_body_count': len(bodies), 'qualification_sha256': hf(qp), 'manifest_sha256': hf(mp)}, indent=2))
    return 0

if __name__ == '__main__':
    raise SystemExit(main())
