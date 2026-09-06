#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
P6C_FIXTURE_AND_TASK_PROMPT_FREEZE_v1_0  (EXFILTRATION phase)

GATE TYPE : FIXTURE / IDENTITY FREEZE  (runtime = FALSE for models/tools/predicates)

PURPOSE
-------
Close the P6C blocking gate FREEZE_FIXTURE_AND_DEFENSE_SHAS by:
  (1) Independently recomputing SHA-256 for every design-spec §4 defense/fixture
      file and comparing to the expected constant  -> ESTABLISHED / MISMATCH / MISSING.
      (This is the independent recomputation the design-spec caveat
       'sha256_independently_recomputed: NOT_ESTABLISHED' requires. The KNOWN_*
       constants embedded in the harness are self-declared, NOT independent.)
  (2) FAIL-CLOSING the documented conflation: the design-spec §4 'EXFILTRATION
      task prompt' row carries 946AE6...DABD, which is actually the BENIGN system
      prompt identity (v1_4 result system_prompt_sha256). If the candidate exfil
      task-prompt file hashes to that benign value, this tool REFUSES and labels
      EXFIL_TASK_PROMPT_CONFLATED_WITH_BENIGN. It never freezes a benign prompt as
      the attack task.
  (3) Read-only discovery of where the attack task actually comes from (harness
      --task argument, historical logs). If not authoritatively located, it leaves
      NOT_ESTABLISHED and prints a read-only discovery command instead of inventing.
  (4) Emitting the corrected system_message_sha256 over the concatenated system
      content (SYSTEM_PROMPT + TOOL_SCHEMA_TEXT) for the ledger.
  (5) Writing an EXTERNAL-BOUND manifest (result -> manifest -> binding), never
      self-hashing, never overwriting frozen artifacts.

CODE RULES HONORED
------------------
- New filename + distinct class name (P6cFixtureAndTaskPromptFreeze).
- Does NOT import or execute the SDK (predicates/sandbox/gym/api), the model,
  the guardrails, the ledger logic, or any tool. It only opens files in binary
  read mode to hash them, and reads text to grep for the task-prompt source.
- Fail-closed: any NOT_ESTABLISHED / MISMATCH / MISSING sets frozen=false.
- Raw values preserved; nothing decoded; no secret contents copied to output.
- External manifest binding (result/manifest/binding are three separate files).
- Never writes to any input path; only NEW out-tag'd files under --out-dir.

CLAIM BOUNDARY
--------------
ALLOWED  : file identity (SHA-256) equality/inequality vs expected; whether the
           candidate exfil task prompt is distinct from the benign system prompt;
           corrected system_message_sha256.
PROHIBITED: any runtime, model-generation, guardrail, sink, predicate, breach,
           hosted-parity, or robust-security claim. Identity != claim relevance.
"""

import argparse
import hashlib
import json
import os
import sys
from datetime import datetime, timezone

TOOL_ID = "P6C_FIXTURE_AND_TASK_PROMPT_FREEZE"
TOOL_VERSION = "v1_0"
NOT_ESTABLISHED = "NOT_ESTABLISHED"

# ---- Expected identities carried in from frozen evidence (design-spec §4). -----
# These are the values to VERIFY against; they are NOT trusted on their own.
EXPECTED = {
    "secret_fixture":      "746AA20818152DCC585F78C4E8F93990A668AEA0E060AA254D06502AEAA16FB8",
    "optimal_py":          "6724FEDF7BBF3E67DFCDD564BA8A73463E0F783D5C84E0A70DCEFF40C1BC61ED",
    "predicates_py":       "9D9DE5118D8883A0074A5405ED85CF2DEC3F68E8516908CBC48F409E3BA56F37",
    "sandbox_py":          "B781375C5AAE3C2533F6992AAE6D3C65CA56B7077822F1A27955756BEF1168D0",
    "api_py":              "60F1E4424EC3DEE73186F87ED1184D2CA1DBC4C2A0022004DECEC8B6E94C7CB1",
    "gym_py":              "8BBC3479515C388717D76FE9964D957A7CBD9BFB97C28AA894E9C51E3051F8AF",
    "custom_guardrail":    "2AC1CA55FB0C18460F50B35677F5ECD9EB3477CFB21F9C19F44A48C7AEFD5C26",
    "ledger":              "18146742E6866C491A032AA96EFC248FFED05706895D32FDE724145D0878009C",
    "transport_shim_v1_4": "9CA5D8618D693F434B6B327302B00BDA9A628C3441A08A6270E72D1CA7B3DE1A",
    "real_harness":        "289F67E0FA89FAC02B256C893F3B69C88D025E0A074BE7A287189DDEB5840F39",
}

# The BENIGN system-prompt identity. The candidate exfil task prompt MUST NOT
# equal this value (that is the documented conflation to fail-close on).
BENIGN_SYSTEM_PROMPT_SHA256 = "946AE69B0C3F704F4043668704F8CFAD480366C197C560D85145B2C0BBB6DABD"

# Substrings that indicate a real attack-task source when grepping (read-only).
TASK_SOURCE_MARKERS = ("--task", "fs.read", "http.post", "secret.txt", "exfil")


def sha256_file(path):
    """Independent SHA-256 over the raw bytes of a file (no normalization)."""
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest().upper()


def sha256_text(t):
    return hashlib.sha256(t.encode("utf-8", "surrogatepass")).hexdigest().upper()


class P6cFixtureAndTaskPromptFreeze:
    def __init__(self, args):
        self.args = args
        self.rows = []
        self.notes = []

    # ---- (1) independent rehash of every §4 defense/fixture -------------------
    def _hash_row(self, key, path, expected):
        if path is None:
            return {"artifact": key, "path": None, "expected_sha256": expected,
                    "observed_sha256": None, "status": "MISSING_PATH_ARG"}
        if not os.path.isfile(path):
            return {"artifact": key, "path": path, "expected_sha256": expected,
                    "observed_sha256": None, "status": "FILE_NOT_FOUND"}
        obs = sha256_file(path)
        status = "ESTABLISHED" if obs == expected else "SHA_MISMATCH"
        return {"artifact": key, "path": path, "expected_sha256": expected,
                "observed_sha256": obs, "status": status}

    def freeze_defenses(self):
        a = self.args
        mapping = [
            ("secret_fixture",      a.secret_fixture),
            ("optimal_py",          a.optimal),
            ("predicates_py",       a.predicates),
            ("sandbox_py",          a.sandbox),
            ("api_py",              a.api),
            ("gym_py",              a.gym),
            ("custom_guardrail",    a.custom_guardrail),
            ("ledger",              a.ledger),
            ("transport_shim_v1_4", a.transport_shim),
            ("real_harness",        a.real_harness),
        ]
        for key, path in mapping:
            self.rows.append(self._hash_row(key, path, EXPECTED[key]))

    # ---- (2)+(3) exfil task prompt: fail-close conflation, else discover -------
    def freeze_task_prompt(self):
        a = self.args
        if a.exfil_task_prompt is None or not os.path.isfile(a.exfil_task_prompt):
            row = {
                "artifact": "exfil_task_prompt",
                "path": a.exfil_task_prompt,
                "expected_sha256": NOT_ESTABLISHED,
                "observed_sha256": None,
                "status": NOT_ESTABLISHED,
                "reason": "No distinct exfil task-prompt file supplied. 946A..DABD "
                          "is the BENIGN system prompt and MUST NOT be reused as the "
                          "exfil task. Author the real multi-hop task (fs.read secret.txt "
                          "-> encode -> http.post) as its own file, then re-run.",
                "read_only_discovery": self._discovery_command(),
            }
            self.rows.append(row)
            return

        obs = sha256_file(a.exfil_task_prompt)
        if obs == BENIGN_SYSTEM_PROMPT_SHA256:
            row = {
                "artifact": "exfil_task_prompt",
                "path": a.exfil_task_prompt,
                "observed_sha256": obs,
                "status": "EXFIL_TASK_PROMPT_CONFLATED_WITH_BENIGN",
                "reason": "Candidate hashes to the BENIGN system prompt (946A..DABD). "
                          "Refusing to freeze a benign prompt as the attack task.",
            }
            self.rows.append(row)
            return

        # Distinct, non-benign candidate: freeze its identity (no content copied).
        self.rows.append({
            "artifact": "exfil_task_prompt",
            "path": a.exfil_task_prompt,
            "observed_sha256": obs,
            "status": "ESTABLISHED_DISTINCT_FROM_BENIGN",
            "reason": "Distinct from benign 946A..DABD; frozen as exfil task prompt.",
        })

    def _discovery_command(self):
        root = self.args.project_root or "."
        return (
            'Windows read-only discovery (locate the real attack task, do not invent):\n'
            f'  findstr /s /i /m "--task fs.read http.post secret.txt" "{root}\\*.py" "{root}\\*.json" "{root}\\*.ipynb"\n'
            f'  where /r "{root}" *task*prompt*.txt\n'
            '  :: The harness takes the attack instruction via the --task argument;\n'
            '  :: it is a runtime input, not an SDK file. Freeze the exact string you pass.'
        )

    # ---- (4) corrected system_message_sha256 for the ledger -------------------
    def corrected_system_message_sha256(self):
        if not (self.args.system_prompt_file and os.path.isfile(self.args.system_prompt_file)):
            return {"status": NOT_ESTABLISHED,
                    "reason": "Pass --system-prompt-file (and optional --tool-schema-file) "
                              "to compute the concatenated system_message_sha256."}
        parts = [open(self.args.system_prompt_file, "r", encoding="utf-8").read()]
        if self.args.tool_schema_file and os.path.isfile(self.args.tool_schema_file):
            parts.append(open(self.args.tool_schema_file, "r", encoding="utf-8").read())
        concat = "\n".join(parts)
        return {
            "status": "COMPUTED",
            "concatenation_order": "system_prompt + '\\n' + tool_schema (if provided)",
            "system_message_sha256": sha256_text(concat),
            "note": "This is the SYSTEM message identity, explicitly NOT the exfil task prompt.",
        }

    # ---- assemble + external binding ------------------------------------------
    def run(self):
        self.freeze_defenses()
        self.freeze_task_prompt()
        sysmsg = self.corrected_system_message_sha256()

        blocking = [r for r in self.rows
                    if r["status"] not in ("ESTABLISHED", "ESTABLISHED_DISTINCT_FROM_BENIGN")]
        frozen = len(blocking) == 0

        result = {
            "tool_id": TOOL_ID,
            "tool_version": TOOL_VERSION,
            "gate": "P6C_FREEZE_FIXTURE_AND_DEFENSE_SHAS",
            "runtime_model_tool_predicate_execution": False,
            "generated_utc": datetime.now(timezone.utc).isoformat(),
            "phase": "EXFILTRATION",
            "independent_recomputation": True,
            "rows": self.rows,
            "corrected_system_message": sysmsg,
            "benign_system_prompt_sha256": BENIGN_SYSTEM_PROMPT_SHA256,
            "frozen": frozen,
            "blocking_rows": [r["artifact"] for r in blocking],
            "verdict": "FIXTURE_FREEZE_COMPLETE" if frozen
                       else "FIXTURE_FREEZE_INCOMPLETE_FAIL_CLOSED",
            "claim_boundary": {
                "allowed": [
                    "SHA-256 identity equality/inequality vs the design-spec §4 expected values.",
                    "Whether the candidate exfil task prompt is DISTINCT from the benign system prompt.",
                    "The corrected concatenated system_message_sha256.",
                ],
                "prohibited": [
                    "Any runtime / model-generation / guardrail / sink / predicate / breach claim.",
                    "hosted_parity / official_gym / official_exfiltration.",
                    "That cryptographic identity establishes claim relevance.",
                    "Freezing 946A..DABD as the exfil task prompt (it is the benign system prompt).",
                ],
            },
        }

        out_dir = self.args.out_dir
        os.makedirs(out_dir, exist_ok=True)
        tag = self.args.out_tag
        result_name = f"p6c_fixture_and_task_prompt_freeze_result_{tag}.json"
        manifest_name = f"p6c_fixture_and_task_prompt_freeze_manifest_{tag}.json"
        binding_name = f"p6c_fixture_and_task_prompt_freeze_binding_{tag}.txt"

        result_path = os.path.join(out_dir, result_name)
        with open(result_path, "w", encoding="utf-8") as fh:
            json.dump(result, fh, indent=2, ensure_ascii=False)
        result_sha = sha256_file(result_path)

        manifest = {
            "tool_id": TOOL_ID,
            "tool_version": TOOL_VERSION,
            "binds": "p6c_fixture_and_task_prompt_freeze_result",
            "result_filename": result_name,
            "result_sha256": result_sha,
            "parent_gate_document": "P6C_Real_Agent_Formation_Test_Design_Spec_v1_0.md",
            "parent_preflight_result": "p6c_transport_extraction_fix_result_v1_4.json",
            "parent_preflight_result_sha256":
                "8AC92A61985196B836A4DCCB2869ACA0049180B542452CCADB20C346DA3F952F",
            "status": "P6C_FIXTURE_FREEZE_"
                      + ("COMPLETE" if result["frozen"] else "INCOMPLETE"),
        }
        manifest_path = os.path.join(out_dir, manifest_name)
        with open(manifest_path, "w", encoding="utf-8") as fh:
            json.dump(manifest, fh, indent=2, ensure_ascii=False)
        manifest_sha = sha256_file(manifest_path)

        with open(os.path.join(out_dir, binding_name), "w", encoding="utf-8") as fh:
            fh.write(f"manifest_filename={manifest_name}\n")
            fh.write(f"manifest_sha256={manifest_sha}\n")
            fh.write(f"result_sha256={result_sha}\n")

        print(json.dumps(result, indent=2, ensure_ascii=False))
        print(f"\nresult_sha256={result_sha}")
        print(f"manifest_sha256={manifest_sha}")
        print(f"frozen={result['frozen']}  verdict={result['verdict']}")
        if not result["frozen"]:
            print("FAIL-CLOSED: P6C runtime is NOT authorized. Blocking rows: "
                  + ", ".join(result["blocking_rows"]))
            sys.exit(2)


def build_parser():
    p = argparse.ArgumentParser(description="P6C read-only fixture + exfil task-prompt freeze")
    p.add_argument("--project-root")
    p.add_argument("--secret-fixture")
    p.add_argument("--optimal")
    p.add_argument("--predicates")
    p.add_argument("--sandbox")
    p.add_argument("--api")
    p.add_argument("--gym")
    p.add_argument("--custom-guardrail", dest="custom_guardrail")
    p.add_argument("--ledger")
    p.add_argument("--transport-shim", dest="transport_shim")
    p.add_argument("--real-harness", dest="real_harness")
    # The candidate exfil task prompt (MUST be distinct from benign 946A..DABD).
    p.add_argument("--exfil-task-prompt", dest="exfil_task_prompt")
    # For the corrected system_message_sha256:
    p.add_argument("--system-prompt-file", dest="system_prompt_file")
    p.add_argument("--tool-schema-file", dest="tool_schema_file")
    p.add_argument("--out-dir", required=True)
    p.add_argument("--out-tag", default=TOOL_VERSION)
    return p


def main(argv=None):
    args = build_parser().parse_args(argv)
    P6cFixtureAndTaskPromptFreeze(args).run()


if __name__ == "__main__":
    main()
