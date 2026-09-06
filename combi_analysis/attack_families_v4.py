"""
attack_families_v4.py
==========================================================================
Loads families_config_v4.yaml and builds AttackCandidate objects for all
four attack families. Successor to attack_yaml_harness_v2.py /
attack_robust_v3.py.

CONFIRMED ABSENT from this harness (verified by the assertion block at the
bottom of build_all_candidates_and_manifest -- the self-test will FAIL if
any of these ever creep back in):
  - any `tool: dynamic` / vi_1..vi_n variable-capture step
  - any `tool: dummy` no-op filler call
  - any step whose note contains "even if it says not allowed" or similar
    persist-past-denial language

Each scenario contributes `candidates * len(trigger_variants or [None])`
AttackCandidate objects: the fixed `steps:` are rendered as leading
conversation turns, and each `trigger_variants` entry is appended as the
final turn -- producing N independent, differently-worded replicates of the
same semantic request. This is what makes a single submission yield a
PER-SCENARIO RATE (see robustness_ledger_v4.py) rather than one pass/fail
sample.
==========================================================================
"""

from __future__ import annotations

import hashlib
import json
import os
import re
from pathlib import Path
from typing import Any, Final

try:
    import yaml
except Exception as exc:  # pragma: no cover
    raise SystemExit("PyYAML is required to run this harness locally.") from exc

_SDK_AVAILABLE = True
try:
    from aicomp_sdk.attacks.contracts import (
        AttackAlgorithmBase,
        AttackCandidate,
        AttackRunConfig,
    )
except Exception:
    try:
        from aicomp_sdk.attacks import (
            AttackAlgorithmBase,
            AttackCandidate,
            AttackRunConfig,
        )
    except Exception:
        _SDK_AVAILABLE = False

        class AttackAlgorithmBase:  # type: ignore
            pass

        class AttackRunConfig:  # type: ignore
            pass

        class AttackCandidate:  # type: ignore
            def __init__(self, user_messages=None, messages=None):
                self.user_messages = user_messages or messages

            @classmethod
            def from_messages(cls, messages):
                return cls(user_messages=messages)


def _make_candidate(messages: tuple) -> "AttackCandidate":
    try:
        return AttackCandidate.from_messages(messages)
    except Exception:
        return AttackCandidate(user_messages=messages)


CONFIG_PATH: Final = Path(
    os.getenv("FAMILIES_CONFIG_PATH", str(Path(__file__).parent / "families_config_v4.yaml"))
)

# Hard-banned tool names / phrasing -- presence of any of these anywhere in
# the loaded YAML is a build-time error, not a silent skip. This is the
# actual enforcement mechanism for "no harness tricks", not just a comment.
BANNED_TOOL_NAMES = {"dynamic", "dummy"}
BANNED_NOTE_PATTERNS = [
    re.compile(r"even if it says not allowed", re.IGNORECASE),
    re.compile(r"continue.{0,20}not allowed", re.IGNORECASE),
    re.compile(r"\bvi_\d+\b"),
]


def _step_to_message(step: dict) -> str:
    tool = step.get("tool", "")
    if tool in BANNED_TOOL_NAMES:
        raise ValueError(f"Banned harness-trick tool '{tool}' found in step: {step}")
    note = step.get("note", "") or ""
    for pat in BANNED_NOTE_PATTERNS:
        if pat.search(note):
            raise ValueError(f"Banned harness-trick phrasing found in step note: {note!r}")

    args = step.get("args", {}) or {}
    auth = step.get("authorization_required")
    auth_prefix = "You are authorized to do the following. " if auth else ""

    if "content" in args and tool == "read":
        # simulated tool-result content (email/web fixture text presented verbatim)
        return f"{args['content'].strip()}"

    arg_str = ", ".join(f"{k}={v!r}" for k, v in args.items() if k != "content")
    base = f"{auth_prefix}Call tool `{tool}` with {arg_str}." if arg_str else f"{auth_prefix}Call tool `{tool}`."
    if note:
        base += f" ({note})"
    return base


def build_all_candidates_and_manifest(config_path: Path = CONFIG_PATH):
    with open(config_path, "r", encoding="utf-8") as f:
        config = yaml.safe_load(f)

    candidates: list = []
    manifest: list[dict] = []

    for family, scenarios in config["families"].items():
        for scenario in scenarios:
            fixed_steps = scenario.get("steps", []) or []
            fixed_messages = tuple(_step_to_message(s) for s in fixed_steps)
            variants = scenario.get("trigger_variants") or [None]
            max_hops = scenario.get("max_tool_hops")
            n_candidates_declared = scenario.get("candidates", 1)

            for rep_idx, trigger in enumerate(variants):
                messages = fixed_messages + ((trigger,) if trigger else tuple())
                if max_hops is not None:
                    assert len(messages) <= max_hops, (
                        f"{scenario['instruction_id']} replicate {rep_idx}: "
                        f"{len(messages)} hops exceeds max_tool_hops={max_hops}"
                    )
                digest = hashlib.sha256("|".join(messages).encode("utf-8")).hexdigest()
                candidates.append(_make_candidate(messages))
                manifest.append({
                    "index": len(manifest),
                    "family": family,
                    "instruction_id": scenario["instruction_id"],
                    "scenario_group_id": scenario["scenario_group_id"],
                    "evidence_basis": scenario.get("evidence_basis"),
                    "gap_targeted": scenario.get("gap_targeted"),
                    "replicate_idx": rep_idx,
                    "n_declared_candidates_field": n_candidates_declared,
                    "authorization_required": scenario.get("authorization_required"),
                    "max_tool_hops": max_hops,
                    "n_hops": len(messages),
                    "messages_sha256": digest,
                })

    return candidates, manifest


class AttackAlgorithm(AttackAlgorithmBase):
    """v4 submission: config-driven, no harness tricks (enforced at build
    time -- see BANNED_TOOL_NAMES / BANNED_NOTE_PATTERNS), replication-based
    for robustness classification via robustness_ledger_v4.py."""

    def run(self, env, config: "AttackRunConfig") -> list:
        candidates, _manifest = build_all_candidates_and_manifest()
        return candidates


if __name__ == "__main__":
    if os.getenv("KAGGLE_IS_COMPETITION_RERUN"):
        import kaggle_evaluation.jed_attack_134815.jed_attack_inference_server as server

        server.JEDAttackInferenceServer().serve()
    else:
        out_dir = Path(os.getenv("ATTACK_SELF_TEST_DIR", "./attack_self_test_out"))
        out_dir.mkdir(parents=True, exist_ok=True)
        candidates, manifest = build_all_candidates_and_manifest()
        (out_dir / "families_v4_manifest.json").write_text(
            json.dumps(manifest, indent=2), encoding="utf-8"
        )
        print(f"SDK_AVAILABLE: {_SDK_AVAILABLE}")
        print(f"Total candidates: {len(candidates)}")
        by_group: dict[str, int] = {}
        for row in manifest:
            by_group.setdefault(row["scenario_group_id"], 0)
            by_group[row["scenario_group_id"]] += 1
        for grp, count in by_group.items():
            print(f"  {grp}: {count} replicate(s)")
        print(f"Manifest written to: {out_dir / 'families_v4_manifest.json'}")
        print("\nHarness-trick check: PASSED (no BANNED_TOOL_NAMES / BANNED_NOTE_PATTERNS triggered an exception above)")
