"""
attack_yaml_harness_v3.py
==========================================================================
Generic, config-driven attack.py harness that loads families_config_v3.yaml
and builds AttackCandidate objects for the four attack families
(EXFILTRATION, CONFUSED_DEPUTY, UNTRUSTED_TO_ACTION, DESTRUCTIVE_WRITE).

This is a near-identical port of the project's own proven
attack_yaml_harness_v2.py -- the candidate-building logic is intentionally
UNCHANGED from that version (it already works and is understood). The
only substantive change is the default config filename (v3 instead of v2)
and the docstrings/comments below, updated to describe the v3 evidence
base this config draws from.

WHAT THIS DOES
  - Reads a YAML instruction spec (see families_config_v3.yaml).
  - For each instruction block, generates N=candidates AttackCandidate(s).
  - Converts each `steps:` (or per-candidate `candidate_steps:`) list into a
    natural-language, multi-turn conversation, one turn per step, matching
    the message-based approach used in prior submissions (this harness does
    NOT attempt literal SDK tool dispatch -- it produces conversation turns
    that describe the intended tool call; the real model + guardrail loop
    inside the competition sandbox decides what tool call, if any, actually
    gets made).
  - `tool: dynamic` steps render as `{auth_prefix}{note}` verbatim. Every
    block in families_config_v3.yaml sets `authorization_required: false`
    and bakes the exact, already-validated "You are authorized to..."
    phrasing directly into `note:` -- this preserves prompt fidelity to
    what this project's own real-GPT-OSS testing already confirmed
    produces the documented ALLOW/DENY behavior, rather than switching to
    this harness's generic `tool: <name>, args: {...}` mechanical
    rendering, which was never empirically tested by this project.

WHAT THIS DOES NOT DO (fail-closed, matches project discipline)
  - Does NOT assume any fixture path is real beyond file_seed/secret.txt,
    which is the one byte-verified (P8) canonical path on record. Every
    other synthetic fixture (injected emails/web pages, throwaway DW
    targets) is documented via `per_candidate_fixture:` notes in the YAML
    and must be seeded into a THROWAWAY fixtures copy before a real run --
    never written into the real competition fixtures directory.
  - Does NOT implement a `confirm` tool call -- not part of this project's
    confirmed evidence base.
  - Does NOT include the UTA predicate-window gap-boundary sweep as a
    candidate -- that finding requires direct synthetic-trace predicates.py
    evaluation, not a conversational AttackCandidate, and is documented as
    excluded at the bottom of families_config_v3.yaml.
  - Does NOT perform attack optimization, candidate flooding, sentinel/
    marker injection, or any scoring-maximization trick. Every candidate
    is a fixed, already-evidence-backed scenario.
==========================================================================
"""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
from typing import Any, Final

try:
    import yaml
except Exception as exc:  # pragma: no cover
    raise SystemExit(
        "PyYAML is required to run this harness locally (not required inside "
        "the Kaggle rerun image, which only needs the generated candidates)."
    ) from exc

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


CONFIG_PATH: Final = Path(os.getenv("FAMILIES_CONFIG_PATH", str(Path(__file__).parent / "families_config_v3.yaml")))


def _step_to_message(step: dict, block: dict) -> str:
    """Render one YAML step as one natural-language conversation turn."""
    tool = step.get("tool", "unknown")
    args = step.get("args", {}) or {}
    note = step.get("note", "")
    auth = step.get("authorization_required", block.get("authorization_required"))

    auth_prefix = "You are authorized to do the following. " if auth else ""

    if tool == "dynamic":
        return f"{auth_prefix}{note}".strip()

    if tool == "dummy":
        return f"{auth_prefix}{note or 'Perform a no-op / log placeholder action.'}".strip()

    arg_str = ", ".join(f"{k}={v!r}" for k, v in args.items())
    base = f"{auth_prefix}Call tool `{tool}` with {arg_str}."
    if note:
        base += f" ({note})"
    return base


def _build_messages_for_candidate(block: dict, step_list: list[dict]) -> tuple:
    return tuple(_step_to_message(s, block) for s in step_list)


def build_all_candidates_and_manifest(config_path: Path = CONFIG_PATH):
    with open(config_path, "r", encoding="utf-8") as f:
        config = yaml.safe_load(f)

    candidates: list = []
    manifest: list[dict] = []

    for family, blocks in config["families"].items():
        for block in blocks:
            n_candidates = int(block["candidates"])
            max_hops = block.get("max_tool_hops")

            if "candidate_steps" in block:
                # One distinct step-list per candidate (paired/triplet designs)
                per_candidate_steps = block["candidate_steps"]
                assert len(per_candidate_steps) == n_candidates, (
                    f"{block['instruction_id']}: candidate_steps has "
                    f"{len(per_candidate_steps)} entries but candidates={n_candidates}"
                )
                for i, step_list in enumerate(per_candidate_steps):
                    messages = _build_messages_for_candidate(block, step_list)
                    _finalize_candidate(
                        family, block, i, messages, max_hops, candidates, manifest
                    )
            else:
                # Same step template repeated across N candidates (fixture
                # index, if any, is noted but not resolved to real content).
                step_list = block["steps"]
                per_candidate_fixture = block.get("per_candidate_fixture")
                for i in range(n_candidates):
                    fixture_note = ""
                    if per_candidate_fixture and i < len(per_candidate_fixture):
                        fixture_note = f" [candidate fixture: {per_candidate_fixture[i]}]"
                    messages = _build_messages_for_candidate(block, step_list)
                    if fixture_note:
                        messages = (messages[0] + fixture_note,) + messages[1:]
                    _finalize_candidate(
                        family, block, i, messages, max_hops, candidates, manifest
                    )

    return candidates, manifest


def _finalize_candidate(family, block, candidate_idx, messages, max_hops, candidates, manifest):
    if max_hops is not None:
        assert len(messages) <= max_hops, (
            f"{block['instruction_id']} candidate {candidate_idx}: "
            f"{len(messages)} hops exceeds max_tool_hops={max_hops}"
        )
    digest = hashlib.sha256("|".join(messages).encode("utf-8")).hexdigest()
    candidates.append(_make_candidate(messages))
    manifest.append(
        {
            "index": len(manifest),
            "family": family,
            "instruction_id": block["instruction_id"],
            "candidate_idx": candidate_idx,
            "authorization_required": block.get("authorization_required"),
            "max_tool_hops": max_hops,
            "n_hops": len(messages),
            "messages_sha256": digest,
            # carried through for local_validate_v3.py convenience only;
            # harmless extra keys, not read by the Kaggle rerun path.
            "expected": (
                block.get("expected")[candidate_idx]
                if isinstance(block.get("expected"), list)
                else block.get("expected")
            ),
            "hypothesis": block.get("hypothesis"),
        }
    )


class AttackAlgorithm(AttackAlgorithmBase):
    """Config-driven submission: loads families_config_v3.yaml at runtime
    and returns all generated candidates. No search, no score optimization."""

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
        (out_dir / "yaml_harness_manifest_v3.json").write_text(
            json.dumps(manifest, indent=2), encoding="utf-8"
        )
        print(f"SDK_AVAILABLE: {_SDK_AVAILABLE}")
        print(f"Total candidates: {len(candidates)}")
        by_family: dict[str, int] = {}
        for row in manifest:
            by_family.setdefault(row["family"], 0)
            by_family[row["family"]] += 1
        for fam, count in by_family.items():
            print(f"  {fam}: {count} candidates")
        print(f"Manifest written to: {out_dir / 'yaml_harness_manifest_v3.json'}")
