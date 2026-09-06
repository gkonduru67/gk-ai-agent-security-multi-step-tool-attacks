"""
robustness_ledger_v4.py
==========================================================================
Local, offline tool for classifying whether a hosted-scored scenario
constitutes a ROBUST security finding, or just a single observation.
Companion to attack_families_v4.py / families_config_v4.yaml.

WHY THIS EXISTS
  Hosted feedback from the competition grader is score-only -- no per-step
  trace. A single submission's score for a scenario_group_id is Tier-A-
  equivalent evidence in this project's own vocabulary: real, single-sample,
  not yet robust. This tool tracks scores for the SAME scenario_group_id
  across MULTIPLE, INDEPENDENT submissions and only classifies a finding as
  robust once repeated observations agree -- mirroring the project's own
  Tier A -> Tier B evidence discipline (real single sample -> frozen/
  repeated replay), applied here to hosted scenarios instead of local runs.

CLASSIFICATION STATUSES
  - NOT_ESTABLISHED: zero observations recorded.
  - SINGLE_SAMPLE: exactly one observation. Real, but not yet robust.
  - REPLICATED_CONSISTENT: >=2 independent observations, all non-null,
    within CONSISTENCY_BAND of each other. Strongest status assignable --
    means the RATE is stable across independent hosted runs. Does NOT by
    itself establish causal mechanism (guardrail failure vs. model
    compliance tendency) -- that ambiguity from score-only feedback is
    unresolved by replication and must be stated separately.
  - CONSISTENTLY_NULL: >=2 independent observations, all at/below
    NULL_THRESHOLD. A robust NEGATIVE result -- scientifically valid,
    reported as such (mirrors this project's PROVABLY_INAPPLICABLE framing
    for the EXFILTRATION lineage-ledger finding).
  - INCONSISTENT: >=2 observations that disagree beyond the consistency
    band. Flagged for MORE replicates, not resolved into a claim.

USAGE
  python robustness_ledger_v4.py record \
      --scenario-group-id exfil_real_corpus_chain_v4 \
      --submission-label "2026-08-28-combined-run1" \
      --n-candidates 3 \
      --score 0.10 \
      --note "combined submission across all 10 v4 scenario groups"

  python robustness_ledger_v4.py classify
==========================================================================
"""

from __future__ import annotations

import argparse
import json
import os
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Final

LEDGER_PATH: Final = Path(os.getenv("ROBUSTNESS_LEDGER_PATH", "./robustness_ledger_v4.json"))

NULL_THRESHOLD: Final = 0.02
CONSISTENCY_BAND: Final = 3.0


@dataclass
class Observation:
    scenario_group_id: str
    submission_label: str
    n_candidates: int
    score: float
    observed_rate: float
    note: str = ""
    recorded_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


def _load_ledger() -> list[dict]:
    if LEDGER_PATH.exists():
        return json.loads(LEDGER_PATH.read_text(encoding="utf-8"))
    return []


def _save_ledger(records: list[dict]) -> None:
    LEDGER_PATH.write_text(json.dumps(records, indent=2), encoding="utf-8")


def record_observation(scenario_group_id: str, submission_label: str, n_candidates: int,
                        score: float, note: str = "") -> Observation:
    observed_rate = score / n_candidates if n_candidates > 0 else 0.0
    obs = Observation(
        scenario_group_id=scenario_group_id,
        submission_label=submission_label,
        n_candidates=n_candidates,
        score=score,
        observed_rate=observed_rate,
        note=note,
    )
    records = _load_ledger()
    records.append(asdict(obs))
    _save_ledger(records)
    return obs


def classify_scenario_group(observations: list[dict]) -> dict:
    n = len(observations)
    rates = [o["observed_rate"] for o in observations]

    if n == 0:
        return {"status": "NOT_ESTABLISHED", "n_observations": 0, "rates": []}

    if n == 1:
        return {
            "status": "SINGLE_SAMPLE",
            "n_observations": 1,
            "rates": rates,
            "interpretation": (
                "Exactly one hosted observation. Equivalent to Tier A (real, "
                "single-sample) evidence in this project's own vocabulary -- "
                "real, but not yet robust. Submit at least one more "
                "independent replicate/day before treating this rate as reliable."
            ),
        }

    nulls = [r <= NULL_THRESHOLD for r in rates]
    if all(nulls):
        return {
            "status": "CONSISTENTLY_NULL",
            "n_observations": n,
            "rates": rates,
            "interpretation": (
                "All independent observations are at/below the null threshold. "
                "This IS a robust finding -- a reliable negative result. Do not "
                "read this as 'guardrail proven effective' without hosted "
                "trace evidence -- it may equally reflect model non-compliance "
                "with the scenario's instructions. State both possibilities."
            ),
        }

    if any(nulls) and not all(nulls):
        return {
            "status": "INCONSISTENT",
            "n_observations": n,
            "rates": rates,
            "interpretation": (
                "Observations disagree: at least one null and at least one "
                "non-null rate. NOT classified as robust in either direction. "
                "Needs more independent replicates."
            ),
        }

    lo, hi = min(rates), max(rates)
    ratio = hi / lo if lo > 0 else float("inf")
    if ratio <= CONSISTENCY_BAND:
        return {
            "status": "REPLICATED_CONSISTENT",
            "n_observations": n,
            "rates": rates,
            "ratio": ratio,
            "interpretation": (
                f"All {n} independent observations are non-null and within "
                f"{CONSISTENCY_BAND}x of each other (ratio={ratio:.2f}). "
                "Strongest status this tool assigns: a robust, repeatable "
                "non-zero rate across independent hosted runs. Does NOT "
                "establish causal mechanism (guardrail failure vs. model "
                "compliance) -- only that the rate itself is stable."
            ),
        }
    else:
        return {
            "status": "INCONSISTENT",
            "n_observations": n,
            "rates": rates,
            "ratio": ratio,
            "interpretation": (
                f"All observations are non-null but vary by {ratio:.2f}x, "
                f"exceeding the {CONSISTENCY_BAND}x consistency band. Not yet "
                "stable enough to call robust. Needs more replicates."
            ),
        }


def classify_all() -> dict[str, dict]:
    records = _load_ledger()
    by_group: dict[str, list[dict]] = {}
    for r in records:
        by_group.setdefault(r["scenario_group_id"], []).append(r)
    return {group: classify_scenario_group(obs) for group, obs in by_group.items()}


def _print_classification(results: dict[str, dict]) -> None:
    if not results:
        print("No observations recorded yet. Use the 'record' command first.")
        return
    for group, result in results.items():
        print(f"\n=== {group} ===")
        print(f"  status: {result['status']}")
        print(f"  n_observations: {result['n_observations']}")
        print(f"  rates: {[round(r, 4) for r in result.get('rates', [])]}")
        if "ratio" in result:
            print(f"  ratio (max/min): {result['ratio']:.2f}")
        print(f"  interpretation: {result['interpretation']}")


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command", required=True)

    rec = sub.add_parser("record", help="Record one hosted observation for a scenario_group_id.")
    rec.add_argument("--scenario-group-id", required=True)
    rec.add_argument("--submission-label", required=True)
    rec.add_argument("--n-candidates", type=int, required=True)
    rec.add_argument("--score", type=float, required=True)
    rec.add_argument("--note", default="")

    sub.add_parser("classify", help="Classify robustness for all recorded scenario_group_ids.")

    args = parser.parse_args()

    if args.command == "record":
        obs = record_observation(
            scenario_group_id=args.scenario_group_id,
            submission_label=args.submission_label,
            n_candidates=args.n_candidates,
            score=args.score,
            note=args.note,
        )
        print(f"Recorded: {json.dumps(asdict(obs), indent=2)}")
        print(f"\nLedger now at: {LEDGER_PATH.resolve()}")

    elif args.command == "classify":
        results = classify_all()
        _print_classification(results)


if __name__ == "__main__":
    main()
