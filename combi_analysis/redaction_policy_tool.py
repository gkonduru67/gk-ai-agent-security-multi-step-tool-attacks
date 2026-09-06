#!/usr/bin/env python3
# =============================================================================
# redaction_policy_tool.py
# AI_AGENT_SECURITY -- Phase 1, Priority 0 helper (P6b redaction policy)
#
# WHAT "NEEDS TO BE DONE" HERE, IN PLAIN TERMS
# ---------------------------------------------
# Your priority_0 rule says: "publish a redaction policy for the single
# real secret value referenced in P6b ... before any of that data appears
# in a publication draft." This is fundamentally a DECISION only you can
# make -- e.g. "replace the literal secret with the token [REDACTED_P6B]
# in all published material" or "never quote the value verbatim; describe
# it only as 'a synthetic API-key-shaped string'". No script can choose
# that policy for you.
#
# What this script DOES do, in two stages:
#
#   STAGE 1 -- "define": you describe the policy ONCE (method + placeholder
#     token + policy text). This does NOT require the secret value itself
#     -- defining a policy is a statement of INTENT, not an application of
#     it. Writes redaction_policy_v1.json, mergeable into manifest_v1 via
#     manifest_v1_generator.py --redaction-policy-file.
#
#   STAGE 2 -- "scan" / "apply": ENFORCES the policy you already defined,
#     against actual draft files, at the point the real secret value IS
#     needed (to search for it). Design choices to keep this safe:
#       - The secret is NEVER accepted as a bare CLI argument (which would
#         leak into shell history / process listings on most systems).
#         It must come from an environment variable (default name
#         AICOMP_P6B_SECRET) or a local one-line file you point to with
#         --secret-file (read once, never echoed, never logged).
#       - This script never prints the secret value itself anywhere --
#         not in console output, not in the JSON report. Matches are
#         reported by file+line+redacted-context only.
#       - "scan" is read-only: it reports where the secret appears, it
#         does not touch your files.
#       - "apply" is opt-in and additive: it writes REDACTED COPIES next
#         to (not overwriting) your original draft files, with every
#         occurrence of the secret replaced by your chosen placeholder
#         token. Originals are never modified, per the same read-only
#         guarantee used elsewhere in this project's tooling.
#
# Run command examples:
#   # Stage 1 -- define the policy once:
#   python redaction_policy_tool.py define ^
#       --method placeholder_token --placeholder "[REDACTED_P6B_SECRET]" ^
#       --policy-text "The single real P6b secret value is never quoted verbatim in any publication draft; it is replaced with [REDACTED_P6B_SECRET] and referenced only by its role (protected-path read target), never its content."
#
#   # Stage 2 -- scan draft files before submission (secret via env var):
#   set AICOMP_P6B_SECRET=the-actual-secret-value        (PowerShell: $env:AICOMP_P6B_SECRET="...")
#   python redaction_policy_tool.py scan --draft-file "kaggle_working_note_draft.md" --draft-file "ieee_manuscript_draft.tex"
#
#   # Stage 2b -- produce redacted copies for safe sharing/review:
#   python redaction_policy_tool.py apply --draft-file "kaggle_working_note_draft.md" --output-suffix ".redacted"
# =============================================================================

import os
import sys
import json
import argparse
import datetime


def utc_now():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def win_long_path(p):
    if os.name != "nt":
        return p
    if p.startswith("\\\\?\\"):
        return p
    if p.startswith("\\\\"):
        return "\\\\?\\UNC\\" + p.lstrip("\\")
    return "\\\\?\\" + p


def cmd_define(args):
    policy = {
        "policy_defined": True,
        "method": args.method,
        "placeholder_token": args.placeholder,
        "policy_text": args.policy_text,
        "defined_at_utc": utc_now(),
        "notes": (
            "Defined via redaction_policy_tool.py define. This record contains "
            "NO secret material -- only the policy statement. To ENFORCE this "
            "policy against actual draft files, run: "
            "redaction_policy_tool.py scan / apply (secret supplied only via "
            "environment variable or a local file, never as a bare CLI arg)."
        ),
    }
    with open(args.output, "w", encoding="utf-8") as f:
        json.dump(policy, f, indent=2)
    print("Wrote policy definition: {}".format(os.path.abspath(args.output)))
    print()
    print("Policy method:      {}".format(args.method))
    print("Placeholder token:  {}".format(args.placeholder))
    print("Policy text:        {}".format(args.policy_text))
    print()
    print("Next: rerun manifest_v1_generator.py --redaction-policy-file {}".format(args.output))
    print("Then, before any draft is shared/submitted, run the 'scan' subcommand")
    print("against your draft files to confirm the secret does not appear unredacted.")
    return 0


def _load_secret(args):
    if args.secret_file:
        if not os.path.isfile(win_long_path(args.secret_file)):
            print("ERROR: --secret-file not found: {}".format(args.secret_file))
            return None
        with open(win_long_path(args.secret_file), "r", encoding="utf-8") as f:
            val = f.read().strip()
        if not val:
            print("ERROR: --secret-file is empty.")
            return None
        return val
    env_val = os.environ.get(args.secret_env_var)
    if env_val:
        return env_val
    print("ERROR: no secret provided. Set the {} environment variable, or pass --secret-file.".format(args.secret_env_var))
    print("(The secret is intentionally never accepted as a bare --secret CLI argument,")
    print(" to avoid it leaking into shell history or process listings.)")
    return None


def _redact_for_display(text, secret):
    """Never print the raw secret anywhere -- even in an error/context
    snippet. Returns text with the secret masked."""
    if not secret:
        return text
    return text.replace(secret, "<SECRET-REDACTED-FOR-DISPLAY>")


def cmd_scan(args):
    secret = _load_secret(args)
    if not secret:
        return 2

    results = []
    for path in args.draft_file:
        if not os.path.isfile(win_long_path(path)):
            results.append({"path": path, "error": "FILE_NOT_FOUND"})
            continue
        hits = []
        try:
            with open(win_long_path(path), "r", encoding="utf-8", errors="replace") as f:
                for lineno, line in enumerate(f, start=1):
                    if secret in line:
                        # report a masked context snippet only -- never the raw secret
                        masked = _redact_for_display(line.rstrip("\n"), secret)
                        hits.append({"line": lineno, "context_masked": masked})
        except OSError as e:
            results.append({"path": path, "error": str(e)})
            continue
        results.append({"path": path, "occurrences": len(hits), "hits": hits})

    report = {
        "generated_at_utc": utc_now(),
        "note": "Secret value itself is never included in this report -- occurrences shown as masked context only.",
        "results": results,
    }
    with open(args.output, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)

    print("=" * 78)
    print("P6B REDACTION SCAN (read-only -- no files modified)")
    print("=" * 78)
    total_hits = 0
    for r in results:
        if "error" in r:
            print("  [ERROR] {}: {}".format(r["path"], r["error"]))
            continue
        n = r["occurrences"]
        total_hits += n
        status = "CLEAN" if n == 0 else "FOUND {} OCCURRENCE(S) -- NOT SAFE TO PUBLISH AS-IS".format(n)
        print("  [{}] {}".format(status, r["path"]))
        for h in r.get("hits", []):
            print("      line {}: {}".format(h["line"], h["context_masked"]))
    print()
    print("Wrote full report: {}".format(os.path.abspath(args.output)))
    if total_hits > 0:
        print()
        print("RECOMMENDATION: run the 'apply' subcommand to generate redacted")
        print("copies before sharing/submitting these drafts.")
        return 1
    print()
    print("No unredacted occurrences found in the scanned file(s).")
    return 0


def cmd_apply(args):
    secret = _load_secret(args)
    if not secret:
        return 2

    if not os.path.isfile(win_long_path(args.policy_file)):
        print("ERROR: policy file not found: {} -- run 'define' first.".format(args.policy_file))
        return 2
    with open(win_long_path(args.policy_file), "r", encoding="utf-8") as f:
        policy = json.load(f)
    placeholder = policy.get("placeholder_token")
    if not placeholder:
        print("ERROR: policy file has no placeholder_token defined.")
        return 2

    written = []
    for path in args.draft_file:
        if not os.path.isfile(win_long_path(path)):
            print("  [SKIP] {} -- not found".format(path))
            continue
        with open(win_long_path(path), "r", encoding="utf-8", errors="replace") as f:
            content = f.read()
        n_occurrences = content.count(secret)
        redacted_content = content.replace(secret, placeholder)
        out_path = path + args.output_suffix
        with open(out_path, "w", encoding="utf-8") as f:
            f.write(redacted_content)
        written.append({"original": path, "redacted_copy": out_path, "occurrences_replaced": n_occurrences})
        print("  [OK] {} -> {} ({} occurrence(s) replaced)".format(path, out_path, n_occurrences))

    print()
    print("Originals were NOT modified. Redacted copies written alongside them.")
    return 0


def main():
    parser = argparse.ArgumentParser(description="Define and enforce the P6b real-secret redaction policy.")
    sub = parser.add_subparsers(dest="command", required=True)

    p_define = sub.add_parser("define", help="Write the redaction policy definition (no secret material needed).")
    p_define.add_argument("--method", required=True, choices=["placeholder_token", "description_only", "hash_reference"])
    p_define.add_argument("--placeholder", default="[REDACTED_P6B_SECRET]")
    p_define.add_argument("--policy-text", required=True)
    p_define.add_argument("--output", default="redaction_policy_v1.json")
    p_define.set_defaults(func=cmd_define)

    p_scan = sub.add_parser("scan", help="Read-only scan of draft files for unredacted secret occurrences.")
    p_scan.add_argument("--draft-file", action="append", required=True, dest="draft_file")
    p_scan.add_argument("--secret-env-var", default="AICOMP_P6B_SECRET")
    p_scan.add_argument("--secret-file", default=None)
    p_scan.add_argument("--output", default="p6b_redaction_scan_report.json")
    p_scan.set_defaults(func=cmd_scan)

    p_apply = sub.add_parser("apply", help="Write redacted copies of draft files (originals untouched).")
    p_apply.add_argument("--draft-file", action="append", required=True, dest="draft_file")
    p_apply.add_argument("--secret-env-var", default="AICOMP_P6B_SECRET")
    p_apply.add_argument("--secret-file", default=None)
    p_apply.add_argument("--policy-file", default="redaction_policy_v1.json")
    p_apply.add_argument("--output-suffix", default=".redacted")
    p_apply.set_defaults(func=cmd_apply)

    args = parser.parse_args()
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
