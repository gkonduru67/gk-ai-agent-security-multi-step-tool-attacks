#!/usr/bin/env python3
# =============================================================================
# redaction_policy_tool.py  (v1.1 -- placeholder-text detection)
# AI_AGENT_SECURITY -- Phase 1, Priority 0 helper (P6b redaction policy)
#
# CHANGELOG vs v1.0
# ------------------
#   v1.1: A real run came back with policy_text="..." -- almost certainly
#   an abbreviated example command's ellipsis, copy-pasted literally
#   rather than replaced with real policy text. The `define` subcommand
#   now flags (but does not block) suspiciously short/placeholder-looking
#   policy_text values -- "...", "", "TODO", "TBD", "N/A", or anything
#   under 20 characters -- both in the console output AND as an explicit
#   "policy_text_looks_like_placeholder" field in the written JSON, so
#   manifest_v1_generator.py's overlay merge can surface this too instead
#   of silently accepting policy_defined=true with meaningless text.
#
#   Also (from the same session): "scan" now distinguishes FILE_NOT_FOUND
#   errors that are EXPECTED (the draft simply hasn't been authored yet --
#   e.g. the Kaggle working note is phase_2_publication.output_1, which
#   doesn't exist until priority_0 through priority_6 are complete) from
#   any other error, with an explicit note so a missing file doesn't read
#   as a tooling failure.
#
# WHAT THIS SCRIPT DOES (unchanged from v1.0)
# ---------------------------------------------
# Your priority_0 rule says: "publish a redaction policy for the single
# real secret value referenced in P6b ... before any of that data appears
# in a publication draft." This is fundamentally a DECISION only you can
# make. This script has two stages:
#
#   STAGE 1 -- "define": describe the policy ONCE (method + placeholder
#     token + policy text). Does NOT require the secret value itself.
#
#   STAGE 2 -- "scan" / "apply": ENFORCES the policy against actual draft
#     files. The secret is NEVER accepted as a bare CLI argument (which
#     would leak into shell history / process listings). It must come
#     from an environment variable (default AICOMP_P6B_SECRET) or a local
#     one-line file via --secret-file (read once, never echoed, never
#     logged). "scan" is read-only. "apply" writes REDACTED COPIES
#     alongside originals -- originals are never modified.
#
# Run command examples:
#   # Stage 1 -- define the policy once:
#   python redaction_policy_tool.py define --method placeholder_token --placeholder "[REDACTED_P6B_SECRET]" --policy-text "The single real P6b secret value is never quoted verbatim in any publication draft; it is replaced with [REDACTED_P6B_SECRET] and referenced only by its role (protected-path read target), never its content."
#
#   # Stage 2 -- scan draft files (secret via a local file, safest on Windows):
#   python redaction_policy_tool.py scan --draft-file "kaggle_working_note_draft.md" --secret-file "C:\...\secret.txt"
#
#   # Stage 2b -- produce redacted copies for safe sharing/review:
#   python redaction_policy_tool.py apply --draft-file "kaggle_working_note_draft.md" --secret-file "C:\...\secret.txt" --output-suffix ".redacted"
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


PLACEHOLDER_LOOKALIKES = {"...", "..", ".", "", "todo", "tbd", "n/a", "na", "tbc", "xxx", "placeholder"}


def looks_like_placeholder_text(text):
    if text is None:
        return True
    stripped = text.strip()
    if stripped.lower() in PLACEHOLDER_LOOKALIKES:
        return True
    if len(stripped) < 20:
        return True
    return False


def cmd_define(args):
    is_placeholder = looks_like_placeholder_text(args.policy_text)
    policy = {
        "policy_defined": True,
        "method": args.method,
        "placeholder_token": args.placeholder,
        "policy_text": args.policy_text,
        "policy_text_looks_like_placeholder": is_placeholder,
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
    if is_placeholder:
        print("=" * 78)
        print("WARNING: policy_text ('{}') looks like a placeholder or example".format(args.policy_text))
        print("value, not a real policy statement (either empty, a bare ellipsis/")
        print("TODO-style marker, or under 20 characters). This has been WRITTEN")
        print("as-is (not blocked), but manifest_v1_generator.py's gaps report")
        print("will flag this file's policy as needing re-definition with real")
        print("text before it's treated as satisfying the priority_0 requirement.")
        print("=" * 78)
        print()
        print("Example of a real policy statement:")
        print('  --policy-text "The single real P6b secret value is never quoted')
        print('  verbatim in any publication draft; it is replaced with')
        print('  [REDACTED_P6B_SECRET] and referenced only by its role (protected-')
        print('  path read target), never its content."')
        print()
    print("Next: rerun manifest_v1_generator.py --redaction-policy-file {}".format(args.output))
    print("Then, before any draft is shared/submitted, run the 'scan' subcommand")
    print("against your draft files to confirm the secret does not appear unredacted.")
    return 1 if is_placeholder else 0


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
    any_file_not_found = False
    for r in results:
        if "error" in r:
            print("  [ERROR] {}: {}".format(r["path"], r["error"]))
            if r["error"] == "FILE_NOT_FOUND":
                any_file_not_found = True
            continue
        n = r["occurrences"]
        total_hits += n
        status = "CLEAN" if n == 0 else "FOUND {} OCCURRENCE(S) -- NOT SAFE TO PUBLISH AS-IS".format(n)
        print("  [{}] {}".format(status, r["path"]))
        for h in r.get("hits", []):
            print("      line {}: {}".format(h["line"], h["context_masked"]))
    print()
    print("Wrote full report: {}".format(os.path.abspath(args.output)))
    if any_file_not_found:
        print()
        print("NOTE: FILE_NOT_FOUND is expected/correct if that draft has not been")
        print("authored yet (e.g. the Kaggle working note is phase_2_publication.")
        print("output_1_kaggle_working_note -- it does not exist until you actually")
        print("write it, after priority_0 through priority_6 are complete). Re-run")
        print("this scan once the real draft file exists, pointed at its real path.")
    if total_hits > 0:
        print()
        print("RECOMMENDATION: run the 'apply' subcommand to generate redacted")
        print("copies before sharing/submitting these drafts.")
        return 1
    print()
    if not any_file_not_found:
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
    if policy.get("policy_text_looks_like_placeholder"):
        print("WARNING: the loaded policy's own policy_text looks like a placeholder")
        print("(see policy_text_looks_like_placeholder=true in {}).".format(args.policy_file))
        print("Proceeding with the redaction (placeholder_token is still valid), but")
        print("you should redefine the policy_text before citing this policy in any")
        print("publication draft.")
        print()

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
