#!/usr/bin/env python3
# =============================================================================
# p8_live_fixture_check_v1_0.py
# -----------------------------------------------------------------------------
# PHASE:            P8 - Fixture Identity Closure (final live-file check)
# AUTHORIZED SCOPE: READ-ONLY confirmation that the runtime-load-bearing secret
#                   fixture exists in the LIVE fixtures_dir and matches its
#                   expected hash. Specifically:
#                     (1) resolve the live fixtures_dir using the SAME precedence
#                         documented for resolve_fixtures_dir() in
#                         aicomp_sdk/evaluation/ops.py, VALIDATING each candidate
#                         with the _validate_fixtures_dir rule (must contain
#                         file_seed/, web_corpus.json, mail_seed.json);
#                     (2) stat  <fixtures_dir>/file_seed/secret.txt  (the file
#                         ToolSuite copies to sandbox-root secret.txt);
#                     (3) SHA-256 it and compare to the expected P7 hash.
#
# IMPORTANT HONESTY NOTE (fail-closed reconstruction):
#   * This script does NOT import or execute any SDK code. resolve_fixtures_dir's
#     FULL body was never inspected — only its signature + the _validate_fixtures_dir
#     rule. So the resolver here is a FAITHFUL RE-IMPLEMENTATION of the documented
#     precedence, and every resolution step is reported with its evidence. If the
#     SDK's real precedence differs, pass --fixtures-dir explicitly to remove all
#     ambiguity (explicit arg is precedence #1 in the SDK anyway).
#
# READ-ONLY / FAIL-CLOSED CONTRACT:
#   * stat + hash only. Opens files 'rb'. NO writes, NO reruns, NO SDK import.
#   * Missing fixtures_dir / missing file_seed/secret.txt / hash mismatch ->
#     recorded as NOT_ESTABLISHED and forces a non-zero exit, so P8 cannot be
#     marked closed on an absent or drifted file.
# =============================================================================

import argparse
import datetime as _dt
import hashlib
import json
import os
import sys

SCRIPT_ID = "p8_live_fixture_check_v1_0"
SCRIPT_VERSION = "1.0"

# The runtime-scored secret content per P7 v1_2 manifest (file_seed family).
EXPECTED_SECRET_SHA256 = \
    "746aa20818152dcc585f78c4e8f93990a668aea0e060aa254d06502aeaa16fb8"

# _validate_fixtures_dir rule observed in evaluation/ops.py (L206-218):
# a valid fixtures_dir must contain these entries.
REQUIRED_FIXTURE_ENTRIES = ["file_seed", "web_corpus.json", "mail_seed.json"]

# The load-bearing relative path inside fixtures_dir (suite.py L50: fs_root =
# fixtures_dir / "file_seed"; then iterdir -> basename at sandbox root).
SECRET_REL_PATH = os.path.join("file_seed", "secret.txt")


def utc_now_iso():
    return _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def sha256_of_file(path, chunk=1 << 20):
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for block in iter(lambda: fh.read(chunk), b""):
            h.update(block)
    return h.hexdigest()


def validate_fixtures_dir(path):
    """Faithful re-implementation of _validate_fixtures_dir (ops.py L206-218):
    returns (is_valid, missing_entries)."""
    missing = []
    for entry in REQUIRED_FIXTURE_ENTRIES:
        full = os.path.join(path, entry)
        if entry.endswith(".json"):
            if not os.path.isfile(full):
                missing.append(entry)
        else:
            if not os.path.isdir(full):
                missing.append(entry + "/")
    return (len(missing) == 0), missing


def candidate_search(explicit, env_var, extra_candidates):
    """Resolve fixtures_dir by the documented precedence:
       1) explicit --fixtures-dir
       2) env var (AICOMP_FIXTURES_DIR by default)
       3) a list of default/likely candidates (user-supplied via --candidate)
    Each candidate is validated; the FIRST valid one wins. Every step recorded."""
    trail = []

    def consider(source, path):
        if not path:
            return None
        abspath = os.path.abspath(os.path.expanduser(path))
        present = os.path.isdir(abspath)
        valid, missing = (False, REQUIRED_FIXTURE_ENTRIES)
        if present:
            valid, missing = validate_fixtures_dir(abspath)
        trail.append({
            "source": source, "path": abspath, "present": present,
            "valid": valid, "missing": missing,
        })
        return abspath if (present and valid) else None

    winner = consider("explicit_arg", explicit)
    if winner:
        return winner, trail

    winner = consider(f"env:{env_var}", os.environ.get(env_var))
    if winner:
        return winner, trail

    for cand in (extra_candidates or []):
        winner = consider("candidate", cand)
        if winner:
            return winner, trail

    return None, trail


def main(argv=None):
    ap = argparse.ArgumentParser(
        description="P8 read-only live-fixture check: confirm "
                    "file_seed/secret.txt exists in the live fixtures_dir and "
                    "matches the expected hash. No SDK import, no writes.")
    ap.add_argument("--fixtures-dir", default=None,
                    help="Explicit fixtures_dir (precedence #1, same as the "
                         "SDK). If given and valid, resolution stops here.")
    ap.add_argument("--env-var", default="AICOMP_FIXTURES_DIR",
                    help="Env var name to consult (precedence #2).")
    ap.add_argument("--candidate", action="append", default=[],
                    help="Additional candidate fixtures_dir path(s) to try "
                         "(precedence #3). Repeatable. e.g. the SDK's default "
                         "packaged fixtures path.")
    ap.add_argument("--expected-sha256", default=EXPECTED_SECRET_SHA256,
                    help="Expected SHA-256 of file_seed/secret.txt "
                         "(default: 746aa208… from P7 v1_2).")
    ap.add_argument("--out-dir", default=os.getcwd())
    ap.add_argument("--tag", default="v1_0")
    args = ap.parse_args(argv)

    os.makedirs(args.out_dir, exist_ok=True)

    report = {
        "script_id": SCRIPT_ID, "script_version": SCRIPT_VERSION,
        "authorized_scope": "P8 read-only live-fixture existence + hash check",
        "read_only": True, "imported_sdk": False, "executed_sdk": False,
        "method": "stat + sha256; resolver is a faithful re-impl of "
                  "resolve_fixtures_dir precedence (SDK not executed)",
        "expected_secret_sha256": args.expected_sha256,
        "secret_rel_path": SECRET_REL_PATH,
        "started_utc": utc_now_iso(),
        "resolution_trail": [],
        "result": {},
        "gaps": [],
    }

    fixtures_dir, trail = candidate_search(
        args.fixtures_dir, args.env_var, args.candidate)
    report["resolution_trail"] = trail

    if fixtures_dir is None:
        report["result"] = {
            "fixtures_dir": None,
            "status": "NOT_ESTABLISHED_no_valid_fixtures_dir",
        }
        report["gaps"].append(
            "No valid fixtures_dir found (need file_seed/ + web_corpus.json + "
            "mail_seed.json). Pass --fixtures-dir or --candidate.")
    else:
        secret_path = os.path.join(fixtures_dir, SECRET_REL_PATH)
        res = {"fixtures_dir": fixtures_dir,
               "secret_path": os.path.abspath(secret_path)}
        if not os.path.isfile(secret_path):
            res["status"] = "NOT_ESTABLISHED_secret_missing"
            res["exists"] = False
            report["gaps"].append(
                f"{SECRET_REL_PATH} MISSING in resolved fixtures_dir "
                "-> P10 would hit fs.read not_found (guaranteed null).")
        else:
            res["exists"] = True
            res["size_bytes"] = os.path.getsize(secret_path)
            digest = sha256_of_file(secret_path)
            res["sha256"] = digest
            res["mtime_utc"] = _dt.datetime.fromtimestamp(
                os.path.getmtime(secret_path),
                _dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
            if digest == args.expected_sha256:
                res["status"] = "ESTABLISHED_present_and_hash_match"
                res["hash_match"] = True
            else:
                res["status"] = "NOT_ESTABLISHED_hash_mismatch"
                res["hash_match"] = False
                report["gaps"].append(
                    f"Hash mismatch: expected {args.expected_sha256[:16]}… "
                    f"got {digest[:16]}… -> fixture drift, do NOT proceed.")
        report["result"] = res

    report["finished_utc"] = utc_now_iso()
    canon = json.dumps({k: v for k, v in report.items()
                        if k != "manifest_sha256"},
                       sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    report["manifest_sha256"] = hashlib.sha256(canon.encode("utf-8")).hexdigest()

    out_json = os.path.join(args.out_dir,
                            f"p8_live_fixture_check_{args.tag}.json")
    with open(out_json, "w", encoding="utf-8") as fh:
        json.dump(report, fh, indent=2, ensure_ascii=False)

    # ---- console summary ----
    print("=" * 72)
    print(f"{SCRIPT_ID}  (READ-ONLY; no SDK import/exec)")
    print("=" * 72)
    print("Resolution trail (precedence order):")
    for t in trail:
        flag = ("VALID" if t["valid"] else
                ("present-but-invalid" if t["present"] else "absent"))
        print(f"  [{t['source']:<20}] {flag}")
        print(f"      {t['path']}")
        if t["present"] and not t["valid"]:
            print(f"      missing: {t['missing']}")
    print("-" * 72)
    r = report["result"]
    if r.get("fixtures_dir"):
        print(f"Resolved fixtures_dir : {r['fixtures_dir']}")
        print(f"Secret path           : {r.get('secret_path')}")
        print(f"Exists                : {r.get('exists')}")
        if r.get("exists"):
            print(f"Size                  : {r.get('size_bytes')} bytes")
            print(f"SHA-256               : {r.get('sha256')}")
            print(f"Expected              : {args.expected_sha256}")
            print(f"Hash match            : {r.get('hash_match')}")
        print(f"STATUS                : {r.get('status')}")
    else:
        print(f"STATUS                : {r.get('status')}")
    print("-" * 72)
    if report["gaps"]:
        print("GAPS:")
        for g in report["gaps"]:
            print(f"  - {g}")
    else:
        print("GAPS: none -> P8 fixture-identity fully CLOSED, P9 may open.")
    print("-" * 72)
    print(f"Report SHA-256 : {report['manifest_sha256']}")
    print(f"JSON report    : {out_json}")
    print("=" * 72)

    # Fail-closed exit: only a present + hash-matching secret returns 0.
    status = report["result"].get("status", "")
    return 0 if status == "ESTABLISHED_present_and_hash_match" else 2


if __name__ == "__main__":
    sys.exit(main())
