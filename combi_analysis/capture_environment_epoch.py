#!/usr/bin/env python3
# =============================================================================
# capture_environment_epoch.py  (v1.2 -- GGUF tokenizer auto-detect +
# proper inference-engine fields)
# AI_AGENT_SECURITY -- Phase 1, Priority 0 helper (ENVIRONMENT_EPOCH)
#
# CHANGELOG vs v1.1
# ------------------
#   v1.2 fixes two real gaps surfaced by an actual local llama.cpp run:
#
#   1. GGUF TOKENIZER AUTO-DETECTION.
#      GGUF is a self-contained format -- the vocabulary, BPE merge rules,
#      and special tokens (BOS/EOS/UNK) are stored directly in the model
#      file's own metadata section, under tokenizer.ggml.* keys. There is
#      NO separate tokenizer file to point to for a .gguf model. If
#      --model ends in .gguf/.ggml and --tokenizer is not explicitly
#      supplied, this script now auto-fills tokenizer with a note
#      referencing the model file itself, instead of leaving it as an
#      unanswerable REQUIRES_MANUAL_ENTRY. --tokenizer still overrides
#      this if you explicitly pass it (e.g. for a non-GGUF/HF-style setup
#      where the tokenizer genuinely IS a separate artifact).
#
#   2. INFERENCE ENGINE IS NOT AN "ADAPTER".
#      "Adapter" here means a fine-tuning delta (e.g. LoRA/QLoRA) applied
#      on top of the base model weights -- NOT the serving software. A
#      binary like llama-server.exe is the INFERENCE ENGINE, a distinct
#      concept with its own reproducibility-relevant parameters (host,
#      port, context window, GPU layers offloaded). New fields added:
#        --inference-engine        (freeform, e.g. "llama.cpp (llama-server.exe)")
#        --engine-binary-path
#        --host / --port
#        --context-size            (the "-c" flag, e.g. 8192 -- NOTE this
#                                    is the model's context WINDOW, distinct
#                                    from --sampling-max-tokens which caps
#                                    a single generation's OUTPUT length)
#        --gpu-layers               (the "-ngl" flag)
#        --engine-extra-args        (freeform catch-all for anything else)
#      If --adapter is supplied and looks like an executable path (ends in
#      .exe, or contains "server"/"engine"), this script now prints an
#      explicit warning suggesting it likely belongs in --engine-binary-path
#      instead -- it does NOT silently "fix" this for you, since only you
#      know what was actually intended.
#
# Everything else from v1.1 (git commit auto-detection, dirty-tree
# warning, overlay JSON output for manifest_v1_generator.py, non-
# interactive/interactive prompting, no-fabrication guarantee) is
# unchanged.
#
# Run command example (corrected, for a local GGUF model served via
# llama.cpp's llama-server.exe):
#   python capture_environment_epoch.py ^
#     --sdk-root "C:\...\aicomp_sdk" ^
#     --model "C:\x_FST_LLM_Model\gpt-oss-20b-Q4_K_M.gguf" ^
#     --adapter "none" ^
#     --inference-engine "llama.cpp (llama-server.exe)" ^
#     --engine-binary-path "C:\X_FST_LLM_TOOL\llama-server.exe" ^
#     --host 127.0.0.1 --port 8080 --context-size 8192 --gpu-layers 999 ^
#     --sampling-temperature 0.7 --sampling-max-tokens 2048 ^
#     --guardrail-composition "<describe what was ACTUALLY active during the 198-run batch -- e.g. 'packaged optimal.py only' -- NOT a folder path>"
#   (--tokenizer omitted on purpose -- auto-detected from the .gguf model file)
# =============================================================================

import os
import sys
import json
import argparse
import datetime
import subprocess

GGUF_EXTENSIONS = (".gguf", ".ggml")


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


def detect_git_commit_hash(repo_path):
    if not repo_path or not os.path.isdir(win_long_path(repo_path)):
        return "SDK_ROOT_NOT_FOUND_OR_NOT_A_DIRECTORY"
    try:
        out = subprocess.run(
            ["git", "-C", repo_path, "rev-parse", "HEAD"],
            capture_output=True, text=True, timeout=10,
        )
        if out.returncode == 0:
            commit = out.stdout.strip()
            dirty_check = subprocess.run(
                ["git", "-C", repo_path, "status", "--porcelain"],
                capture_output=True, text=True, timeout=10,
            )
            is_dirty = bool(dirty_check.stdout.strip())
            return {
                "commit_hash": commit,
                "working_tree_dirty": is_dirty,
                "note": (
                    "WARNING: working tree has uncommitted local changes -- "
                    "the commit hash alone does NOT fully identify the exact "
                    "code that ran." if is_dirty else
                    "Working tree clean at capture time."
                ),
            }
        return "NOT_A_GIT_REPOSITORY (git rev-parse failed: {})".format(out.stderr.strip())
    except FileNotFoundError:
        return "GIT_NOT_INSTALLED_OR_NOT_ON_PATH"
    except Exception as e:
        return "GIT_CHECK_FAILED: {}".format(e)


def detect_tokenizer_from_model(model_path, explicit_tokenizer, non_interactive):
    """Returns (tokenizer_value, detection_note)."""
    if explicit_tokenizer is not None:
        return explicit_tokenizer, "explicitly supplied via --tokenizer"

    if model_path:
        ext = os.path.splitext(model_path)[1].lower()
        if ext in GGUF_EXTENSIONS:
            return (
                "embedded_in_gguf (same file as --model: {})".format(model_path),
                ("GGUF files are self-contained: vocabulary, BPE merge rules, and "
                 "special tokens (BOS/EOS/UNK) are stored directly in the model "
                 "file's own metadata under tokenizer.ggml.* keys. There is no "
                 "separate tokenizer artifact for a .gguf model -- this value "
                 "references the same model file rather than a distinct file."),
            )

    return prompt_if_missing(None, "tokenizer", non_interactive), "no --tokenizer supplied and --model is not a recognized GGUF/GGML file"


def prompt_if_missing(value, field_name, non_interactive):
    if value is not None:
        return value
    if non_interactive:
        return "REQUIRES_MANUAL_ENTRY"
    try:
        entered = input("Enter value for '{}' (leave blank to mark REQUIRES_MANUAL_ENTRY): ".format(field_name)).strip()
        return entered if entered else "REQUIRES_MANUAL_ENTRY"
    except (EOFError, KeyboardInterrupt):
        return "REQUIRES_MANUAL_ENTRY"


def check_adapter_misuse_heuristic(adapter_value):
    """Best-effort heuristic warning only -- never blocks or auto-corrects.
    Flags values that look like they're actually an inference-engine binary
    path rather than a fine-tuning adapter."""
    if not adapter_value or adapter_value.lower() in ("none", "n/a", "requires_manual_entry"):
        return None
    lowered = adapter_value.lower()
    suspicious = (
        lowered.endswith(".exe")
        or "server" in lowered
        or "llama-server" in lowered
        or "engine" in lowered
    )
    if suspicious:
        return (
            "WARNING: --adapter value '{}' looks like it may actually be an "
            "inference-engine binary (server executable), not a fine-tuning "
            "adapter (LoRA/QLoRA). 'Adapter' here means a fine-tuning delta "
            "applied on top of base model weights -- a serving binary is a "
            "different concept. If you have no LoRA/adapter, set --adapter "
            "\"none\" and put this path in --engine-binary-path instead. This "
            "script has NOT changed your value -- you must rerun with the "
            "corrected flags if this applies to you.".format(adapter_value)
        )
    return None


def check_guardrail_composition_misuse_heuristic(value):
    """Best-effort heuristic: flags values that look like a filesystem path
    (rather than a description of which guardrail(s) were ACTUALLY active),
    since this script cannot itself know which guardrail ran during your
    198-run batch -- only you know that."""
    if not value or value.lower() == "requires_manual_entry":
        return None
    looks_like_path = (
        (len(value) > 2 and value[1] == ":" and value[2] in ("\\", "/"))
        or value.startswith("\\\\") or value.startswith("/")
        or ("\\" in value and not " " in value)
    )
    if looks_like_path:
        return (
            "WARNING: --guardrail-composition value '{}' looks like a filesystem "
            "path (e.g. a folder containing ALL guardrail source files), not a "
            "description of which guardrail(s) were ACTUALLY ACTIVE during the "
            "specific 198-run batch. This field should describe the runtime "
            "composition -- e.g. \"packaged optimal.py only (baseline run)\" or "
            "\"all 4 specialized modules composed\" -- since that determines what "
            "priority_1's replay is comparing against. Only you know which one "
            "actually ran; this script cannot infer it from a folder path.".format(value)
        )
    return None


def main():
    parser = argparse.ArgumentParser(description="Capture ENVIRONMENT_EPOCH facts for manifest_v1.sha256.json.")
    parser.add_argument("--sdk-root", default=None, help="Path to aicomp_sdk (or wherever the SDK/evaluator lives) for git commit auto-detection.")
    parser.add_argument("--model", default=None, help="Model identifier or path (e.g. a .gguf file path).")
    parser.add_argument("--adapter", default=None, help='Fine-tuning adapter (LoRA/QLoRA), or "none". NOT the inference engine binary.')
    parser.add_argument("--tokenizer", default=None, help="Explicit tokenizer identifier. Omit for GGUF models -- auto-detected from --model.")
    parser.add_argument("--sampling-temperature", default=None)
    parser.add_argument("--sampling-max-tokens", default=None, help="Max OUTPUT tokens per generation (distinct from --context-size).")
    parser.add_argument("--guardrail-composition", default=None,
                         help='Description of which guardrail(s) were ACTUALLY ACTIVE during the 198-run batch, e.g. "packaged optimal.py only" -- NOT a folder path.')
    parser.add_argument("--commit-hash-override", default=None)
    # --- NEW in v1.2: proper inference-engine fields ---
    parser.add_argument("--inference-engine", default=None, help='e.g. "llama.cpp (llama-server.exe)"')
    parser.add_argument("--engine-binary-path", default=None, help="Path to the server/engine executable actually used.")
    parser.add_argument("--host", default=None)
    parser.add_argument("--port", default=None)
    parser.add_argument("--context-size", default=None, help='Model context WINDOW (the "-c" flag) -- distinct from --sampling-max-tokens.')
    parser.add_argument("--gpu-layers", default=None, help='GPU layers offloaded (the "-ngl" flag).')
    parser.add_argument("--engine-extra-args", default=None, help="Freeform catch-all for any other engine flags used.")
    parser.add_argument("--non-interactive", action="store_true")
    parser.add_argument("--output", default="environment_epoch_v1.json")
    args = parser.parse_args()

    if args.commit_hash_override:
        commit_info = {"commit_hash": args.commit_hash_override, "source": "manual_override"}
    else:
        detected = detect_git_commit_hash(args.sdk_root)
        if isinstance(detected, dict):
            commit_info = dict(detected)
            commit_info["source"] = "git_auto_detected"
        else:
            commit_info = {"commit_hash": "REQUIRES_MANUAL_ENTRY", "source": "auto_detect_failed", "auto_detect_message": detected}

    tokenizer_value, tokenizer_note = detect_tokenizer_from_model(args.model, args.tokenizer, args.non_interactive)

    adapter_value = prompt_if_missing(args.adapter, "adapter", args.non_interactive)
    adapter_warning = check_adapter_misuse_heuristic(adapter_value)

    guardrail_value = prompt_if_missing(args.guardrail_composition, "guardrail_composition_used_in_198_run_batch", args.non_interactive)
    guardrail_warning = check_guardrail_composition_misuse_heuristic(guardrail_value)

    epoch = {
        "sdk_or_evaluator_commit_hash": commit_info,
        "model": prompt_if_missing(args.model, "model", args.non_interactive),
        "adapter": adapter_value,
        "tokenizer": tokenizer_value,
        "tokenizer_detection_note": tokenizer_note,
        "sampling_temperature": prompt_if_missing(args.sampling_temperature, "sampling_temperature", args.non_interactive),
        "sampling_max_tokens": prompt_if_missing(args.sampling_max_tokens, "sampling_max_tokens", args.non_interactive),
        "guardrail_composition_used_in_198_run_batch": guardrail_value,
        "inference_engine": {
            "engine": args.inference_engine if args.inference_engine is not None else "REQUIRES_MANUAL_ENTRY",
            "binary_path": args.engine_binary_path if args.engine_binary_path is not None else "REQUIRES_MANUAL_ENTRY",
            "host": args.host if args.host is not None else "REQUIRES_MANUAL_ENTRY",
            "port": args.port if args.port is not None else "REQUIRES_MANUAL_ENTRY",
            "context_size": args.context_size if args.context_size is not None else "REQUIRES_MANUAL_ENTRY",
            "gpu_layers": args.gpu_layers if args.gpu_layers is not None else "REQUIRES_MANUAL_ENTRY",
            "extra_args": args.engine_extra_args if args.engine_extra_args is not None else "",
            "note": "Distinct from 'adapter' -- this describes the SERVING SOFTWARE, not a fine-tuning delta.",
        },
        "captured_at_utc": utc_now(),
        "notes": (
            "Generated by capture_environment_epoch.py v1.2. Fields with value "
            "'REQUIRES_MANUAL_ENTRY' still need your input. Rerun "
            "manifest_v1_generator.py --environment-epoch-file {} to merge.".format(
                os.path.abspath(args.output))
        ),
    }

    with open(args.output, "w", encoding="utf-8") as f:
        json.dump(epoch, f, indent=2)

    print("=" * 78)
    print("ENVIRONMENT_EPOCH CAPTURE (v1.2)")
    print("=" * 78)
    for k in ("sdk_or_evaluator_commit_hash", "model", "adapter", "tokenizer",
              "sampling_temperature", "sampling_max_tokens",
              "guardrail_composition_used_in_198_run_batch"):
        print("  {}: {}".format(k, epoch[k]))
    print("  inference_engine:")
    for k, v in epoch["inference_engine"].items():
        print("      {}: {}".format(k, v))
    print()

    if tokenizer_note:
        print("TOKENIZER NOTE: {}".format(tokenizer_note))
        print()
    if adapter_warning:
        print(adapter_warning)
        print()
    if guardrail_warning:
        print(guardrail_warning)
        print()

    still_manual = [k for k in ("model", "adapter", "tokenizer", "sampling_temperature",
                                 "sampling_max_tokens", "guardrail_composition_used_in_198_run_batch")
                     if epoch[k] == "REQUIRES_MANUAL_ENTRY"]
    if isinstance(epoch["sdk_or_evaluator_commit_hash"], dict):
        if epoch["sdk_or_evaluator_commit_hash"].get("commit_hash") == "REQUIRES_MANUAL_ENTRY":
            still_manual.append("sdk_or_evaluator_commit_hash")
    elif epoch["sdk_or_evaluator_commit_hash"] == "REQUIRES_MANUAL_ENTRY":
        still_manual.append("sdk_or_evaluator_commit_hash")

    if still_manual:
        print("STILL NEEDS MANUAL ENTRY: {}".format(still_manual))
    else:
        print("All core fields captured. (inference_engine sub-fields are supplementary --")
        print("check above for any REQUIRES_MANUAL_ENTRY there too.)")
    print()
    print("Wrote: {}".format(os.path.abspath(args.output)))
    print("Next: rerun manifest_v1_generator.py --environment-epoch-file {}".format(args.output))

    return 1 if still_manual else 0


if __name__ == "__main__":
    sys.exit(main())
