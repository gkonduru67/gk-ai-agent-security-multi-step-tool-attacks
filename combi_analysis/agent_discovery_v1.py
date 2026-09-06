#!/usr/bin/env python3
r"""
agent_discovery_v1.py  (P8.1 support -- run this FIRST, before v2 of the
predicate verifier)
==========================================================================
Answers, with zero guessing: "what agent classes exist in aicomp_sdk/agents,
and what does SandboxEnv.__init__ actually require for its `agent` argument?"

This directly targets the TypeError from your last run:
  SandboxEnv.__init__() missing 1 required positional argument: 'agent'

WHAT THIS DOES (read-only, no model calls, no fixture writes)
  1. Uses `inspect.signature()` on SandboxEnv.__init__ to print its EXACT
     real parameter list, defaults, and annotations -- not the static-
     contract-document's paraphrase.
  2. Walks aicomp_sdk/agents/*.py and, for every class found, prints its
     __init__ signature too -- so you can see which one plausibly accepts
     a server_url / model_path / endpoint kwarg pointing at your running
     llama-server (http://127.0.0.1:8080).
  3. Does NOT attempt to instantiate anything or call the model. This is
     pure introspection, safe to run any number of times.

Usage:
  python agent_discovery_v1.py --project-root "C:\...\ai-agent-security-multi-step-tool-attacks"
==========================================================================
"""

from __future__ import annotations

import argparse
import importlib
import inspect
import pkgutil
import sys
from pathlib import Path
from typing import Any


def describe_signature(obj: Any) -> str:
    try:
        return str(inspect.signature(obj))
    except (ValueError, TypeError) as exc:
        return f"<could not introspect: {exc}>"


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--project-root", required=True)
    ap.add_argument("--agents-subdir", default="aicomp_sdk/agents",
                     help="Relative path to the agents directory (default: aicomp_sdk/agents)")
    args = ap.parse_args()

    project_root = Path(args.project_root).resolve()
    sys.path.insert(0, str(project_root))

    print("=" * 70)
    print("PART 1: SandboxEnv.__init__ real signature")
    print("=" * 70)
    try:
        from aicomp_sdk.core.env.sandbox import SandboxEnv
        sig = inspect.signature(SandboxEnv.__init__)
        print(f"SandboxEnv.__init__{sig}")
        print()
        print("Parameter details:")
        for name, param in sig.parameters.items():
            if name == "self":
                continue
            default = "REQUIRED (no default)" if param.default is inspect.Parameter.empty else repr(param.default)
            annotation = param.annotation if param.annotation is not inspect.Parameter.empty else "<no type hint>"
            print(f"  - {name}: default={default}, annotation={annotation}")
    except Exception as exc:
        print(f"FAILED to import/introspect SandboxEnv: {type(exc).__name__}: {exc}")

    print()
    print("=" * 70)
    print(f"PART 2: Classes found under {args.agents_subdir}")
    print("=" * 70)
    agents_dir = project_root / args.agents_subdir
    if not agents_dir.is_dir():
        print(f"FAILED: {agents_dir} does not exist or is not a directory.")
        return

    agents_package = args.agents_subdir.replace("/", ".").replace("\\", ".")
    py_files = sorted(agents_dir.glob("*.py"))
    if not py_files:
        print(f"No .py files found directly under {agents_dir}")
        return

    for py_file in py_files:
        if py_file.name == "__init__.py":
            continue
        module_name = f"{agents_package}.{py_file.stem}"
        print(f"\n--- {py_file.name} (module: {module_name}) ---")
        try:
            mod = importlib.import_module(module_name)
        except Exception as exc:
            print(f"  FAILED to import: {type(exc).__name__}: {exc}")
            continue

        found_any_class = False
        for attr_name in dir(mod):
            if attr_name.startswith("_"):
                continue
            obj = getattr(mod, attr_name)
            if inspect.isclass(obj) and obj.__module__ == module_name:
                found_any_class = True
                print(f"  class {attr_name}:")
                print(f"    __init__{describe_signature(obj.__init__)}")
                # Flag any parameter name that looks like it wants an endpoint/model path
                try:
                    sig = inspect.signature(obj.__init__)
                    endpoint_like = [
                        p for p in sig.parameters
                        if any(k in p.lower() for k in ("server", "url", "endpoint", "model", "host", "port"))
                    ]
                    if endpoint_like:
                        print(f"    -> LIKELY connects to an external model/server via: {endpoint_like}")
                except Exception:
                    pass
        if not found_any_class:
            print("  (no classes defined directly in this module)")

    print()
    print("=" * 70)
    print("NEXT STEP")
    print("=" * 70)
    print(
        "Look for a class above whose __init__ accepts something like "
        "server_url / base_url / endpoint / host+port, and note its exact "
        "name and required arguments. Pass that back so predicate_verify_v2 "
        "can be wired to instantiate it pointed at http://127.0.0.1:8080."
    )


if __name__ == "__main__":
    main()
