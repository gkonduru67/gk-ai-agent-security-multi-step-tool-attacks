#!/usr/bin/env python3
r"""
agent_discovery_v2.py
==========================================================================
Successor to agent_discovery_v1.py. That script confirmed GPTOSSAgent
exists but requires a `backend: HFGenerationBackendProtocol` argument, NOT
a direct `server_url` kwarg. This script finds the concrete backend
implementation (or confirms none exists and shows you the interface you'd
need to implement).

WHAT THIS DOES (read-only, no model calls, no fixture writes)
  1. Recursively walks the ENTIRE aicomp_sdk package tree (not just
     aicomp_sdk/agents/, which was v1's narrower scope) using
     pkgutil.walk_packages.
  2. For every module found, lists every class defined directly in it, and
     flags any whose name or constructor parameters suggest it is an HTTP/
     backend/client implementation (name contains Backend/HF/Llama/Client/
     Http/Server; or constructor params contain url/host/port/endpoint).
  3. Specifically locates HFGenerationBackendProtocol itself (wherever it
     is defined) and prints its declared method signatures -- this tells
     you the exact interface a backend object must satisfy, which is
     useful evidence even if no ready-made concrete class exists.
  4. Also locates HFModelProfile and HFResponseParser (the other two
     GPTOSSAgent constructor params) the same way, since a full working
     construction likely needs all three.

Usage:
  python agent_discovery_v2.py --project-root "C:\...\ai-agent-security-multi-step-tool-attacks"
==========================================================================
"""

from __future__ import annotations

import argparse
import importlib
import inspect
import pkgutil
import sys
import traceback
from pathlib import Path
from typing import Any


BACKEND_NAME_HINTS = ["backend", "hf", "llama", "client", "http", "server", "openai", "harmony"]
CONSTRUCTOR_ARG_HINTS = ["url", "host", "port", "endpoint", "base_url", "server_url", "model_path", "model_name"]

TARGET_INTERFACE_NAMES = ["HFGenerationBackendProtocol", "HFModelProfile", "HFResponseParser"]


def describe_signature(obj: Any) -> str:
    try:
        return str(inspect.signature(obj))
    except (ValueError, TypeError) as exc:
        return f"<could not introspect: {exc}>"


def is_protocol_like(cls: type) -> bool:
    """Heuristic: a bare (self, *args, **kwargs) __init__ with no other
    declared body typically indicates a typing.Protocol / ABC interface
    definition rather than a concrete, instantiable implementation."""
    try:
        sig = inspect.signature(cls.__init__)
        params = list(sig.parameters.values())
        # self, *args, **kwargs pattern
        return (
            len(params) >= 1
            and any(p.kind == inspect.Parameter.VAR_POSITIONAL for p in params)
            and any(p.kind == inspect.Parameter.VAR_KEYWORD for p in params)
        )
    except (ValueError, TypeError):
        return False


def walk_all_modules(package_name: str) -> list[str]:
    """Return every importable submodule name under package_name, walking
    recursively. Import errors for individual submodules are recorded but
    do not stop the walk."""
    module_names = []
    try:
        package = importlib.import_module(package_name)
    except Exception as exc:
        print(f"FATAL: could not import root package '{package_name}': {type(exc).__name__}: {exc}")
        return module_names

    if not hasattr(package, "__path__"):
        return [package_name]

    for finder, name, ispkg in pkgutil.walk_packages(package.__path__, prefix=package_name + "."):
        module_names.append(name)
    return module_names


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--project-root", required=True)
    ap.add_argument("--root-package", default="aicomp_sdk",
                     help="Top-level package to walk recursively (default: aicomp_sdk)")
    args = ap.parse_args()

    project_root = Path(args.project_root).resolve()
    sys.path.insert(0, str(project_root))

    print("=" * 70)
    print(f"Walking every submodule under '{args.root_package}' ...")
    print("=" * 70)
    module_names = walk_all_modules(args.root_package)
    print(f"Found {len(module_names)} submodules.\n")

    all_classes: dict[str, dict[str, Any]] = {}
    import_failures = []

    for mod_name in module_names:
        try:
            mod = importlib.import_module(mod_name)
        except Exception as exc:
            import_failures.append({"module": mod_name, "error": f"{type(exc).__name__}: {exc}"})
            continue

        for attr_name in dir(mod):
            if attr_name.startswith("_"):
                continue
            obj = getattr(mod, attr_name)
            if inspect.isclass(obj) and obj.__module__ == mod_name:
                key = f"{mod_name}.{attr_name}"
                all_classes[key] = {"module": mod_name, "class_name": attr_name, "obj": obj}

    print("=" * 70)
    print("PART 1: Candidate backend/client implementations")
    print("=" * 70)
    found_candidates = False
    for key, info in sorted(all_classes.items()):
        cls = info["obj"]
        name_hit = any(h in info["class_name"].lower() for h in BACKEND_NAME_HINTS)
        try:
            sig = inspect.signature(cls.__init__)
            param_names = [p.lower() for p in sig.parameters]
            arg_hit = any(any(h in p for h in CONSTRUCTOR_ARG_HINTS) for p in param_names)
        except (ValueError, TypeError):
            arg_hit = False
            param_names = []

        if name_hit or arg_hit:
            found_candidates = True
            protocol_like = is_protocol_like(cls)
            print(f"\n  {key}" + ("  [PROTOCOL-LIKE -- likely NOT directly instantiable]" if protocol_like else "  [CONCRETE -- likely instantiable]"))
            print(f"    __init__{describe_signature(cls.__init__)}")
            if arg_hit:
                matched_args = [p for p in param_names if any(h in p for h in CONSTRUCTOR_ARG_HINTS)]
                print(f"    -> constructor args suggesting HTTP/endpoint config: {matched_args}")

    if not found_candidates:
        print("\n  No classes matched the name/argument heuristics anywhere in the package tree.")
        print("  This suggests the backend may need to be constructed via a FACTORY FUNCTION")
        print("  rather than a class -- re-run with --show-all-functions if this script")
        print("  supported it, or manually grep the codebase for 'HFGenerationBackendProtocol'")
        print("  usages / 'llama_server' / '127.0.0.1' / 'localhost' string literals.")

    print("\n" + "=" * 70)
    print("PART 2: Direct lookup of the 3 target interfaces GPTOSSAgent needs")
    print("=" * 70)
    for target_name in TARGET_INTERFACE_NAMES:
        matches = [(k, v) for k, v in all_classes.items() if v["class_name"] == target_name]
        if not matches:
            print(f"\n  {target_name}: NOT FOUND anywhere in the walked package tree.")
            continue
        for key, info in matches:
            cls = info["obj"]
            print(f"\n  {key}")
            print(f"    __init__{describe_signature(cls.__init__)}")
            # If it's a Protocol, print its declared abstract/expected methods
            methods = [
                m for m in dir(cls)
                if not m.startswith("_") and callable(getattr(cls, m, None))
            ]
            if methods:
                print(f"    Declared methods (interface it expects a real implementation to provide): {methods}")
                for m in methods:
                    try:
                        msig = inspect.signature(getattr(cls, m))
                        print(f"      .{m}{msig}")
                    except (ValueError, TypeError):
                        pass

    if import_failures:
        print("\n" + "=" * 70)
        print(f"NOTE: {len(import_failures)} submodule(s) failed to import (often optional "
              "dependencies like transformers/torch -- usually safe to ignore unless one "
              "of them is clearly backend-related):")
        print("=" * 70)
        for f in import_failures[:20]:
            print(f"  {f['module']}: {f['error']}")
        if len(import_failures) > 20:
            print(f"  ... and {len(import_failures) - 20} more")

    print("\n" + "=" * 70)
    print("NEXT STEP")
    print("=" * 70)
    print(
        "If Part 1 found a CONCRETE class (not protocol-like) with an HTTP-style "
        "constructor argument, that is very likely the backend to construct and "
        "pass as GPTOSSAgent(backend=<that_instance>). If Part 1 found nothing "
        "concrete, Part 2's interface listing tells you exactly what methods a "
        "minimal custom adapter would need to implement to talk to your running "
        "llama-server at http://127.0.0.1:8080 (likely its OpenAI-compatible "
        "/v1/chat/completions or native /completion endpoint)."
    )


if __name__ == "__main__":
    main()
