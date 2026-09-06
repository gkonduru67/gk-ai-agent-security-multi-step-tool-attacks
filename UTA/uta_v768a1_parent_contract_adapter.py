#!/usr/bin/env python3
"""Compatibility adapter for UTA v7.68A.1 targeted replay.

Exports analysis constants/functions from the frozen v7.68A parent runner and
agent/trace contract helpers from the frozen v7.67A.1 runner. This corrects the
matrix-wide HARNESS_RUNTIME failure caused by incorrectly assuming that the
v7.68A parent module itself exported ScriptedAgent.
"""
from __future__ import annotations
import hashlib, importlib.util, json, sys
from pathlib import Path

ADAPTER_VERSION = "UTA_v7.68A.1_PARENT_CONTRACT_ADAPTER_1"
HERE = Path(__file__).resolve().parent
PARENT_PATH = HERE / "uta_three_guardrail_history_matrix_v7_68A.py"
CONTRACT_PATH = HERE / "uta_sb_spacer_contract_ana_corr_v7_67A_1.py"


def _sha(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest().upper()


def _load(path: Path, name: str):
    if not path.is_file():
        raise FileNotFoundError(f"Required frozen module not found: {path}")
    spec = importlib.util.spec_from_file_location(name, path)
    if not spec or not spec.loader:
        raise ImportError(path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


_parent = _load(PARENT_PATH, "uta_v768a1_frozen_parent_impl")
_contract = _load(CONTRACT_PATH, "uta_v768a1_frozen_contract_impl")

# Frozen experiment semantics and analyzer come from v7.68A.
PROMPTS = _parent.PROMPTS
SPACER_PATH = _parent.SPACER_PATH
SPACER_CONTENT = _parent.SPACER_CONTENT
SOURCE_ID = _parent.SOURCE_ID
MARKER = _parent.MARKER
TARGET = _parent.TARGET
EXPECTED_NAMES = _parent.EXPECTED_NAMES
analyze = _parent.analyze
semantic_response = _parent.semantic_response

# Agent construction and Sandbox trace adaptation come from v7.67A.1, where
# these contracts were actually defined and previously runtime validated.
ScriptedAgent = _contract.ScriptedAgent
find_trace = _contract.find_trace
set_env_agent = _contract.set_env_agent

ADAPTER_PREFLIGHT = {
    "adapter_version": ADAPTER_VERSION,
    "adapter_file": str(Path(__file__).resolve()),
    "adapter_sha256": _sha(Path(__file__).resolve()),
    "frozen_parent_file": str(PARENT_PATH),
    "frozen_parent_sha256": _sha(PARENT_PATH),
    "frozen_contract_file": str(CONTRACT_PATH),
    "frozen_contract_sha256": _sha(CONTRACT_PATH),
    "exports": {
        "ScriptedAgent": f"{ScriptedAgent.__module__}.{ScriptedAgent.__qualname__}",
        "find_trace": f"{find_trace.__module__}.{find_trace.__qualname__}",
        "set_env_agent": f"{set_env_agent.__module__}.{set_env_agent.__qualname__}",
        "analyze": f"{analyze.__module__}.{analyze.__qualname__}",
        "semantic_response": f"{semantic_response.__module__}.{semantic_response.__qualname__}",
    },
}

# Fail before matrix entry if the adapter surface is incomplete.
_REQUIRED = (
    "ScriptedAgent", "find_trace", "set_env_agent", "analyze",
    "semantic_response", "PROMPTS", "SPACER_PATH", "SPACER_CONTENT"
)
for _name in _REQUIRED:
    if _name not in globals() or globals()[_name] is None:
        raise RuntimeError(f"Compatibility adapter missing required export: {_name}")
