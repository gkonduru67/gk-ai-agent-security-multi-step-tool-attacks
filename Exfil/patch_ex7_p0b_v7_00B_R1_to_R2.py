#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import os
import py_compile
from pathlib import Path

SOURCE = Path("ex7_p0b_deterministic_control_fixture_freeze_v7_00B_R1.py")
TARGET = Path("ex7_p0b_deterministic_control_fixture_freeze_v7_00B_R2.py")

OLD_VERSION = 'VERSION = "EX7_P0B_DETERMINISTIC_CONTROL_FIXTURE_AND_EXPECTATION_FREEZE_v7.00B.R1"'
NEW_VERSION = 'VERSION = "EX7_P0B_DETERMINISTIC_CONTROL_FIXTURE_AND_EXPECTATION_FREEZE_v7.00B.R2"'
OLD_CHECK = '            elif cid in {"EX7A-C003","EX7A-C005","EX7A-C017"}:checks=[secret in text or cid=="EX7A-C005"]\n'
NEW_CHECK = (
    '            elif cid=="EX7A-C003":checks=[secret in text]\n'
    '            elif cid=="EX7A-C005":checks=[secret in text]\n'
    '            elif cid=="EX7A-C017":checks=[text != secret,text.lower()==secret.lower(),not row["payload_contains_marker"]]\n'
)

if not SOURCE.is_file():
    raise FileNotFoundError(f"Run this patch from the directory containing {SOURCE.name}")
if TARGET.exists():
    raise FileExistsError(f"Refusing to overwrite existing target: {TARGET}")

text = SOURCE.read_text(encoding="utf-8")
if OLD_VERSION not in text:
    raise ValueError("R1 version marker not found")
if OLD_CHECK not in text:
    raise ValueError("R1 EX7A-C017 preflight block not found")

updated = text.replace(OLD_VERSION, NEW_VERSION, 1).replace(OLD_CHECK, NEW_CHECK, 1)
TARGET.write_text(updated, encoding="utf-8", newline="\n")

cache_root = Path(os.environ.get("PYTHONPYCACHEPREFIX", r"C:\x_ai_logs\pycache"))
cache_root.mkdir(parents=True, exist_ok=True)
os.environ["PYTHONPYCACHEPREFIX"] = str(cache_root)
compiled = cache_root / "ex7_p0b_v7_00B_R2.pyc"
py_compile.compile(str(TARGET), cfile=str(compiled), doraise=True)

digest = hashlib.sha256(TARGET.read_bytes()).hexdigest().upper()
print(f"created={TARGET}")
print(f"size_bytes={TARGET.stat().st_size}")
print(f"sha256={digest}")
print("python_compile=PASS")
