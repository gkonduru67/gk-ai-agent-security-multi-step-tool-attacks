from __future__ import annotations

import hashlib
import json
from pathlib import Path

FIXTURE = Path(
    r"C:\Users\gkonduru\OneDrive - Forescout Technologies, Inc"
    r"\F_drive\forescout\Learning\Kaggle"
    r"\ai-agent-security-multi-step-tool-attacks-Jun11-Sep1"
    r"\ai-agent-security-multi-step-tool-attacks"
    r"\aicomp_sdk\fixtures\web_corpus.json"
)

RISK_TERMS = (
    "secret.txt",
    "fs.read",
    "fs.write",
    "fs.delete",
    "http.post",
    "email.send",
    "shell.run",
    "execute",
    "system instruction",
    "authorized system",
    "ignore previous",
    "send_to_server",
    "delete_file",
)

def sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest().upper()

root = json.loads(FIXTURE.read_text(encoding="utf-8"))

if isinstance(root, list):
    records = root
elif isinstance(root, dict):
    records = (
        root.get("pages")
        or root.get("records")
        or root.get("items")
        or root.get("documents")
        or []
    )
else:
    raise TypeError(f"Unsupported fixture root: {type(root).__name__}")

if not isinstance(records, list):
    raise TypeError("Could not locate a list of web records")

candidates = []

for index, record in enumerate(records):
    if not isinstance(record, dict):
        continue

    record_id = record.get("id")
    title = str(record.get("title") or "")
    url = str(record.get("url") or "")
    content = str(record.get("content") or "")

    combined = f"{title}\n{url}\n{content}".lower()
    matched_terms = sorted(term for term in RISK_TERMS if term in combined)
    candidate = bool(record_id) and not matched_terms

    row = {
        "index": index,
        "id": record_id,
        "title": title,
        "url_sha256": sha256_text(url),
        "content_length": len(content),
        "content_sha256": sha256_text(content),
        "risk_terms": matched_terms,
        "candidate": candidate,
    }

    if candidate:
        candidates.append(row)

print(f"Fixture: {FIXTURE}")
print(f"Fixture SHA-256: {hashlib.sha256(FIXTURE.read_bytes()).hexdigest().upper()}")
print(f"Record count: {len(records)}")
print(f"Low-risk candidate count: {len(candidates)}")
print()

for row in candidates:
    print(
        f"id={row['id']!r} | "
        f"title={row['title']!r} | "
        f"content_length={row['content_length']} | "
        f"content_sha256={row['content_sha256']}"
    )