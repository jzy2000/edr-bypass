#!/usr/bin/env python3
"""Check cards, catalog, and banned strings. Exit 0 when the pack is consistent."""

from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CARDS = ROOT / "cards"
CATALOG = ROOT / "catalog" / "index.yaml"
DENY = ROOT / "scripts" / "deny.txt"

REQUIRED = (
    "id",
    "plane",
    "privilege",
    "kind",
    "action",
    "summary",
    "oracle",
    "skip",
)
ORACLE_KEYS = ("hold", "miss", "inconclusive")
ID_RE = re.compile(r"^[A-Z]+-\d{2}$")


def _scalar(raw: str):
    raw = raw.strip()
    if raw in ("true", "false"):
        return raw == "true"
    if raw == "null":
        return None
    if raw.startswith("[") and raw.endswith("]"):
        inner = raw[1:-1].strip()
        if not inner:
            return []
        return [part.strip().strip('"').strip("'") for part in inner.split(",")]
    if raw.startswith('"') and raw.endswith('"'):
        return raw[1:-1]
    return raw


def front_matter(path: Path) -> dict:
    text = path.read_text()
    if not text.startswith("---\n"):
        raise SystemExit(f"{path}: missing front matter")
    end = text.find("\n---\n", 4)
    if end < 0:
        raise SystemExit(f"{path}: unclosed front matter")
    data: dict = {}
    oracle = None
    for line in text[4:end].splitlines():
        if not line.strip():
            continue
        if line.startswith("  ") and oracle is not None:
            key, _, value = line.strip().partition(":")
            oracle[key] = _scalar(value)
            continue
        key, _, value = line.partition(":")
        key = key.strip()
        if key == "oracle":
            oracle = {}
            data["oracle"] = oracle
            continue
        oracle = None
        data[key] = _scalar(value)
    return data


def catalog_ids() -> dict:
    listed = {}
    current = None
    for line in CATALOG.read_text().splitlines():
        stripped = line.strip()
        if stripped.startswith("- id:"):
            current = stripped.split(":", 1)[1].strip()
            listed[current] = {}
        elif current and stripped.startswith("card:"):
            listed[current]["card"] = stripped.split(":", 1)[1].strip()
    return listed


def main() -> int:
    errors: list[str] = []
    listed = catalog_ids()
    files = sorted(CARDS.glob("*.md"))
    seen: set[str] = set()

    for path in files:
        card = front_matter(path)
        for key in REQUIRED:
            if key not in card:
                errors.append(f"{path.name}: missing {key}")
        cid = str(card.get("id", ""))
        if not ID_RE.match(cid):
            errors.append(f"{path.name}: bad id {cid!r}")
        if cid in seen:
            errors.append(f"duplicate id {cid}")
        seen.add(cid)
        if cid not in listed:
            errors.append(f"{cid} has a card but is not in the catalog")
        elif listed[cid].get("card") != f"cards/{path.name}":
            errors.append(f"{cid}: catalog card path mismatch")
        oracle = card.get("oracle") or {}
        for key in ORACLE_KEYS:
            if key not in oracle:
                errors.append(f"{cid}: oracle.{key} missing")
        action = str(card.get("action", ""))
        skip = bool(card.get("skip"))
        if action == "unspecified" and not skip:
            errors.append(f"{cid}: unspecified action must set skip true")
        if action != "unspecified" and skip:
            errors.append(f"{cid}: specified action must set skip false")

    for cid in listed:
        if cid not in seen:
            errors.append(f"{cid} is in the catalog but has no card")

    deny_lines = []
    if DENY.exists():
        deny_lines = [
            line.strip()
            for line in DENY.read_text().splitlines()
            if line.strip() and not line.startswith("#")
        ]
    if deny_lines:
        for path in ROOT.rglob("*"):
            if not path.is_file():
                continue
            if any(part in {".git", "archive", "deny.txt"} for part in path.parts):
                continue
            if path.suffix.lower() not in {".md", ".yaml", ".yml", ".json", ".py", ".cpp"}:
                continue
            text = path.read_text(errors="replace")
            for banned in deny_lines:
                if banned in text:
                    errors.append(f"{path.relative_to(ROOT)} contains a banned string")

    if errors:
        print("\n".join(errors))
        return 1
    print(f"ok: {len(seen)} cards")
    return 0


if __name__ == "__main__":
    sys.exit(main())
