#!/usr/bin/env python3
"""Rank released source files for defensive bug-bounty review.

This is a prioritizer, not a vulnerability detector. Scores identify code that
crosses security-sensitive boundaries so human/local reproduction can focus
there first. Public fixes are exclusion references, never bounty evidence.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

SENSITIVE_PREFIXES = (
    "cmd/nvidia-cdi-hook/",
    "internal/ldconfig/",
    "internal/modifier/",
    "internal/oci/",
    "pkg/nvcdi/",
)

WEIGHTS = {
    "pivot_root": 8,
    "pivotRoot": 8,
    "execve": 8,
    "exec.Command": 7,
    "unix.Mount": 7,
    "os.OpenRoot": 6,
    "OpenatInRoot": 6,
    "MkdirAllHandle": 5,
    "Symlink": 5,
    "Renameat": 5,
    "Chmod": 4,
    "Chown": 4,
    "containerRoot": 4,
    "driverRoot": 4,
    "filepath.Join": 2,
    "filepath.Clean": 2,
    "Bundle": 2,
}


def rank(root: Path, limit: int = 20) -> list[dict]:
    ranked: list[dict] = []
    for path in root.rglob("*.go"):
        rel = path.relative_to(root).as_posix()
        if not rel.startswith(SENSITIVE_PREFIXES):
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue
        hits = {token: text.count(token) for token in WEIGHTS if token in text}
        score = sum(WEIGHTS[token] * count for token, count in hits.items())
        if score <= 0:
            continue
        ranked.append({
            "path": rel,
            "score": score,
            "signals": sorted(hits),
            "finding": False,
            "next": "local_review_then_reproduction_if_concrete",
        })
    ranked.sort(key=lambda item: (-item["score"], item["path"]))
    return ranked[:limit]


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("source_root", type=Path)
    parser.add_argument("--limit", type=int, default=20)
    args = parser.parse_args()
    if not args.source_root.is_dir():
        raise SystemExit("source root missing")
    print(json.dumps({
        "truth": "ranking only; no vulnerability proof",
        "candidates": rank(args.source_root, max(1, args.limit)),
    }, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
