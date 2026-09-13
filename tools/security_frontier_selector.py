#!/usr/bin/env python3
"""Select the next highest-ranked untouched released-code boundary candidate.

Selection is prioritization only. It never proves a vulnerability or unlocks
submission. Public-fix overlap, tests, fixtures, vendor/generated code, and
paths temporarily deprioritized after a tested hypothesis are excluded from
primary frontier selection. Deprioritization never means vulnerability-free.

If every ranked candidate has been reviewed or deprioritized, return a
fail-closed EXHAUSTED state instead of raising. Exhaustion means the current
ranked search space is complete; it does not mean the target is vulnerability-
free and it does not unlock submission.
"""

from __future__ import annotations

import argparse
import json
from pathlib import PurePosixPath

SKIP_PARTS = {"vendor", "testdata", "tests"}
SKIP_SUFFIXES = ("_test.go", ".gen.go")


def load_deprioritized(path: str | None) -> set[str]:
    if not path:
        return set()
    data = json.load(open(path, encoding="utf-8"))
    entries = data.get("primary_deprioritized", [])
    if not isinstance(entries, list):
        raise ValueError("primary_deprioritized must be a list")
    return {
        str(item.get("path", ""))
        for item in entries
        if isinstance(item, dict) and item.get("path")
    }


def eligible(item: dict, deprioritized: set[str] | None = None) -> bool:
    path = str(item.get("path", ""))
    if not path or item.get("public_fix_overlap") is True:
        return False
    if path in (deprioritized or set()):
        return False
    p = PurePosixPath(path)
    if any(part in SKIP_PARTS for part in p.parts):
        return False
    if path.endswith(SKIP_SUFFIXES) or "zz_generated" in p.name:
        return False
    return item.get("classification") == "UNVERIFIED_BOUNDARY_CANDIDATE"


def select_frontier(payload: dict, deprioritized: set[str] | None = None) -> dict:
    candidates = payload.get("candidates", [])
    if not isinstance(candidates, list):
        raise ValueError("candidates must be a list")
    deprioritized = deprioritized or set()
    for item in candidates:
        if isinstance(item, dict) and eligible(item, deprioritized):
            return {
                "truth": "frontier selection only; no vulnerability proof",
                "status": "ACTIVE",
                "exhausted": False,
                "candidate": item,
                "finding": False,
                "submission_ready": False,
                "deprioritized_count": len(deprioritized),
                "ranked_candidate_count": len(candidates),
            }
    return {
        "truth": "current ranked frontier exhausted; this does not prove absence of vulnerabilities",
        "status": "EXHAUSTED",
        "exhausted": True,
        "candidate": None,
        "finding": False,
        "submission_ready": False,
        "deprioritized_count": len(deprioritized),
        "ranked_candidate_count": len(candidates),
        "next": "rotate_to_next_verified_target_or_expand_search_model",
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("ranking")
    parser.add_argument("--history")
    args = parser.parse_args()
    payload = json.load(open(args.ranking, encoding="utf-8"))
    deprioritized = load_deprioritized(args.history)
    print(json.dumps(select_frontier(payload, deprioritized), indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
