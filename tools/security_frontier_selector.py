#!/usr/bin/env python3
"""Select the highest-ranked untouched released-code boundary candidate.

Selection is prioritization only. It never proves a vulnerability or unlocks
submission. Public-fix overlap, tests, fixtures, vendor and generated code are
excluded from the frontier.
"""

from __future__ import annotations

import argparse
import json
from pathlib import PurePosixPath

SKIP_PARTS = {"vendor", "testdata", "tests"}
SKIP_SUFFIXES = ("_test.go", ".gen.go")


def eligible(item: dict) -> bool:
    path = str(item.get("path", ""))
    if not path or item.get("public_fix_overlap") is True:
        return False
    p = PurePosixPath(path)
    if any(part in SKIP_PARTS for part in p.parts):
        return False
    if path.endswith(SKIP_SUFFIXES) or "zz_generated" in p.name:
        return False
    return item.get("classification") == "UNVERIFIED_BOUNDARY_CANDIDATE"


def select_frontier(payload: dict) -> dict:
    candidates = payload.get("candidates", [])
    if not isinstance(candidates, list):
        raise ValueError("candidates must be a list")
    for item in candidates:
        if isinstance(item, dict) and eligible(item):
            return {
                "truth": "frontier selection only; no vulnerability proof",
                "candidate": item,
                "finding": False,
                "submission_ready": False,
            }
    raise ValueError("no eligible untouched frontier candidate")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("ranking")
    args = parser.parse_args()
    payload = json.load(open(args.ranking, encoding="utf-8"))
    print(json.dumps(select_frontier(payload), indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
