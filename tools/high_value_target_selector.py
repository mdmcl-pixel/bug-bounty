#!/usr/bin/env python3
"""Select the next ready high-value defensive research target.

This is orchestration only. It never proves a vulnerability, authorizes testing
outside published scope, unlocks submission, or changes the zero-spend rule.
"""

from __future__ import annotations

import argparse
import json

READY = {"READY", "ACTIVE"}


def select_target(payload: dict) -> dict:
    targets = payload.get("targets", [])
    if not isinstance(targets, list):
        raise ValueError("targets must be a list")
    eligible = [
        item for item in targets
        if isinstance(item, dict)
        and item.get("status") in READY
        and item.get("review_mode") == "LOCAL_SOURCE_ONLY"
        and int(item.get("priority", 0)) > 0
    ]
    eligible.sort(key=lambda item: (-int(item.get("priority", 0)), str(item.get("id", ""))))
    if not eligible:
        return {
            "status": "EXHAUSTED",
            "target": None,
            "finding": False,
            "submission_ready": False,
            "owner_action_required": False,
            "truth": "no ready target; do not widen scope automatically",
        }
    target = eligible[0]
    return {
        "status": "ACTIVE",
        "target": target,
        "finding": False,
        "submission_ready": False,
        "owner_action_required": False,
        "truth": "target selection only; local/source review remains bound to published scope",
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("queue")
    args = parser.parse_args()
    payload = json.load(open(args.queue, encoding="utf-8"))
    print(json.dumps(select_target(payload), indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
