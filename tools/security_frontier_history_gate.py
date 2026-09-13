#!/usr/bin/env python3
"""Fail-closed integrity gate for defensive frontier history.

History records only prioritization decisions. It must never claim findings,
unlock submission, or silently duplicate the same path.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

ALLOWED = {
    "TESTED_ESCAPE_HYPOTHESIS_REJECTED",
    "PUBLIC_FIX_DEPENDENCY_REFERENCE_ONLY",
    "DEPRIORITIZED_NO_ATTACKER_CONTROL_SHOWN",
    "DEPRIORITIZED_NO_PRIVILEGE_CROSSING_SHOWN",
    "DEPRIORITIZED_DISABLED_BY_DEFAULT",
}


def validate(data: dict) -> dict:
    if not isinstance(data, dict):
        raise ValueError("history must be an object")
    if not data.get("target") or not data.get("release") or not data.get("release_commit"):
        raise ValueError("target/release/release_commit required")
    entries = data.get("primary_deprioritized")
    if not isinstance(entries, list):
        raise ValueError("primary_deprioritized must be a list")

    seen: set[str] = set()
    for item in entries:
        if not isinstance(item, dict):
            raise ValueError("history entry must be an object")
        path = str(item.get("path", "")).strip()
        classification = item.get("classification")
        if not path or path in seen:
            raise ValueError("history paths must be nonempty and unique")
        seen.add(path)
        if classification not in ALLOWED:
            raise ValueError(f"unsupported classification: {classification}")
        if item.get("finding") is not False or item.get("submission_ready") is not False:
            raise ValueError("history may never claim a finding or unlock submission")
        if classification == "TESTED_ESCAPE_HYPOTHESIS_REJECTED":
            if int(item.get("repeat_count", 0)) < 2 or item.get("result") != "PASS_CONTAINMENT":
                raise ValueError("tested-hypothesis entry lacks repeatable containment evidence")
            if not item.get("evidence_run_id") or not item.get("tested_hypothesis"):
                raise ValueError("tested-hypothesis entry lacks evidence identity")
        if classification == "PUBLIC_FIX_DEPENDENCY_REFERENCE_ONLY" and not item.get("reason"):
            raise ValueError("public-fix dependency entry lacks reason")
        if classification == "DEPRIORITIZED_NO_ATTACKER_CONTROL_SHOWN":
            reason = str(item.get("reason", "")).strip()
            if not reason:
                raise ValueError("no-attacker-control entry lacks reason")
            if "attacker" not in reason.lower() and "container-controlled" not in reason.lower():
                raise ValueError("no-attacker-control reason must identify the missing attacker-controlled boundary")
        if classification == "DEPRIORITIZED_NO_PRIVILEGE_CROSSING_SHOWN":
            reason = str(item.get("reason", "")).strip()
            if not reason:
                raise ValueError("no-privilege-crossing entry lacks reason")
            lower = reason.lower()
            if "privilege" not in lower and "host" not in lower and "container-local" not in lower:
                raise ValueError("no-privilege-crossing reason must identify why impact remains below the protected boundary")
        if classification == "DEPRIORITIZED_DISABLED_BY_DEFAULT":
            reason = str(item.get("reason", "")).strip().lower()
            if not reason:
                raise ValueError("disabled-by-default entry lacks reason")
            if "disabled by default" not in reason:
                raise ValueError("disabled-by-default reason must explicitly identify default-disabled status")
            if "enable" not in reason and "configuration" not in reason:
                raise ValueError("disabled-by-default reason must identify the non-default enablement condition")

    return {
        "gate": "PASS",
        "entries": len(entries),
        "unique_paths": len(seen),
        "finding": False,
        "submission_unlocked": False,
        "truth": "history integrity passed; this is prioritization evidence only",
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("history", type=Path)
    args = parser.parse_args()
    try:
        data = json.loads(args.history.read_text(encoding="utf-8"))
        result = validate(data)
    except Exception as exc:
        print(json.dumps({"gate": "LOCKED", "reason": str(exc)}, sort_keys=True))
        return 1
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
