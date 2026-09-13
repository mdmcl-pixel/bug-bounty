#!/usr/bin/env python3
"""Fail-closed evidence gate for lawful bug-bounty research.

This gate never proves a vulnerability. It only checks that a candidate has the
minimum evidence required before it may be marked ready for owner review.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

REQUIRED_TRUE = (
    "in_scope",
    "released_code_only",
    "meaningful_security_impact",
    "realistic_attack_scenario",
    "control_test_passed",
    "duplicate_check_clear",
    "public_fix_check_clear",
)


def fail(reason: str) -> int:
    print(json.dumps({"gate": "LOCKED", "reason": reason}, sort_keys=True))
    return 1


def main() -> int:
    if len(sys.argv) != 2:
        return fail("candidate file required")

    path = Path(sys.argv[1])
    if not path.is_file():
        return fail("candidate file missing")

    try:
        candidate = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return fail("candidate JSON invalid")

    if candidate.get("submission_unlocked") is True:
        return fail("candidate may not self-unlock submission")

    if not candidate.get("target") or not candidate.get("release"):
        return fail("target/release identity missing")

    for key in REQUIRED_TRUE:
        if candidate.get(key) is not True:
            return fail(f"required evidence missing: {key}")

    repro = candidate.get("local_reproduction")
    if not isinstance(repro, dict):
        return fail("local reproduction evidence missing")
    if repro.get("environment") != "linux":
        return fail("Linux reproduction required")
    if int(repro.get("successful_runs", 0)) < 2:
        return fail("at least two successful reproductions required")
    if repro.get("deterministic") is not True:
        return fail("deterministic reproduction required")

    if candidate.get("confirmed_finding") is not True:
        return fail("candidate is not confirmed")

    print(json.dumps({
        "gate": "READY_FOR_OWNER_REVIEW",
        "target": candidate["target"],
        "release": candidate["release"],
        "truth": "evidence threshold passed; bounty acceptance and payout remain unverified",
    }, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
