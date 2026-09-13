#!/usr/bin/env python3
"""Fail-closed impact gate for Proton local/source research candidates.

Reproduction alone is not a finding. Promotion requires a verified in-scope
security boundary, duplicate clearance, and attacker capability beyond an
already-equivalent local privilege. This tool never unlocks submission.
"""

from __future__ import annotations

import argparse
import json


def evaluate(payload: dict) -> dict:
    candidate = payload.get("candidate")
    if not isinstance(candidate, dict):
        raise ValueError("candidate must be an object")

    checks = {
        "reproduced": candidate.get("reproduced") is True,
        "scope_verified": candidate.get("scope_verified") is True,
        "duplicate_checked": candidate.get("duplicate_checked") is True,
        "security_boundary_crossed": candidate.get("security_boundary_crossed") is True,
        "attacker_capability_gain_proven": candidate.get("attacker_capability_gain_proven") is True,
    }
    evidence_complete = all(checks.values())

    return {
        "candidate_id": candidate.get("id"),
        "gate": "PASS_EVIDENCE_COMPLETE_MANUAL_REVIEW_REQUIRED" if evidence_complete else "PARKED_IMPACT_NOT_PROVEN",
        "checks": checks,
        "finding": False,
        "submission_ready": False,
        "owner_action_required": evidence_complete,
        "truth": (
            "evidence complete enough for manual owner review; submission remains locked"
            if evidence_complete
            else "reproduction retained as research evidence only; no finding or submission"
        ),
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("state")
    args = parser.parse_args()
    payload = json.load(open(args.state, encoding="utf-8"))
    print(json.dumps(evaluate(payload), indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
