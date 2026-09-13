#!/usr/bin/env python3
"""Fail-closed evidence gate for lawful bug-bounty research.

This gate never proves a vulnerability. It only checks that a candidate has the
minimum evidence required before it may be marked ready for owner review.
"""

from __future__ import annotations

import argparse
import json
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


def emit_locked(reason: str) -> int:
    print(json.dumps({"gate": "LOCKED", "reason": reason}, sort_keys=True))
    return 1


def load_json(path: Path, label: str):
    if not path.is_file():
        raise ValueError(f"{label} file missing")
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        raise ValueError(f"{label} JSON invalid") from exc


def check_public_fix_registry(candidate: dict, registry_path: Path | None) -> str | None:
    if registry_path is None:
        return None
    try:
        registry = load_json(registry_path, "public-fix registry")
    except ValueError as exc:
        return str(exc)

    if registry.get("target") != candidate.get("target"):
        return "public-fix registry target mismatch"
    if registry.get("release") != candidate.get("release"):
        return "public-fix registry release mismatch"

    public_commits = {
        item.get("commit")
        for item in registry.get("public_fixes", [])
        if isinstance(item, dict) and item.get("classification") == "PUBLIC_FIX_EXCLUDE"
    }
    references = candidate.get("reference_commits", [])
    if not isinstance(references, list):
        return "reference_commits must be a list"
    matched = sorted(public_commits.intersection(str(x) for x in references))
    if matched:
        return f"candidate references known public fix: {matched[0]}"
    return None


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("candidate", type=Path)
    parser.add_argument("--public-fix-registry", type=Path)
    args = parser.parse_args()

    try:
        candidate = load_json(args.candidate, "candidate")
    except ValueError as exc:
        return emit_locked(str(exc))

    if candidate.get("submission_unlocked") is True:
        return emit_locked("candidate may not self-unlock submission")

    if not candidate.get("target") or not candidate.get("release"):
        return emit_locked("target/release identity missing")

    registry_reason = check_public_fix_registry(candidate, args.public_fix_registry)
    if registry_reason:
        return emit_locked(registry_reason)

    for key in REQUIRED_TRUE:
        if candidate.get(key) is not True:
            return emit_locked(f"required evidence missing: {key}")

    repro = candidate.get("local_reproduction")
    if not isinstance(repro, dict):
        return emit_locked("local reproduction evidence missing")
    if repro.get("environment") != "linux":
        return emit_locked("Linux reproduction required")
    if int(repro.get("successful_runs", 0)) < 2:
        return emit_locked("at least two successful reproductions required")
    if repro.get("deterministic") is not True:
        return emit_locked("deterministic reproduction required")

    if candidate.get("confirmed_finding") is not True:
        return emit_locked("candidate is not confirmed")

    print(json.dumps({
        "gate": "READY_FOR_OWNER_REVIEW",
        "target": candidate["target"],
        "release": candidate["release"],
        "truth": "evidence threshold passed; bounty acceptance and payout remain unverified",
    }, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
