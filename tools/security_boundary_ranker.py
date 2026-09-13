#!/usr/bin/env python3
"""Rank released source files for defensive bug-bounty review.

This is a prioritizer, not a vulnerability detector. Scores identify production
code crossing security-sensitive boundaries so local reproduction can focus
there. Public fixes are reference-only exclusions; nearby untouched files get
a small adjacency boost while tests, fixtures and generated code are removed
before scoring.
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

SKIP_PARTS = {"vendor", "testdata", "tests"}
SKIP_SUFFIXES = ("_test.go", ".gen.go")

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

PUBLIC_FIX_PENALTY = 10
ADJACENCY_BONUS = 5


def should_skip(rel: str) -> bool:
    p = Path(rel)
    return (
        any(part in SKIP_PARTS for part in p.parts)
        or rel.endswith(SKIP_SUFFIXES)
        or "zz_generated" in p.name
    )


def load_exclusions(path: Path | None) -> dict:
    if path is None:
        return {}
    if not path.is_file():
        raise ValueError("exclusion registry missing")
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError("exclusion registry must be an object")
    return data


def exclusion_index(exclusions: dict) -> tuple[dict[str, list[str]], set[str]]:
    by_file: dict[str, list[str]] = {}
    fixed_dirs: set[str] = set()
    for item in exclusions.get("public_fixes", []):
        if not isinstance(item, dict) or item.get("classification") != "PUBLIC_FIX_EXCLUDE":
            continue
        commit = str(item.get("commit", "")).strip()
        for raw_path in item.get("affected_files", []):
            rel = str(raw_path).strip().replace("\\", "/")
            if not rel:
                continue
            if commit:
                by_file.setdefault(rel, []).append(commit)
            fixed_dirs.add(str(Path(rel).parent).replace("\\", "/"))
    return by_file, fixed_dirs


def rank(root: Path, limit: int = 20, exclusions: dict | None = None) -> list[dict]:
    public_by_file, fixed_dirs = exclusion_index(exclusions or {})
    ranked: list[dict] = []
    for path in root.rglob("*.go"):
        rel = path.relative_to(root).as_posix()
        if not rel.startswith(SENSITIVE_PREFIXES) or should_skip(rel):
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue
        hits = {token: text.count(token) for token in WEIGHTS if token in text}
        raw_score = sum(WEIGHTS[token] * count for token, count in hits.items())
        if raw_score <= 0:
            continue

        public_refs = sorted(set(public_by_file.get(rel, [])))
        public_overlap = bool(public_refs)
        parent = str(Path(rel).parent).replace("\\", "/")
        adjacency_bonus = ADJACENCY_BONUS if parent in fixed_dirs and not public_overlap else 0
        penalty = PUBLIC_FIX_PENALTY if public_overlap else 0
        priority_score = max(1, raw_score + adjacency_bonus - penalty)

        ranked.append({
            "path": rel,
            "raw_score": raw_score,
            "score": priority_score,
            "signals": sorted(hits),
            "public_fix_overlap": public_overlap,
            "public_fix_refs": public_refs,
            "adjacency_bonus": adjacency_bonus,
            "finding": False,
            "submission_ready": False,
            "classification": (
                "PUBLIC_FIX_OVERLAP_REFERENCE_ONLY"
                if public_overlap
                else "UNVERIFIED_BOUNDARY_CANDIDATE"
            ),
            "next": (
                "review_adjacent_behavior_only_do_not_resubmit_public_fix"
                if public_overlap
                else "local_review_then_reproduction_if_concrete"
            ),
        })
    ranked.sort(key=lambda item: (-item["score"], item["public_fix_overlap"], item["path"]))
    return ranked[:limit]


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("source_root", type=Path)
    parser.add_argument("--limit", type=int, default=20)
    parser.add_argument("--exclusions", type=Path)
    args = parser.parse_args()
    if not args.source_root.is_dir():
        raise SystemExit("source root missing")
    try:
        exclusions = load_exclusions(args.exclusions)
    except (ValueError, json.JSONDecodeError) as exc:
        raise SystemExit(str(exc)) from exc
    print(json.dumps({
        "truth": "production-code ranking only; public fixes are reference-only; no vulnerability proof",
        "candidates": rank(args.source_root, max(1, args.limit), exclusions),
    }, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
