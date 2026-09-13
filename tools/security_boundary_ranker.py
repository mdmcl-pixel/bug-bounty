#!/usr/bin/env python3
"""Rank released Linux production implementations for defensive review.

This is a prioritizer, not a vulnerability detector. It focuses on implemented
functions/methods crossing security-sensitive boundaries. Tests, fixtures,
generated/non-Linux files and declaration/configuration-only files are removed
before scoring. Public fixes, explicit dependent files, and wrappers that
directly depend on public-fixed packages remain reference-only exclusions.
Host/operator configuration-only paths and paths without an identified
privileged sink are down-ranked rather than declared safe.
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
NON_LINUX_SUFFIXES = ("_other.go", "_windows.go", "_darwin.go", "_freebsd.go")
CONFIG_ONLY_NAMES = {"options.go", "config.go"}
PRIVILEGED_OPERATION_TOKENS = (
    "pivot_root", "pivotRoot", "execve", "exec.Command", "unix.Mount",
    "os.OpenRoot", "OpenatInRoot", "MkdirAllHandle", "Symlink", "Renameat",
    "Chmod", "Chown", "os.WriteFile", "os.OpenFile", "unix.Openat",
)
INPUT_PROXIMITY_TOKENS = (
    "os.Stdin", "json.NewDecoder", "ReadDir(", "entry.Name()", "cli.StringFlag",
    "container-spec", "containerRoot.Open(", "containerRoot.Lstat(", "os.Getenv",
)
HOST_CONFIGURATION_TOKENS = (
    "l.csv.Files", "dxcore.GetDriverStorePaths(", "o.driverRoot", "o.devRoot",
    "o.librarySearchPaths", "o.configSearchPaths", "populateOptions(",
    "lookup.WithSearchPaths(",
)
WEIGHTS = {
    "pivot_root": 8, "pivotRoot": 8, "execve": 8, "exec.Command": 7,
    "unix.Mount": 7, "os.OpenRoot": 6, "OpenatInRoot": 6,
    "MkdirAllHandle": 5, "Symlink": 5, "Renameat": 5, "Chmod": 4,
    "Chown": 4, "containerRoot": 4, "driverRoot": 4,
    "filepath.Join": 2, "filepath.Clean": 2, "Bundle": 2,
}
PUBLIC_FIX_PENALTY = 10
PUBLIC_FIX_DEPENDENCY_PENALTY = 8
HOST_CONFIGURATION_ONLY_PENALTY = 5
NO_PRIVILEGED_SINK_PENALTY = 6
ADJACENCY_BONUS = 5
SOURCE_SINK_BONUS = 6
MODULE_PREFIX = "github.com/NVIDIA/nvidia-container-toolkit/"


def should_skip(rel: str) -> bool:
    p = Path(rel)
    return (
        any(part in SKIP_PARTS for part in p.parts)
        or rel.endswith(SKIP_SUFFIXES)
        or rel.endswith(NON_LINUX_SUFFIXES)
        or "zz_generated" in p.name
    )


def is_configuration_only(rel: str, text: str) -> bool:
    """Drop option/config plumbing unless it performs a privileged operation."""
    name = Path(rel).name
    if name not in CONFIG_ONLY_NAMES:
        return False
    return not any(token in text for token in PRIVILEGED_OPERATION_TOKENS)


def load_exclusions(path: Path | None) -> dict:
    if path is None:
        return {}
    if not path.is_file():
        raise ValueError("exclusion registry missing")
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError("exclusion registry must be an object")
    return data


def exclusion_index(exclusions: dict) -> tuple[dict[str, list[str]], set[str], dict[str, list[str]], dict[str, list[str]]]:
    by_file: dict[str, list[str]] = {}
    fixed_dirs: set[str] = set()
    by_import: dict[str, list[str]] = {}
    dependent_by_file: dict[str, list[str]] = {}
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
            parent = str(Path(rel).parent).replace("\\", "/")
            fixed_dirs.add(parent)
            if parent and parent != "." and commit:
                by_import.setdefault(MODULE_PREFIX + parent, []).append(commit)
        for raw_path in item.get("dependent_files", []):
            rel = str(raw_path).strip().replace("\\", "/")
            if rel and commit:
                dependent_by_file.setdefault(rel, []).append(commit)
    return by_file, fixed_dirs, by_import, dependent_by_file


def rank(root: Path, limit: int = 20, exclusions: dict | None = None) -> list[dict]:
    public_by_file, fixed_dirs, public_by_import, dependent_by_file = exclusion_index(exclusions or {})
    ranked: list[dict] = []
    for path in root.rglob("*.go"):
        rel = path.relative_to(root).as_posix()
        if not rel.startswith(SENSITIVE_PREFIXES) or should_skip(rel):
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue
        if "func " not in text or is_configuration_only(rel, text):
            continue
        hits = {token: text.count(token) for token in WEIGHTS if token in text}
        raw_score = sum(WEIGHTS[token] * count for token, count in hits.items())
        if raw_score <= 0:
            continue
        input_hits = sorted(token for token in INPUT_PROXIMITY_TOKENS if token in text)
        sink_hits = sorted(token for token in PRIVILEGED_OPERATION_TOKENS if token in text)
        host_config_hits = sorted(token for token in HOST_CONFIGURATION_TOKENS if token in text)
        host_config_only = bool(host_config_hits) and not input_hits
        no_privileged_sink = not sink_hits
        source_sink_bonus = SOURCE_SINK_BONUS if input_hits and sink_hits else 0
        public_refs = sorted(set(public_by_file.get(rel, [])))
        public_overlap = bool(public_refs)
        dependency_refs = sorted({
            *dependent_by_file.get(rel, []),
            *(
                commit
                for import_path, commits in public_by_import.items()
                if f'"{import_path}"' in text
                for commit in commits
            ),
        })
        public_fix_dependency = bool(dependency_refs) and not public_overlap
        parent = str(Path(rel).parent).replace("\\", "/")
        adjacency_bonus = ADJACENCY_BONUS if parent in fixed_dirs and not public_overlap and not public_fix_dependency else 0
        penalty = 0
        if host_config_only:
            penalty += HOST_CONFIGURATION_ONLY_PENALTY
        if no_privileged_sink:
            penalty += NO_PRIVILEGED_SINK_PENALTY
        if public_overlap:
            penalty += PUBLIC_FIX_PENALTY
        elif public_fix_dependency:
            penalty += PUBLIC_FIX_DEPENDENCY_PENALTY
        priority_score = max(1, raw_score + adjacency_bonus + source_sink_bonus - penalty)
        if public_overlap:
            classification = "PUBLIC_FIX_OVERLAP_REFERENCE_ONLY"
            next_step = "review_adjacent_behavior_only_do_not_resubmit_public_fix"
        elif public_fix_dependency:
            classification = "PUBLIC_FIX_DEPENDENCY_REFERENCE_ONLY"
            next_step = "review_wrapper_only_if_independent_boundary_exists"
        else:
            classification = "UNVERIFIED_BOUNDARY_CANDIDATE"
            next_step = "local_review_then_reproduction_if_concrete"
        ranked.append({
            "path": rel,
            "raw_score": raw_score,
            "score": priority_score,
            "signals": sorted(hits),
            "input_proximity_signals": input_hits,
            "privileged_sink_signals": sink_hits,
            "source_sink_bonus": source_sink_bonus,
            "no_privileged_sink": no_privileged_sink,
            "no_privileged_sink_penalty": NO_PRIVILEGED_SINK_PENALTY if no_privileged_sink else 0,
            "host_configuration_signals": host_config_hits,
            "host_configuration_only": host_config_only,
            "host_configuration_penalty": HOST_CONFIGURATION_ONLY_PENALTY if host_config_only else 0,
            "public_fix_overlap": public_overlap,
            "public_fix_refs": public_refs,
            "public_fix_dependency": public_fix_dependency,
            "public_fix_dependency_refs": dependency_refs,
            "adjacency_bonus": adjacency_bonus,
            "finding": False,
            "submission_ready": False,
            "classification": classification,
            "next": next_step,
        })
    ranked.sort(key=lambda item: (-item["score"], item["no_privileged_sink"], item["host_configuration_only"], item["public_fix_overlap"], item["public_fix_dependency"], item["path"]))
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
        "truth": "Linux implemented production-code ranking only; input-to-privileged-sink proximity is a prioritization signal, not proof of attacker control or vulnerability; configuration-only files are filtered unless they perform privileged operations; paths without identified privileged sinks and host/operator configuration-only paths are down-ranked; public fixes, explicit dependent files, and direct package dependencies are reference-only",
        "candidates": rank(args.source_root, max(1, args.limit), exclusions),
    }, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
