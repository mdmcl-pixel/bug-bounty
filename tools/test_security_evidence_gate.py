import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

GATE = Path(__file__).with_name("security_evidence_gate.py")


class EvidenceGateTests(unittest.TestCase):
    def run_gate(self, payload, registry=None):
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False, encoding="utf-8") as f:
            json.dump(payload, f)
            candidate_path = Path(f.name)
        registry_path = None
        if registry is not None:
            with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False, encoding="utf-8") as f:
                json.dump(registry, f)
                registry_path = Path(f.name)
        try:
            cmd = [sys.executable, str(GATE), str(candidate_path)]
            if registry_path is not None:
                cmd += ["--public-fix-registry", str(registry_path)]
            return subprocess.run(cmd, text=True, capture_output=True, check=False)
        finally:
            candidate_path.unlink(missing_ok=True)
            if registry_path is not None:
                registry_path.unlink(missing_ok=True)

    def valid_candidate(self):
        return {
            "target": "example/target",
            "release": "v1.0.0",
            "release_commit": "release-sha-123",
            "submission_unlocked": False,
            "in_scope": True,
            "released_code_only": True,
            "meaningful_security_impact": True,
            "realistic_attack_scenario": True,
            "control_test_passed": True,
            "duplicate_check_clear": True,
            "public_fix_check_clear": True,
            "reference_commits": [],
            "local_reproduction": {
                "environment": "linux",
                "successful_runs": 2,
                "deterministic": True,
            },
            "confirmed_finding": True,
        }

    def registry(self):
        return {
            "target": "example/target",
            "release": "v1.0.0",
            "release_commit": "release-sha-123",
            "public_fixes": [
                {
                    "commit": "public-fix-123",
                    "classification": "PUBLIC_FIX_EXCLUDE",
                }
            ],
        }

    def test_valid_evidence_reaches_owner_review_only(self):
        result = self.run_gate(self.valid_candidate(), self.registry())
        self.assertEqual(result.returncode, 0)
        self.assertIn("READY_FOR_OWNER_REVIEW", result.stdout)

    def test_missing_scope_fails_closed(self):
        candidate = self.valid_candidate()
        candidate["in_scope"] = False
        result = self.run_gate(candidate)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("LOCKED", result.stdout)

    def test_single_reproduction_fails_closed(self):
        candidate = self.valid_candidate()
        candidate["local_reproduction"]["successful_runs"] = 1
        result = self.run_gate(candidate)
        self.assertNotEqual(result.returncode, 0)

    def test_candidate_cannot_self_unlock_submission(self):
        candidate = self.valid_candidate()
        candidate["submission_unlocked"] = True
        result = self.run_gate(candidate)
        self.assertNotEqual(result.returncode, 0)

    def test_known_public_fix_reference_fails_closed(self):
        candidate = self.valid_candidate()
        candidate["reference_commits"] = ["public-fix-123"]
        result = self.run_gate(candidate, self.registry())
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("known public fix", result.stdout)

    def test_registry_identity_mismatch_fails_closed(self):
        registry = self.registry()
        registry["release"] = "v9.9.9"
        result = self.run_gate(self.valid_candidate(), registry)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("registry release mismatch", result.stdout)

    def test_release_commit_mismatch_fails_closed(self):
        candidate = self.valid_candidate()
        candidate["release_commit"] = "wrong-sha"
        result = self.run_gate(candidate, self.registry())
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("release commit mismatch", result.stdout)

    def test_missing_release_commit_fails_closed(self):
        candidate = self.valid_candidate()
        candidate.pop("release_commit")
        result = self.run_gate(candidate, self.registry())
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("identity missing", result.stdout)


if __name__ == "__main__":
    unittest.main()
