import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

GATE = Path(__file__).with_name("security_evidence_gate.py")


class EvidenceGateTests(unittest.TestCase):
    def run_gate(self, payload):
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False, encoding="utf-8") as f:
            json.dump(payload, f)
            path = f.name
        try:
            return subprocess.run(
                [sys.executable, str(GATE), path],
                text=True,
                capture_output=True,
                check=False,
            )
        finally:
            Path(path).unlink(missing_ok=True)

    def valid_candidate(self):
        return {
            "target": "example/target",
            "release": "v1.0.0",
            "submission_unlocked": False,
            "in_scope": True,
            "released_code_only": True,
            "meaningful_security_impact": True,
            "realistic_attack_scenario": True,
            "control_test_passed": True,
            "duplicate_check_clear": True,
            "public_fix_check_clear": True,
            "local_reproduction": {
                "environment": "linux",
                "successful_runs": 2,
                "deterministic": True,
            },
            "confirmed_finding": True,
        }

    def test_valid_evidence_reaches_owner_review_only(self):
        result = self.run_gate(self.valid_candidate())
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


if __name__ == "__main__":
    unittest.main()
