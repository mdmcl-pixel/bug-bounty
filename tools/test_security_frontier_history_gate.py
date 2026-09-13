import unittest

from tools.security_frontier_history_gate import validate


class FrontierHistoryGateTests(unittest.TestCase):
    def base(self):
        return {
            "target": "NVIDIA/nvidia-container-toolkit",
            "release": "v1.20.0",
            "release_commit": "abc",
            "primary_deprioritized": [
                {
                    "path": "a.go",
                    "classification": "TESTED_ESCAPE_HYPOTHESIS_REJECTED",
                    "tested_hypothesis": "escape",
                    "evidence_run_id": 1,
                    "repeat_count": 3,
                    "result": "PASS_CONTAINMENT",
                    "finding": False,
                    "submission_ready": False,
                },
                {
                    "path": "b.go",
                    "classification": "PUBLIC_FIX_DEPENDENCY_REFERENCE_ONLY",
                    "reason": "known public fix dependency",
                    "finding": False,
                    "submission_ready": False,
                },
            ],
        }

    def test_valid_history_passes(self):
        out = validate(self.base())
        self.assertEqual(out["gate"], "PASS")
        self.assertEqual(out["entries"], 2)

    def test_duplicate_path_fails(self):
        data = self.base()
        data["primary_deprioritized"][1]["path"] = "a.go"
        with self.assertRaises(ValueError):
            validate(data)

    def test_history_cannot_claim_finding(self):
        data = self.base()
        data["primary_deprioritized"][0]["finding"] = True
        with self.assertRaises(ValueError):
            validate(data)

    def test_weak_containment_evidence_fails(self):
        data = self.base()
        data["primary_deprioritized"][0]["repeat_count"] = 1
        with self.assertRaises(ValueError):
            validate(data)


if __name__ == "__main__":
    unittest.main()
