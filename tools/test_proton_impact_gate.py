import unittest

from tools.proton_impact_gate import evaluate


class ProtonImpactGateTests(unittest.TestCase):
    def test_reproduced_primitive_without_impact_stays_parked(self):
        payload = {"candidate": {
            "id": "c1",
            "reproduced": True,
            "scope_verified": True,
            "duplicate_checked": False,
            "security_boundary_crossed": False,
            "attacker_capability_gain_proven": False,
        }}
        out = evaluate(payload)
        self.assertEqual(out["gate"], "PARKED_IMPACT_NOT_PROVEN")
        self.assertFalse(out["finding"])
        self.assertFalse(out["submission_ready"])
        self.assertFalse(out["owner_action_required"])

    def test_complete_evidence_requires_manual_review_and_never_auto_submits(self):
        payload = {"candidate": {
            "id": "c2",
            "reproduced": True,
            "scope_verified": True,
            "duplicate_checked": True,
            "security_boundary_crossed": True,
            "attacker_capability_gain_proven": True,
        }}
        out = evaluate(payload)
        self.assertEqual(out["gate"], "PASS_EVIDENCE_COMPLETE_MANUAL_REVIEW_REQUIRED")
        self.assertFalse(out["finding"])
        self.assertFalse(out["submission_ready"])
        self.assertTrue(out["owner_action_required"])


if __name__ == "__main__":
    unittest.main()
