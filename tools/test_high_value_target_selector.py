import unittest

from tools.high_value_target_selector import select_target


class HighValueTargetSelectorTests(unittest.TestCase):
    def test_selects_highest_priority_ready_local_target(self):
        payload = {"targets": [
            {"id": "lower", "status": "READY", "priority": 50, "review_mode": "LOCAL_SOURCE_ONLY"},
            {"id": "higher", "status": "READY", "priority": 100, "review_mode": "LOCAL_SOURCE_ONLY"},
            {"id": "remote", "status": "READY", "priority": 200, "review_mode": "REMOTE_TEST"},
        ]}
        out = select_target(payload)
        self.assertEqual(out["status"], "ACTIVE")
        self.assertEqual(out["target"]["id"], "higher")
        self.assertFalse(out["finding"])
        self.assertFalse(out["submission_ready"])
        self.assertFalse(out["owner_action_required"])

    def test_exhausted_target_is_not_reselected(self):
        payload = {"targets": [
            {"id": "done", "status": "RANKED_FRONTIER_EXHAUSTED", "priority": 100, "review_mode": "LOCAL_SOURCE_ONLY"},
            {"id": "next", "status": "READY", "priority": 90, "review_mode": "LOCAL_SOURCE_ONLY"},
        ]}
        self.assertEqual(select_target(payload)["target"]["id"], "next")

    def test_no_ready_target_fails_closed_without_widening_scope(self):
        out = select_target({"targets": []})
        self.assertEqual(out["status"], "EXHAUSTED")
        self.assertIsNone(out["target"])
        self.assertFalse(out["submission_ready"])
        self.assertFalse(out["owner_action_required"])


if __name__ == "__main__":
    unittest.main()
