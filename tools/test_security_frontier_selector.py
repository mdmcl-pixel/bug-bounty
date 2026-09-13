import unittest

from tools.security_frontier_selector import select_frontier


class FrontierSelectorTests(unittest.TestCase):
    def test_selects_first_untouched_non_test_candidate(self):
        payload = {"candidates": [
            {"path": "internal/oci/known.go", "score": 100, "public_fix_overlap": True, "classification": "PUBLIC_FIX_OVERLAP_REFERENCE_ONLY"},
            {"path": "internal/oci/noise_test.go", "score": 90, "public_fix_overlap": False, "classification": "UNVERIFIED_BOUNDARY_CANDIDATE"},
            {"path": "internal/oci/state.go", "score": 80, "public_fix_overlap": False, "classification": "UNVERIFIED_BOUNDARY_CANDIDATE"},
        ]}
        out = select_frontier(payload)
        self.assertEqual(out["candidate"]["path"], "internal/oci/state.go")
        self.assertFalse(out["finding"])
        self.assertFalse(out["submission_ready"])

    def test_generated_and_fixture_paths_are_skipped(self):
        payload = {"candidates": [
            {"path": "pkg/nvcdi/zz_generated.go", "score": 50, "public_fix_overlap": False, "classification": "UNVERIFIED_BOUNDARY_CANDIDATE"},
            {"path": "pkg/nvcdi/testdata/x.go", "score": 40, "public_fix_overlap": False, "classification": "UNVERIFIED_BOUNDARY_CANDIDATE"},
            {"path": "pkg/nvcdi/device.go", "score": 30, "public_fix_overlap": False, "classification": "UNVERIFIED_BOUNDARY_CANDIDATE"},
        ]}
        self.assertEqual(select_frontier(payload)["candidate"]["path"], "pkg/nvcdi/device.go")

    def test_deprioritized_frontier_rotates_to_next_candidate(self):
        payload = {"candidates": [
            {"path": "cmd/nvidia-cdi-hook/cudacompat/cudacompat.go", "score": 52, "public_fix_overlap": False, "classification": "UNVERIFIED_BOUNDARY_CANDIDATE"},
            {"path": "cmd/nvidia-cdi-hook/create-symlinks/container-root_linux.go", "score": 41, "public_fix_overlap": False, "classification": "UNVERIFIED_BOUNDARY_CANDIDATE"},
        ]}
        out = select_frontier(payload, {"cmd/nvidia-cdi-hook/cudacompat/cudacompat.go"})
        self.assertEqual(out["candidate"]["path"], "cmd/nvidia-cdi-hook/create-symlinks/container-root_linux.go")
        self.assertEqual(out["deprioritized_count"], 1)

    def test_no_eligible_candidate_fails_closed(self):
        with self.assertRaises(ValueError):
            select_frontier({"candidates": []})


if __name__ == "__main__":
    unittest.main()
