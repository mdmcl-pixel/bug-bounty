import tempfile
import unittest
from pathlib import Path

from tools.security_boundary_ranker import rank


class BoundaryRankerTests(unittest.TestCase):
    def test_ranks_sensitive_boundary_over_plain_code(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            sensitive = root / "internal" / "ldconfig" / "x.go"
            sensitive.parent.mkdir(parents=True)
            sensitive.write_text("package x\n// pivot_root\nfunc f(){ _ = os.OpenRoot; _ = unix.Mount }", encoding="utf-8")
            plain = root / "pkg" / "other" / "y.go"
            plain.parent.mkdir(parents=True)
            plain.write_text("package y\nfunc f(){}", encoding="utf-8")
            out = rank(root)
            self.assertEqual(out[0]["path"], "internal/ldconfig/x.go")
            self.assertFalse(out[0]["finding"])
            self.assertFalse(out[0]["submission_ready"])

    def test_ignores_outside_sensitive_prefixes(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            p = root / "random" / "x.go"
            p.parent.mkdir(parents=True)
            p.write_text("package x\n// pivot_root execve unix.Mount", encoding="utf-8")
            self.assertEqual(rank(root), [])

    def test_limit_is_respected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            d = root / "internal" / "oci"
            d.mkdir(parents=True)
            for i in range(3):
                (d / f"{i}.go").write_text("package x\n// filepath.Join containerRoot", encoding="utf-8")
            self.assertEqual(len(rank(root, 2)), 2)

    def test_public_fix_overlap_is_penalized_and_adjacent_file_boosted(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            d = root / "internal" / "ldconfig"
            d.mkdir(parents=True)
            known = d / "known.go"
            adjacent = d / "adjacent.go"
            known.write_text("package x\n// unix.Mount os.OpenRoot filepath.Join", encoding="utf-8")
            adjacent.write_text("package x\n// unix.Mount os.OpenRoot filepath.Join", encoding="utf-8")
            exclusions = {"public_fixes": [{
                "commit": "abc123",
                "classification": "PUBLIC_FIX_EXCLUDE",
                "affected_files": ["internal/ldconfig/known.go"],
            }]}
            out = rank(root, exclusions=exclusions)
            self.assertEqual(out[0]["path"], "internal/ldconfig/adjacent.go")
            self.assertEqual(out[0]["adjacency_bonus"], 5)
            known_item = next(x for x in out if x["path"].endswith("known.go"))
            self.assertTrue(known_item["public_fix_overlap"])
            self.assertEqual(known_item["public_fix_refs"], ["abc123"])
            self.assertEqual(known_item["classification"], "PUBLIC_FIX_OVERLAP_REFERENCE_ONLY")

    def test_test_fixture_and_generated_sources_are_removed_before_scoring(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            d = root / "cmd" / "nvidia-cdi-hook" / "cudacompat"
            d.mkdir(parents=True)
            (d / "real.go").write_text("package x\n// filepath.Join containerRoot", encoding="utf-8")
            (d / "loud_test.go").write_text("package x\n// pivot_root execve unix.Mount Symlink Symlink", encoding="utf-8")
            (d / "zz_generated.go").write_text("package x\n// pivot_root execve unix.Mount", encoding="utf-8")
            fixture = d / "testdata" / "fixture.go"
            fixture.parent.mkdir(parents=True)
            fixture.write_text("package x\n// pivot_root execve unix.Mount", encoding="utf-8")
            out = rank(root)
            self.assertEqual([x["path"] for x in out], ["cmd/nvidia-cdi-hook/cudacompat/real.go"])

    def test_non_linux_platform_sources_are_removed_before_scoring(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            d = root / "cmd" / "nvidia-cdi-hook" / "create-symlinks"
            d.mkdir(parents=True)
            (d / "container-root_linux.go").write_text("package x\n// filepath.Join containerRoot", encoding="utf-8")
            (d / "container_root_other.go").write_text("package x\n// pivot_root execve unix.Mount Symlink Symlink", encoding="utf-8")
            (d / "helper_windows.go").write_text("package x\n// pivot_root execve unix.Mount", encoding="utf-8")
            out = rank(root)
            self.assertEqual([x["path"] for x in out], ["cmd/nvidia-cdi-hook/create-symlinks/container-root_linux.go"])


if __name__ == "__main__":
    unittest.main()
