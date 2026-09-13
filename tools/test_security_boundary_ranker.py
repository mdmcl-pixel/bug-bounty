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
            sensitive.write_text("package x\nfunc f(){ _ = os.OpenRoot; _ = unix.Mount }", encoding="utf-8")
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
            p.write_text("package x\nfunc f(){ _ = unix.Mount }", encoding="utf-8")
            self.assertEqual(rank(root), [])

    def test_limit_is_respected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            d = root / "internal" / "oci"
            d.mkdir(parents=True)
            for i in range(3):
                (d / f"{i}.go").write_text("package x\nfunc f(){ _ = filepath.Join; _ = containerRoot }", encoding="utf-8")
            self.assertEqual(len(rank(root, 2)), 2)

    def test_public_fix_overlap_is_penalized_and_adjacent_file_boosted(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            d = root / "internal" / "ldconfig"
            d.mkdir(parents=True)
            known = d / "known.go"
            adjacent = d / "adjacent.go"
            known.write_text("package x\nfunc f(){ _ = unix.Mount; _ = os.OpenRoot; _ = filepath.Join }", encoding="utf-8")
            adjacent.write_text("package x\nfunc f(){ _ = unix.Mount; _ = os.OpenRoot; _ = filepath.Join }", encoding="utf-8")
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

    def test_test_fixture_generated_and_non_linux_sources_are_removed(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            d = root / "cmd" / "nvidia-cdi-hook" / "cudacompat"
            d.mkdir(parents=True)
            (d / "real.go").write_text("package x\nfunc f(){ _ = filepath.Join; _ = containerRoot }", encoding="utf-8")
            (d / "loud_test.go").write_text("package x\nfunc f(){ _ = unix.Mount }", encoding="utf-8")
            (d / "zz_generated.go").write_text("package x\nfunc f(){ _ = unix.Mount }", encoding="utf-8")
            (d / "helper_windows.go").write_text("package x\nfunc f(){ _ = unix.Mount }", encoding="utf-8")
            fixture = d / "testdata" / "fixture.go"
            fixture.parent.mkdir(parents=True)
            fixture.write_text("package x\nfunc f(){ _ = unix.Mount }", encoding="utf-8")
            out = rank(root)
            self.assertEqual([x["path"] for x in out], ["cmd/nvidia-cdi-hook/cudacompat/real.go"])

    def test_declaration_only_files_are_removed_before_scoring(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            d = root / "pkg" / "nvcdi"
            d.mkdir(parents=True)
            (d / "api.go").write_text("package nvcdi\nconst CreateSymlinksHook = Symlink\ntype I interface{ Bundle() }", encoding="utf-8")
            (d / "impl.go").write_text("package nvcdi\nfunc f(){ _ = filepath.Join; _ = driverRoot }", encoding="utf-8")
            out = rank(root)
            self.assertEqual([x["path"] for x in out], ["pkg/nvcdi/impl.go"])

    def test_configuration_only_file_is_removed(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            d = root / "pkg" / "nvcdi"
            d.mkdir(parents=True)
            (d / "options.go").write_text("package nvcdi\nfunc WithRoot(){ _ = driverRoot; _ = filepath.Join }", encoding="utf-8")
            (d / "impl.go").write_text("package nvcdi\nfunc f(){ _ = os.OpenRoot; _ = containerRoot }", encoding="utf-8")
            out = rank(root)
            self.assertEqual([x["path"] for x in out], ["pkg/nvcdi/impl.go"])

    def test_configuration_file_with_privileged_operation_remains(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            d = root / "internal" / "oci"
            d.mkdir(parents=True)
            (d / "config.go").write_text("package oci\nfunc apply(){ _ = unix.Mount; _ = containerRoot }", encoding="utf-8")
            out = rank(root)
            self.assertEqual([x["path"] for x in out], ["internal/oci/config.go"])

    def test_input_to_privileged_sink_proximity_is_boosted(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            d = root / "internal" / "oci"
            d.mkdir(parents=True)
            (d / "source_sink.go").write_text("package oci\nfunc f(){ _ = os.Stdin; _ = os.OpenRoot; _ = containerRoot }", encoding="utf-8")
            (d / "sink_only.go").write_text("package oci\nfunc f(){ _ = os.OpenRoot; _ = containerRoot }", encoding="utf-8")
            out = rank(root)
            self.assertEqual(out[0]["path"], "internal/oci/source_sink.go")
            self.assertEqual(out[0]["source_sink_bonus"], 6)
            self.assertTrue(out[0]["input_proximity_signals"])
            self.assertTrue(out[0]["privileged_sink_signals"])

    def test_direct_public_fix_package_dependency_is_reference_only(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            wrapper = root / "cmd" / "nvidia-cdi-hook" / "update-ldcache" / "wrapper.go"
            wrapper.parent.mkdir(parents=True)
            wrapper.write_text(
                'package x\nimport "github.com/NVIDIA/nvidia-container-toolkit/internal/ldconfig"\nfunc f(){ _ = containerRoot; _ = filepath.Join; _ = ldconfig.NewRunner }',
                encoding="utf-8",
            )
            clean = root / "internal" / "oci" / "clean.go"
            clean.parent.mkdir(parents=True)
            clean.write_text("package oci\nfunc f(){ _ = os.OpenRoot; _ = containerRoot }", encoding="utf-8")
            exclusions = {"public_fixes": [{
                "commit": "fix123",
                "classification": "PUBLIC_FIX_EXCLUDE",
                "affected_files": ["internal/ldconfig/ldconfig_linux.go"],
            }]}
            out = rank(root, exclusions=exclusions)
            item = next(x for x in out if x["path"].endswith("wrapper.go"))
            self.assertTrue(item["public_fix_dependency"])
            self.assertEqual(item["public_fix_dependency_refs"], ["fix123"])
            self.assertEqual(item["classification"], "PUBLIC_FIX_DEPENDENCY_REFERENCE_ONLY")
            self.assertFalse(item["submission_ready"])

    def test_host_configuration_only_candidate_is_down_ranked(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            d = root / "pkg" / "nvcdi"
            d.mkdir(parents=True)
            host_cfg = d / "host.go"
            boundary = d / "boundary.go"
            host_cfg.write_text(
                "package nvcdi\nfunc f(){ _ = l.csv.Files; _ = filepath.Join; _ = driverRoot }",
                encoding="utf-8",
            )
            boundary.write_text(
                "package nvcdi\nfunc f(){ _ = filepath.Join; _ = driverRoot }",
                encoding="utf-8",
            )
            out = rank(root)
            self.assertEqual(out[0]["path"], "pkg/nvcdi/boundary.go")
            host_item = next(x for x in out if x["path"].endswith("host.go"))
            self.assertTrue(host_item["host_configuration_only"])
            self.assertEqual(host_item["host_configuration_penalty"], 5)
            self.assertTrue(host_item["host_configuration_signals"])

    def test_explicit_public_fix_dependent_file_is_reference_only(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            dependent = root / "pkg" / "nvcdi" / "transform" / "root" / "builder.go"
            dependent.parent.mkdir(parents=True)
            dependent.write_text(
                "package root\nfunc f(){ _ = filepath.Join; _ = driverRoot }",
                encoding="utf-8",
            )
            exclusions = {"public_fixes": [{
                "commit": "fix-root",
                "classification": "PUBLIC_FIX_EXCLUDE",
                "affected_files": ["pkg/nvcdi/transform/root/root.go"],
                "dependent_files": ["pkg/nvcdi/transform/root/builder.go"],
            }]}
            out = rank(root, exclusions=exclusions)
            item = out[0]
            self.assertTrue(item["public_fix_dependency"])
            self.assertEqual(item["public_fix_dependency_refs"], ["fix-root"])
            self.assertEqual(item["classification"], "PUBLIC_FIX_DEPENDENCY_REFERENCE_ONLY")
            self.assertEqual(item["adjacency_bonus"], 0)
            self.assertFalse(item["submission_ready"])


if __name__ == "__main__":
    unittest.main()
