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


if __name__ == "__main__":
    unittest.main()
