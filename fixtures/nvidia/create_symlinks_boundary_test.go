//go:build linux

package symlinks

import (
    "os"
    "path/filepath"
    "testing"

    testlog "github.com/sirupsen/logrus/hooks/test"
)

func boundaryCommand() *command {
    logger, _ := testlog.NewNullLogger()
    return &command{logger: logger}
}

func TestDaisyCreateSymlinksBoundary_AbsoluteParentSymlinkCannotWriteHostOutside(t *testing.T) {
    hostOutside := t.TempDir()
    containerRoot := t.TempDir()
    parent := filepath.Join(containerRoot, "lib")
    if err := os.MkdirAll(parent, 0755); err != nil {
        t.Fatal(err)
    }
    if err := os.Symlink(hostOutside, filepath.Join(parent, "escape")); err != nil {
        t.Fatal(err)
    }

    _ = boundaryCommand().createSymlinkInRoot(containerRoot, "libfoo.so.1", "/lib/escape/libfoo.so")

    if _, err := os.Lstat(filepath.Join(hostOutside, "libfoo.so")); err == nil {
        t.Fatal("symlink creation escaped container root through absolute parent symlink")
    }
}

func TestDaisyCreateSymlinksBoundary_RelativeParentSymlinkCannotWriteHostOutside(t *testing.T) {
    hostOutside := t.TempDir()
    containerRoot := t.TempDir()
    parent := filepath.Join(containerRoot, "lib")
    if err := os.MkdirAll(parent, 0755); err != nil {
        t.Fatal(err)
    }

    rel, err := filepath.Rel(parent, hostOutside)
    if err != nil {
        t.Fatal(err)
    }
    if err := os.Symlink(rel, filepath.Join(parent, "escape")); err != nil {
        t.Fatal(err)
    }

    _ = boundaryCommand().createSymlinkInRoot(containerRoot, "libfoo.so.1", "/lib/escape/libfoo.so")

    if _, err := os.Lstat(filepath.Join(hostOutside, "libfoo.so")); err == nil {
        t.Fatal("symlink creation escaped container root through relative parent symlink")
    }
}

func TestDaisyCreateSymlinksBoundary_NormalInRootCreationStillWorks(t *testing.T) {
    containerRoot := t.TempDir()
    if err := os.MkdirAll(filepath.Join(containerRoot, "lib"), 0755); err != nil {
        t.Fatal(err)
    }

    if err := boundaryCommand().createSymlinkInRoot(containerRoot, "libfoo.so.1", "/lib/libfoo.so"); err != nil {
        t.Fatal(err)
    }
    target, err := os.Readlink(filepath.Join(containerRoot, "lib", "libfoo.so"))
    if err != nil {
        t.Fatal(err)
    }
    if target != "libfoo.so.1" {
        t.Fatalf("unexpected in-root symlink target: %q", target)
    }
}
