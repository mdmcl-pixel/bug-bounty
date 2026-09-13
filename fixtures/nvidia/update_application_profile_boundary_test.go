//go:build linux

package updateapplicationprofile

import (
    "os"
    "path/filepath"
    "testing"
)

func TestDaisyUpdateApplicationProfileBoundary_SymlinkCannotWriteHostOutside(t *testing.T) {
    hostOutside := t.TempDir()
    containerRootDir := t.TempDir()

    etc := filepath.Join(containerRootDir, "etc")
    if err := os.MkdirAll(etc, 0755); err != nil {
        t.Fatal(err)
    }
    if err := os.Symlink(hostOutside, filepath.Join(etc, "nvidia")); err != nil {
        t.Fatal(err)
    }

    root, err := os.OpenRoot(containerRootDir)
    if err != nil {
        t.Fatal(err)
    }
    defer root.Close()

    _ = root.MkdirAll(applicationProfileDir, 0555)
    _ = root.WriteFile(applicationProfileFile, []byte("outside-should-not-change"), 0444)

    outsideFile := filepath.Join(hostOutside, "nvidia-application-profiles-rc.d", "10-container.conf")
    if _, err := os.Stat(outsideFile); err == nil {
        t.Fatal("application-profile write escaped container root through symlink")
    }
}

func TestDaisyUpdateApplicationProfileBoundary_NormalInRootWriteWorks(t *testing.T) {
    containerRootDir := t.TempDir()
    if err := os.MkdirAll(filepath.Join(containerRootDir, "etc", "nvidia"), 0755); err != nil {
        t.Fatal(err)
    }

    root, err := os.OpenRoot(containerRootDir)
    if err != nil {
        t.Fatal(err)
    }
    defer root.Close()

    if err := root.MkdirAll(applicationProfileDir, 0555); err != nil {
        t.Fatal(err)
    }
    expected := []byte("profile")
    if err := root.WriteFile(applicationProfileFile, expected, 0444); err != nil {
        t.Fatal(err)
    }
    got, err := os.ReadFile(filepath.Join(containerRootDir, applicationProfileFile))
    if err != nil {
        t.Fatal(err)
    }
    if string(got) != string(expected) {
        t.Fatalf("unexpected profile contents: %q", got)
    }
}
