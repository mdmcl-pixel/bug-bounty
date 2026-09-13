//go:build linux

package cudacompat

import (
    "os"
    "path/filepath"
    "testing"
)

func TestDaisyCudacompatBoundary_OpenAbsoluteSymlinkCannotReadHostOutside(t *testing.T) {
    hostOutside := t.TempDir()
    marker := filepath.Join(hostOutside, "outside-marker")
    if err := os.WriteFile(marker, []byte("HOST-OUTSIDE"), 0600); err != nil {
        t.Fatal(err)
    }

    containerRootDir := t.TempDir()
    link := filepath.Join(containerRootDir, "escape")
    if err := os.Symlink(marker, link); err != nil {
        t.Fatal(err)
    }

    r, err := newRoot(containerRootDir)
    if err != nil {
        t.Fatal(err)
    }
    defer r.Close()

    f, err := r.Open("/escape")
    if err == nil {
        defer f.Close()
        b, readErr := os.ReadFile(f.Name())
        if readErr == nil && string(b) == "HOST-OUTSIDE" {
            t.Fatal("container-root open escaped to host outside marker")
        }
    }
}

func TestDaisyCudacompatBoundary_GlobAbsoluteSymlinkCannotDiscoverHostOutside(t *testing.T) {
    hostOutside := t.TempDir()
    outsideLib := filepath.Join(hostOutside, "libcuda.so.999.1")
    if err := os.WriteFile(outsideLib, []byte("outside"), 0600); err != nil {
        t.Fatal(err)
    }

    containerRootDir := t.TempDir()
    compatParent := filepath.Join(containerRootDir, "usr", "local", "cuda")
    if err := os.MkdirAll(compatParent, 0755); err != nil {
        t.Fatal(err)
    }
    if err := os.Symlink(hostOutside, filepath.Join(compatParent, "compat")); err != nil {
        t.Fatal(err)
    }

    r, err := newRoot(containerRootDir)
    if err != nil {
        t.Fatal(err)
    }
    defer r.Close()

    files, err := r.globFiles("/usr/local/cuda/compat/libcuda.so.*.*")
    if err == nil && len(files) != 0 {
        t.Fatalf("container-root glob escaped to host outside files: %v", files)
    }
}

func TestDaisyCudacompatBoundary_MkdirAndCreateCannotWriteThroughHostSymlink(t *testing.T) {
    hostOutside := t.TempDir()
    containerRootDir := t.TempDir()

    if err := os.Symlink(hostOutside, filepath.Join(containerRootDir, "etc")); err != nil {
        t.Fatal(err)
    }

    r, err := newRoot(containerRootDir)
    if err != nil {
        t.Fatal(err)
    }
    defer r.Close()

    _ = r.MkdirAll("/etc/ld.so.conf.d", 0755)
    if f, err := r.Create("/etc/ld.so.conf.d/daisy.conf"); err == nil {
        _, _ = f.WriteString("/should-stay-in-container\n")
        _ = f.Close()
    }

    hostWritten := filepath.Join(hostOutside, "ld.so.conf.d", "daisy.conf")
    if _, err := os.Stat(hostWritten); err == nil {
        t.Fatal("container-root write escaped through host symlink")
    }
}
