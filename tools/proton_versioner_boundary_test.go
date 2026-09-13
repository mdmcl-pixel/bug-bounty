package versioner

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/Masterminds/semver/v3"
	"github.com/stretchr/testify/require"
)

// TestDaisyPostVerificationExecutableTargetSwap confirms a narrow released-code
// behavior for defensive triage only. A valid signed update is verified first;
// the verified executable path is then replaced with a symlink to a harmless
// executable outside the update directory. GetExecutable accepts that symlink
// target after verification. This is evidence of a post-verification target
// swap primitive only; it is NOT a vulnerability or exploitability claim.
func TestDaisyPostVerificationExecutableTargetSwap(t *testing.T) {
	dir := t.TempDir()
	exeName := getExeName("bridge")
	exePath := filepath.Join(dir, exeName)

	kr := createSignedFiles(t, dir, exeName)
	require.NoError(t, os.Chmod(exePath, 0o700))

	version := &Version{
		version: semver.MustParse("9.9.9"),
		path:    dir,
	}
	require.NoError(t, version.VerifyFiles(kr))

	outsideDir := t.TempDir()
	outsideExe := filepath.Join(outsideDir, exeName)
	require.NoError(t, os.WriteFile(outsideExe, []byte("harmless-local-marker"), 0o700))

	require.NoError(t, os.Remove(exePath))
	require.NoError(t, os.Symlink(outsideExe, exePath))

	got, err := version.GetExecutable("bridge")
	require.NoError(t, err)
	require.Equal(t, exePath, got)

	resolved, err := filepath.EvalSymlinks(got)
	require.NoError(t, err)
	require.Equal(t, outsideExe, resolved)
}
