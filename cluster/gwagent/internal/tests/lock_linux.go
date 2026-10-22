package tests

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

func LockGateway(t *testing.T) {
	t.Helper()
	lock, err := os.OpenFile(filepath.Join(os.TempDir(), "octelium-gateway-tests.lock"), os.O_CREATE|os.O_RDWR, 0600)
	require.Nil(t, err)
	t.Cleanup(func() { require.Nil(t, lock.Close()) })
	require.Nil(t, unix.Flock(int(lock.Fd()), unix.LOCK_EX))
}
