package daemon

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/octelium/octelium/apis/client/daemonv1"
	"github.com/octelium/octelium/client/octelium/commands/daemon/ipc"
	"github.com/octelium/octelium/client/octelium/commands/daemon/server"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
)

func testDaemonAddress(t *testing.T) string {
	t.Helper()
	if runtime.GOOS == "windows" {
		return fmt.Sprintf(`\\.\pipe\octelium-run-%d-%d`, os.Getpid(), time.Now().UnixNano())
	}
	dir, err := os.MkdirTemp("", "oct-run-")
	require.NoError(t, err)
	t.Cleanup(func() { os.RemoveAll(dir) })
	return filepath.Join(dir, "daemon.sock")
}

func TestRunServerCancellationClosesActiveStatusWatchAndReleasesAddress(t *testing.T) {
	addr := testDaemonAddress(t)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		done <- runServer(ctx, &server.Opts{ListenAddress: addr, StateDir: t.TempDir()})
	}()
	conn, err := grpc.NewClient("passthrough:///"+addr,
		grpc.WithTransportCredentials(ipc.NewTransportCredentials()), grpc.WithContextDialer(ipc.Dial))
	require.NoError(t, err)
	defer conn.Close()
	cl := daemonv1.NewMainServiceClient(conn)
	rpcCtx, rpcCancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer rpcCancel()
	require.Eventually(t, func() bool {
		_, err := cl.GetInfo(rpcCtx, &daemonv1.GetInfoRequest{})
		return err == nil
	}, 4*time.Second, 10*time.Millisecond)
	watch, err := cl.WatchStatus(rpcCtx, &daemonv1.WatchStatusRequest{})
	require.NoError(t, err)
	_, err = watch.Recv()
	require.NoError(t, err)
	_, err = runServerListenConflict(t, addr)
	require.Error(t, err)
	cancel()
	select {
	case err := <-done:
		assert.NoError(t, err)
	case <-time.After(2 * time.Second):
		t.Fatal("the daemon must stop promptly with an active status watcher")
	}
	_, err = watch.Recv()
	assert.Error(t, err)
	lis, err := ipc.Listen(addr)
	require.NoError(t, err, "a stopped daemon must release the IPC address and singleton lock")
	assert.NoError(t, lis.Close())
}

func runServerListenConflict(t *testing.T, addr string) (time.Duration, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	started := time.Now()
	err := runServer(ctx, &server.Opts{ListenAddress: addr, StateDir: t.TempDir()})
	return time.Since(started), err
}

func TestRunServerRejectsInvalidStateDirectory(t *testing.T) {
	file := filepath.Join(t.TempDir(), "file")
	require.NoError(t, os.WriteFile(file, []byte("state is not a directory"), 0600))
	err := runServer(t.Context(), &server.Opts{ListenAddress: testDaemonAddress(t), StateDir: file})
	assert.Error(t, err)
}

func TestRunServerAlreadyCanceledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	addr := testDaemonAddress(t)
	assert.NoError(t, runServer(ctx, &server.Opts{ListenAddress: addr, StateDir: t.TempDir()}))
	lis, err := ipc.Listen(addr)
	require.NoError(t, err)
	assert.NoError(t, lis.Close())
}
