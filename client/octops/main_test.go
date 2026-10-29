package main

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/octelium/octelium/client/octops/commands"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCLIProcess(t *testing.T) {
	if os.Getenv("OCTOPS_TEST_RUN_MAIN") != "true" {
		return
	}
	for i, arg := range os.Args {
		if arg == "--" {
			commands.Cmd.SetArgs(os.Args[i+1:])
			main()
			os.Exit(0)
		}
	}
	t.Fatal("missing command arguments")
}

func TestMainHelp(t *testing.T) {
	var out strings.Builder
	previous := commands.Cmd.OutOrStdout()
	commands.Cmd.SetOut(&out)
	commands.Cmd.SetArgs([]string{"--help"})
	defer func() { commands.Cmd.SetOut(previous); commands.Cmd.SetArgs(nil) }()
	main()
	for _, command := range []string{"init", "upgrade", "install-package", "certificate", "uninstall", "version"} {
		assert.Contains(t, out.String(), command)
	}
}

func TestCLICommandsProcess(t *testing.T) {
	for _, tc := range []struct {
		name string
		args []string
		code int
		want string
	}{
		{"help", []string{"--help"}, 0, "Octelium Cluster operations"},
		{"version", []string{"version", "--out=json"}, 0, `"apiVersion"`},
		{"missing domain", []string{"upgrade"}, 1, "accepts 1 arg"},
		{"too many domains", []string{"uninstall", "one", "two"}, 1, "accepts 1 arg"},
		{"unknown flag", []string{"init", "example.com", "--unknown"}, 1, "unknown flag"},
		{"missing kubeconfig", []string{"init", "example.com", "--bootstrap=-", "--kubeconfig=" + filepath.Join(t.TempDir(), "missing")}, 1, "does not exist"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			args := append([]string{"-test.run=^TestCLIProcess$", "--"}, tc.args...)
			cmd := exec.CommandContext(ctx, os.Args[0], args...)
			cmd.Env = append(os.Environ(), "OCTOPS_TEST_RUN_MAIN=true", "OCTELIUM_HOME=mem", "OCTELIUM_LOGOUT=", "OCTELIUM_AUTH_PROXY_SOCKET=", "OCTELIUM_ACCESS_TOKEN=", "OCTELIUM_PRODUCTION=true", "OCTELIUM_DEV=false", "DEBIAN_FRONTEND=noninteractive", "NO_COLOR=1")
			out, err := cmd.CombinedOutput()
			if tc.code == 0 {
				require.NoError(t, err, "%s", out)
			} else {
				var exitErr *exec.ExitError
				require.ErrorAs(t, err, &exitErr, "%s", out)
				assert.Equal(t, tc.code, exitErr.ExitCode())
			}
			assert.Contains(t, string(out), tc.want)
			assert.NotContains(t, string(out), "panic:")
		})
	}
}
