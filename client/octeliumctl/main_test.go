// Copyright Octelium Labs, LLC. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/octelium/octelium/client/octeliumctl/commands"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCLIProcess(t *testing.T) {
	if os.Getenv("OCTELIUMCTL_TEST_RUN_MAIN") != "true" {
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
	assert.Contains(t, out.String(), "Manage Cluster resources")
	assert.Contains(t, out.String(), "validate")
	assert.Contains(t, out.String(), "apply")
	assert.Contains(t, out.String(), "--domain")
}

func TestCLIValidationProcess(t *testing.T) {
	valid := filepath.Join(t.TempDir(), "valid.yaml")
	invalid := filepath.Join(t.TempDir(), "invalid.yaml")
	require.NoError(t, os.WriteFile(valid, []byte("kind: User\nmetadata: {name: alice}\nspec: {type: HUMAN}\n"), 0600))
	require.NoError(t, os.WriteFile(invalid, []byte("kind: User\nmetadata: {name: alice}\nspec: {type: INVALID}\n"), 0600))
	for _, itm := range []struct {
		name  string
		args  []string
		stdin string
		code  int
		want  string
	}{
		{"help", []string{"--help"}, "", 0, "Manage Cluster resources"},
		{"valid file", []string{"validate", valid}, "", 0, "All 1 Resources are valid"},
		{"stdin", []string{"validate", "-"}, "kind: Group\nmetadata: {name: engineering}\n", 0, "All 1 Resources are valid"},
		{"invalid enum", []string{"validate", invalid}, "", 1, "Validation failed with 1 errors"},
		{"empty directory", []string{"validate", t.TempDir()}, "", 1, "Could not find any Resources"},
		{"missing input", []string{"validate"}, "", 1, "requires at least 1 arg"},
		{"unknown flag", []string{"get", "user", "--unknown"}, "", 1, "unknown flag"},
	} {
		t.Run(itm.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			args := append([]string{"-test.run=^TestCLIProcess$", "--", "--homedir=" + t.TempDir()}, itm.args...)
			cmd := exec.CommandContext(ctx, os.Args[0], args...)
			cmd.Env = append(os.Environ(), "OCTELIUMCTL_TEST_RUN_MAIN=true", "OCTELIUM_AUTH_PROXY_SOCKET=", "OCTELIUM_ACCESS_TOKEN=", "OCTELIUM_DOMAIN=", "OCTELIUM_LOGOUT=", "OCTELIUM_PRODUCTION=true", "OCTELIUM_DEV=false", "NO_COLOR=1")
			cmd.Stdin = strings.NewReader(itm.stdin)
			out, err := cmd.CombinedOutput()
			if itm.code == 0 {
				require.NoError(t, err, "%s", out)
			} else {
				var exitErr *exec.ExitError
				require.ErrorAs(t, err, &exitErr, "%s", out)
				assert.Equal(t, itm.code, exitErr.ExitCode())
			}
			assert.Contains(t, string(out), itm.want)
			assert.NotContains(t, string(out), "panic:")
		})
	}
}
