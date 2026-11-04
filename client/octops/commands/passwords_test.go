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

package commands

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestInitCommandRejectsInvalidPasswordReferencesE2E(t *testing.T) {
	for _, storage := range []string{"postgres", "redis"} {
		for _, ref := range []string{"{}", "{name: ''}", "{name: Credentials}", "{name: credentials, namespace: a/b}", "{name: credentials, key: a/b}"} {
			for _, stdin := range []bool{false, true} {
				t.Run(fmt.Sprintf("%s/%s/stdin=%t", storage, ref, stdin), func(t *testing.T) {
					c, config := newTestKubernetes(t)
					pg, redis := "password: private-postgres-value", "password: private-redis-value"
					if storage == "postgres" {
						pg = "passwordFromSecret: " + ref
					} else {
						redis = "passwordFromSecret: " + ref
					}
					bootstrap := filepath.Join(t.TempDir(), "bootstrap.yaml")
					require.NoError(t, os.WriteFile(bootstrap, []byte(fmt.Sprintf("spec:\n  primaryStorage:\n    postgresql: {host: postgres, username: installer, %s}\n  secondaryStorage:\n    redis: {host: redis, %s}\n", pg, redis)), 0600))
					if stdin {
						file, err := os.Open(bootstrap)
						require.NoError(t, err)
						previous := os.Stdin
						os.Stdin = file
						t.Cleanup(func() { os.Stdin = previous; file.Close() })
						bootstrap = "-"
					}
					credential := filepath.Join(t.TempDir(), "initial-token")
					t.Setenv("OCTELIUM_AUTH_TOKEN_SAVE_PATH", credential)
					output, err := executeTestCommand(t, t.Context(), "init", "example.com", "--bootstrap="+bootstrap, "--kubeconfig="+config, "--version=1.2.3")
					require.ErrorContains(t, err, "passwordFromSecret")
					assert.Empty(t, c.Actions())
					assert.NoFileExists(t, credential)
					for _, value := range []string{"private-postgres-value", "private-redis-value"} {
						assert.NotContains(t, output, value)
						assert.NotContains(t, err.Error(), value)
					}
				})
			}
		}
	}
}
