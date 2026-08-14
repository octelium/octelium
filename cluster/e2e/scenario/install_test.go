/*
 * Copyright Octelium Labs, LLC. All rights reserved.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License version 3,
 * as published by the Free Software Foundation of the License.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

package scenario

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestLoginError(t *testing.T) {
	t.Run("the cobra usage text is dropped", func(t *testing.T) {
		out := `Error: rpc error: code = Unavailable desc = connection error: ` +
			`desc = "transport: Error while dialing: dial tcp 127.0.0.1:443: connect: connection refused"
Usage:
  octelium login [flags]

Examples:

octeliumctl login --auth-token <AUTHENTICATION_TOKEN>

Flags:
      --assertion string    Authenticate using an assertion.
      --auth-token string   Authentication Token
  -h, --help                help for login

Global Flags:
      --domain string    The Cluster Domain

gRPC error Unavailable: connection error`

		got := loginError(out)

		assert.Contains(t, got, "connection refused")
		assert.NotContains(t, got, "Usage:")
		assert.NotContains(t, got, "--auth-token string")
		assert.Less(t, len(got), 200)
	})

	t.Run("output with no Error line still loses the usage text", func(t *testing.T) {
		got := loginError("something went wrong\nUsage:\n  octelium login [flags]\n")

		assert.Equal(t, "something went wrong", got)
	})

	t.Run("a short message is kept whole", func(t *testing.T) {
		assert.Equal(t, "permission denied", loginError("permission denied\n"))
	})

	t.Run("empty", func(t *testing.T) {
		assert.Empty(t, loginError(""))
	})
}
