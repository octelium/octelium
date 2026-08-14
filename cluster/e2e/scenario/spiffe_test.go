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

func TestParseSPIRETrustDomain(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{
			name: "the JSON the helm chart renders into the ConfigMap",
			in: `apiVersion: v1
items:
- apiVersion: v1
  data:
    server.conf: |
      {
        "server": {
          "bind_address": "0.0.0.0",
          "bind_port": "8081",
          "trust_domain": "octelium.local",
          "data_dir": "/run/spire/data",
          "log_level": "info"
        }
      }
  kind: ConfigMap
  metadata:
    name: spire-server
    namespace: spire
kind: List
`,
			want: "octelium.local",
		},
		{
			name: "the HCL form SPIRE also accepts",
			in: `    agent.conf: |
      agent {
        trust_domain = "example.org"
        server_address = "spire-server"
      }
`,
			want: "example.org",
		},
		{
			name: "the chart default, which is what a scenario must not silently accept",
			in:   `          "trust_domain": "example.org",`,
			want: "example.org",
		},
		{
			name: "no trust domain anywhere",
			in: `    bundle.crt: |
      -----BEGIN CERTIFICATE-----
`,
			want: "",
		},
		{
			name: "empty",
			in:   "",
			want: "",
		},
		{
			name: "an unquoted value",
			in:   `  trust_domain: octelium.local`,
			want: "octelium.local",
		},
	}

	for _, tst := range tests {
		t.Run(tst.name, func(t *testing.T) {
			assert.Equal(t, tst.want, parseSPIRETrustDomain(tst.in))
		})
	}
}
