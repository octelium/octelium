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

package suite

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGetManagedSSHCA(t *testing.T) {
	home := t.TempDir()

	_, err := getManagedSSHCA(home)
	assert.NotNil(t, err)

	require.Nil(t, os.Mkdir(filepath.Join(home, ".ssh"), 0o700))
	authorizedKeys := filepath.Join(home, ".ssh", "authorized_keys")

	require.Nil(t, os.WriteFile(authorizedKeys, []byte(
		"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIA user@host\n"+
			"cert-authority ecdsa-sha2-nistp256 AAAAE2VjZHNh other-ca\n"), 0o600))
	_, err = getManagedSSHCA(home)
	assert.NotNil(t, err)

	require.Nil(t, os.WriteFile(authorizedKeys, []byte(
		"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIA user@host\n"+
			"cert-authority ecdsa-sha2-nistp256 AAAAE2VjZHNh octelium-managed:example.com\n"), 0o600))
	ca, err := getManagedSSHCA(home)
	require.Nil(t, err)
	assert.Equal(t, "ecdsa-sha2-nistp256 AAAAE2VjZHNh", ca)
}

func TestNewUpstreamSSHService(t *testing.T) {
	svc := newUpstreamSSHService(2222, "alice", "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIA")
	assert.Equal(t, corev1.Service_Spec_SSH, svc.Spec.Mode)
	assert.Equal(t, "ssh://localhost:2222", svc.Spec.Config.GetUpstream().GetUrl())
	assert.Equal(t, "alice", svc.Spec.Config.GetSsh().User)
	assert.Equal(t, "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIA", svc.Spec.Config.GetSsh().GetUpstreamHostKey().GetKey())

	svc = newUpstreamSSHService(2222, "alice", "")
	assert.Equal(t, "alice", svc.Spec.Config.GetSsh().User)
	assert.Nil(t, svc.Spec.Config.GetSsh().UpstreamHostKey)
}
