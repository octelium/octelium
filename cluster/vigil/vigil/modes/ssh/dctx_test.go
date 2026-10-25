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

package ssh

import (
	"context"
	"net"
	"strings"
	"testing"

	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/apis/main/metav1"
	"github.com/octelium/octelium/cluster/common/sshutils"
	"github.com/octelium/octelium/cluster/common/tests"
	"github.com/octelium/octelium/cluster/vigil/vigil/loadbalancer"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
)

type tstSSHConn struct {
	ssh.Conn
	user string
}

func (c *tstSSHConn) User() string {
	return c.user
}

func TestEffectiveSSHUser(t *testing.T) {
	for _, user := range []string{"", "root", "user@host", "user\x00other", strings.Repeat("u", 64*1024)} {
		for _, configured := range []string{"", "configured-user"} {
			c := &dctx{
				sshConn: &ssh.ServerConn{Conn: &tstSSHConn{user: user}},
				svcConfig: &corev1.Service_Spec_Config{
					Type: &corev1.Service_Spec_Config_Ssh{Ssh: &corev1.Service_Spec_Config_SSH{User: configured}},
				},
			}
			want := user
			if configured != "" {
				want = configured
			}
			assert.Equal(t, want, c.getEffectiveSSHUser())
		}
	}
}

func TestClientHostKey(t *testing.T) {
	ctx := t.Context()
	tst, err := tests.Initialize(nil)
	require.Nil(t, err)
	t.Cleanup(func() { tst.Destroy() })
	signer, err := sshutils.GenerateSigner()
	require.Nil(t, err)
	other, err := sshutils.GenerateSigner()
	require.Nil(t, err)
	svc := &corev1.Service{Metadata: &metav1.Metadata{Name: "test.default"}, Spec: &corev1.Service_Spec{}}

	for _, tc := range []struct {
		name string
		key  *corev1.Service_Spec_Config_SSH_UpstreamHostKey
		fail bool
	}{
		{"fixed key", &corev1.Service_Spec_Config_SSH_UpstreamHostKey{
			Type: &corev1.Service_Spec_Config_SSH_UpstreamHostKey_Key{Key: string(ssh.MarshalAuthorizedKey(signer.PublicKey()))},
		}, false},
		{"empty key", &corev1.Service_Spec_Config_SSH_UpstreamHostKey{
			Type: &corev1.Service_Spec_Config_SSH_UpstreamHostKey_Key{},
		}, true},
		{"invalid key", &corev1.Service_Spec_Config_SSH_UpstreamHostKey{
			Type: &corev1.Service_Spec_Config_SSH_UpstreamHostKey_Key{Key: "ssh-ed25519 invalid"},
		}, true},
		{"false insecure", &corev1.Service_Spec_Config_SSH_UpstreamHostKey{
			Type: &corev1.Service_Spec_Config_SSH_UpstreamHostKey_InsecureIgnoreHostKey{},
		}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := &dctx{svcConfig: &corev1.Service_Spec_Config{
				Type: &corev1.Service_Spec_Config_Ssh{Ssh: &corev1.Service_Spec_Config_SSH{User: "root", UpstreamHostKey: tc.key}},
			}}
			cfg, err := c.getClientConfig(ctx, tst.C.OcteliumC, svc, signer, nil, &loadbalancer.Upstream{})
			if tc.fail {
				assert.NotNil(t, err)
				assert.Nil(t, cfg)
				return
			}
			require.Nil(t, err)
			assert.Equal(t, "root", cfg.User)
			assert.Nil(t, cfg.HostKeyCallback("example.com:22", &net.TCPAddr{}, signer.PublicKey()))
			assert.NotNil(t, cfg.HostKeyCallback("example.com:22", &net.TCPAddr{}, other.PublicKey()))
		})
	}

	c := &dctx{svcConfig: &corev1.Service_Spec_Config{
		Type: &corev1.Service_Spec_Config_Ssh{Ssh: &corev1.Service_Spec_Config_SSH{User: "root"}},
	}}
	for _, key := range [][]byte{{}, {1}, make([]byte, 31), make([]byte, 33), make([]byte, 64*1024)} {
		cfg, err := c.getClientConfig(context.Background(), tst.C.OcteliumC, svc, signer, nil,
			&loadbalancer.Upstream{IsESSH: true, Ed25519PublicKey: key})
		assert.NotNil(t, err)
		assert.Nil(t, cfg)
	}
}

func TestDirectTCPIPMalformed(t *testing.T) {
	valid := ssh.Marshal(&reqDirectTCPIP{Host: "127.0.0.1", Port: 443, Orig: "192.0.2.1", OrigPort: 1234})
	for n := range len(valid) {
		got, err := parseDirectTCPIPReq(valid[:n])
		assert.NotNil(t, err)
		assert.Nil(t, got)
	}
	got, err := parseDirectTCPIPReq(append(append([]byte(nil), valid...), 0))
	assert.NotNil(t, err)
	assert.Nil(t, got)
	got, err = parseDirectTCPIPReq(valid)
	require.Nil(t, err)
	assert.Equal(t, "127.0.0.1", got.Host)
	assert.Equal(t, uint32(443), got.Port)
}

func FuzzDirectTCPIPRequest(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte{255, 255, 255, 255})
	f.Add(ssh.Marshal(&reqDirectTCPIP{Host: "example.com", Port: 443}))
	f.Fuzz(func(t *testing.T, data []byte) {
		got, err := parseDirectTCPIPReq(data)
		if err != nil {
			assert.Nil(t, got)
			return
		}
		require.NotNil(t, got)
		assert.Equal(t, data, ssh.Marshal(got))
	})
}
