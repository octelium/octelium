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
	"bufio"
	"context"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/apis/main/metav1"
	"github.com/octelium/octelium/cluster/common/sshutils"
	"github.com/octelium/octelium/cluster/common/tests"
	"github.com/octelium/octelium/cluster/vigil/vigil/loadbalancer"
	"github.com/octelium/octelium/cluster/vigil/vigil/modes"
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

func TestConnectUpstream(t *testing.T) {
	tst, err := tests.Initialize(nil)
	require.Nil(t, err)
	t.Cleanup(func() { tst.Destroy() })
	octeliumC := tst.C.OcteliumC

	userSigner, err := sshutils.GenerateSigner()
	require.Nil(t, err)
	svc := &corev1.Service{Metadata: &metav1.Metadata{Name: "test.default"}, Spec: &corev1.Service_Spec{}}

	upstreamSrv, err := newTestServer(t.Context(), octeliumC, true, nil, nil)
	require.Nil(t, err)
	require.Nil(t, upstreamSrv.run("127.0.0.1:0"))
	t.Cleanup(func() { upstreamSrv.close() })
	addr := upstreamSrv.lis.Addr().String()

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	var deadline time.Time
	c := &dctx{
		opts: &modes.Opts{
			GetUpstream: func(ctx context.Context, opts *modes.Opts, reqCtx *corev1.RequestContext) (*loadbalancer.Upstream, error) {
				deadline, _ = ctx.Deadline()
				return &loadbalancer.Upstream{HostPort: addr}, nil
			},
		},
		svcConfig: &corev1.Service_Spec_Config{
			Type: &corev1.Service_Spec_Config_Ssh{Ssh: &corev1.Service_Spec_Config_SSH{User: "root"}},
		},
	}
	defer c.close()

	startedAt := time.Now()
	require.Nil(t, c.connect(ctx, octeliumC, svc, nil, userSigner, nil))
	assert.WithinRange(t, deadline, startedAt.Add(upstreamConnectTimeout), time.Now().Add(upstreamConnectTimeout))
	assert.NotNil(t, c.remoteConn.netConn)

	cancel()
	time.Sleep(500 * time.Millisecond)

	ok, _, err := c.remoteConn.sshClient.SendRequest("keepalive@openssh.com", true, nil)
	assert.Nil(t, err)
	assert.True(t, ok)
}

func TestConnectUpstreamStalled(t *testing.T) {
	tst, err := tests.Initialize(nil)
	require.Nil(t, err)
	t.Cleanup(func() { tst.Destroy() })
	octeliumC := tst.C.OcteliumC

	userSigner, err := sshutils.GenerateSigner()
	require.Nil(t, err)
	svc := &corev1.Service{Metadata: &metav1.Metadata{Name: "test.default"}, Spec: &corev1.Service_Spec{}}

	for _, tc := range []struct {
		name     string
		stage    string
		canceled bool
	}{
		{"banner", "banner", false},
		{"kex", "kex", false},
		{"auth", "auth", false},
		{"banner canceled", "banner", true},
		{"kex canceled", "kex", true},
		{"auth canceled", "auth", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			timeout := time.Second
			if tc.canceled {
				timeout = time.Minute
			}
			ctx, cancel := context.WithTimeout(t.Context(), timeout)
			defer cancel()

			var stallOnce sync.Once
			stallCh := make(chan struct{})
			stall := func() {
				stallOnce.Do(func() { close(stallCh) })
			}
			releaseCh := make(chan struct{})

			upstreamSrv, err := newTestServer(ctx, octeliumC, false, nil,
				func(conn ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
					stall()
					<-releaseCh
					return nil, nil
				})
			require.Nil(t, err)

			lis, err := net.Listen("tcp", "127.0.0.1:0")
			require.Nil(t, err)
			defer lis.Close()

			closedCh := make(chan struct{})
			go func() {
				conn, err := lis.Accept()
				if err != nil {
					return
				}
				defer conn.Close()

				switch tc.stage {
				case "auth":
					if _, _, _, err := ssh.NewServerConn(conn, upstreamSrv.sshConfig); err == nil {
						return
					}
				default:
					r := bufio.NewReader(conn)
					if _, err := r.ReadString('\n'); err != nil {
						return
					}
					if tc.stage == "kex" {
						if _, err := conn.Write([]byte("SSH-2.0-OpenSSH_9.6\r\n")); err != nil {
							return
						}
						if _, err := r.ReadByte(); err != nil {
							return
						}
					}
					stall()
					io.Copy(io.Discard, r)
				}
				close(closedCh)
			}()

			if tc.canceled {
				go func() {
					select {
					case <-stallCh:
						cancel()
					case <-ctx.Done():
					}
				}()
			}

			c := &dctx{
				opts: &modes.Opts{
					GetUpstream: func(ctx context.Context, opts *modes.Opts, reqCtx *corev1.RequestContext) (*loadbalancer.Upstream, error) {
						return &loadbalancer.Upstream{HostPort: lis.Addr().String()}, nil
					},
				},
				svcConfig: &corev1.Service_Spec_Config{
					Type: &corev1.Service_Spec_Config_Ssh{Ssh: &corev1.Service_Spec_Config_SSH{User: "root"}},
				},
			}

			errCh := make(chan error, 1)
			go func() {
				errCh <- c.connect(ctx, octeliumC, svc, nil, userSigner, nil)
			}()

			select {
			case err := <-errCh:
				if tc.canceled {
					assert.ErrorIs(t, err, context.Canceled)
				} else {
					assert.ErrorIs(t, err, context.DeadlineExceeded)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("connect did not return")
			}

			select {
			case <-stallCh:
			default:
				t.Fatal("upstream did not reach the stalled stage")
			}

			assert.Nil(t, c.remoteConn.sshClient)
			assert.Nil(t, c.remoteConn.netConn)

			close(releaseCh)

			select {
			case <-closedCh:
			case <-time.After(5 * time.Second):
				t.Fatal("upstream conn was not closed")
			}
		})
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
