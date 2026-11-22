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
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/apis/main/metav1"
	"github.com/octelium/octelium/apis/rsc/rcorev1"
	"github.com/octelium/octelium/apis/rsc/rmetav1"
	"github.com/octelium/octelium/cluster/common/octeliumc"
	"github.com/octelium/octelium/cluster/common/sshutils"
	"github.com/octelium/octelium/cluster/common/vutils"
	"github.com/octelium/octelium/cluster/vigil/vigil/loadbalancer"
	"github.com/octelium/octelium/cluster/vigil/vigil/modes"
	utils_cert "github.com/octelium/octelium/pkg/utils/cert"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"
	"golang.org/x/crypto/ssh"
	"google.golang.org/grpc"
)

type tstCACoreC struct {
	rcorev1.ResourceServiceClient
	mu      sync.Mutex
	secrets map[string]*corev1.Secret
	calls   int
	failAt  int
}

func (c *tstCACoreC) GetSecret(ctx context.Context, req *rmetav1.GetOptions, opts ...grpc.CallOption) (*corev1.Secret, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.calls++
	if c.failAt > 0 && c.calls >= c.failAt {
		return nil, errors.Errorf("secret unavailable")
	}

	ret, ok := c.secrets[req.Name]
	if !ok {
		return nil, errors.Errorf("Secret %s not found", req.Name)
	}

	return ret, nil
}

type tstCAOcteliumC struct {
	octeliumc.ClientInterface
	c *tstCACoreC
}

func (c *tstCAOcteliumC) CoreC() rcorev1.ResourceServiceClient {
	return c.c
}

func newTstCAOcteliumC(t *testing.T) (*tstCAOcteliumC, ssh.PublicKey) {
	t.Helper()

	key, err := utils_cert.GenerateECDSA()
	require.Nil(t, err)
	keyPEM, err := utils_cert.GetPrivateKeyPEM(key.PrivateKey)
	require.Nil(t, err)

	ret := &tstCAOcteliumC{c: &tstCACoreC{secrets: map[string]*corev1.Secret{
		"sys:ssh-ca": {Data: &corev1.Secret_Data{
			Type: &corev1.Secret_Data_ValueBytes{ValueBytes: keyPEM},
		}},
		"sys:ssh-svc-seed": {Data: &corev1.Secret_Data{
			Type: &corev1.Secret_Data_ValueBytes{ValueBytes: []byte(vutils.UUIDv4())},
		}},
	}}}

	ca, err := sshutils.GetCAPublicKey(t.Context(), ret)
	require.Nil(t, err)

	return ret, ca
}

func newTstSSHService() *corev1.Service {
	return &corev1.Service{
		Metadata: &metav1.Metadata{Name: "ssh1.default", Uid: vutils.UUIDv4()},
		Spec:     &corev1.Service_Spec{Mode: corev1.Service_Spec_SSH},
	}
}

func getSignerCert(t *testing.T, signer ssh.Signer) *ssh.Certificate {
	t.Helper()

	cert, ok := signer.PublicKey().(*ssh.Certificate)
	require.True(t, ok)
	return cert
}

func observeLogs(t *testing.T) *observer.ObservedLogs {
	t.Helper()

	core, logs := observer.New(zap.DebugLevel)
	originalLogger := zap.L()
	zap.ReplaceGlobals(zap.New(core))
	t.Cleanup(func() { zap.ReplaceGlobals(originalLogger) })

	return logs
}

func TestIsValidUpstreamUserPrincipal(t *testing.T) {
	for _, user := range []string{
		"root",
		"ubuntu",
		"user.name",
		"user-name_1",
		"user@example.com",
		"DOMAIN\\user",
		"John Smith",
		"ü",
		strings.Repeat("u", maxUpstreamUserPrincipalLen),
	} {
		assert.True(t, isValidUpstreamUserPrincipal(user), "%q", user)
	}

	for _, user := range []string{
		"",
		strings.Repeat("u", maxUpstreamUserPrincipalLen+1),
		"root,ubuntu",
		",",
		"*",
		"ro?t",
		"user\n",
		"user\r",
		"\tuser",
		"user\x00",
		"user\x7f",
		"user\u0085",
		string([]byte{0xff, 0xfe}),
	} {
		assert.False(t, isValidUpstreamUserPrincipal(user), "%q", user)
	}
}

func TestNewUpstreamSigner(t *testing.T) {
	ctx := t.Context()
	octeliumC, ca := newTstCAOcteliumC(t)
	svc := newTstSSHService()

	signer, err := newUpstreamSigner(ctx, octeliumC, svc)
	require.Nil(t, err)

	key, err := sshutils.GenerateServiceEd25519UserSigner(ctx, octeliumC, svc)
	require.Nil(t, err)
	assert.Equal(t, key.PublicKey().Marshal(), signer.key.PublicKey().Marshal())

	cert := getSignerCert(t, signer.cert)
	assert.EqualValues(t, ssh.UserCert, cert.CertType)
	assert.Empty(t, cert.ValidPrincipals)
	assert.Equal(t, key.PublicKey().Marshal(), cert.Key.Marshal())
	assert.Equal(t, ca.Marshal(), cert.SignatureKey.Marshal())

	again, err := newUpstreamSigner(ctx, octeliumC, svc)
	require.Nil(t, err)
	assert.Equal(t, signer.key.PublicKey().Marshal(), again.key.PublicKey().Marshal())

	other, err := newUpstreamSigner(ctx, octeliumC, newTstSSHService())
	require.Nil(t, err)
	assert.NotEqual(t, signer.key.PublicKey().Marshal(), other.key.PublicKey().Marshal())

	delete(octeliumC.c.secrets, "sys:ssh-svc-seed")
	random, err := newUpstreamSigner(ctx, octeliumC, svc)
	require.Nil(t, err)
	assert.NotEqual(t, signer.key.PublicKey().Marshal(), random.key.PublicKey().Marshal())
	assert.Equal(t, random.key.PublicKey().Marshal(), getSignerCert(t, random.cert).Key.Marshal())

	delete(octeliumC.c.secrets, "sys:ssh-ca")
	_, err = newUpstreamSigner(ctx, octeliumC, svc)
	assert.NotNil(t, err)
}

func TestUpstreamSignerGetSigners(t *testing.T) {
	ctx := t.Context()
	octeliumC, ca := newTstCAOcteliumC(t)

	signer, err := newUpstreamSigner(ctx, octeliumC, newTstSSHService())
	require.Nil(t, err)

	legacy := getSignerCert(t, signer.cert)
	data := []byte("upstream-signer")

	var keyIDs []string
	for _, user := range []string{"ubuntu", "root", "John Smith", "ubuntu"} {
		signers := signer.getSigners(ctx, octeliumC, "id", user)
		require.Equal(t, 2, len(signers))

		cert := getSignerCert(t, signers[0])
		assert.EqualValues(t, ssh.UserCert, cert.CertType)
		assert.Equal(t, []string{user}, cert.ValidPrincipals)
		assert.Equal(t, legacy.Key.Marshal(), cert.Key.Marshal())
		assert.Equal(t, ca.Marshal(), cert.SignatureKey.Marshal())
		assert.Equal(t, legacy.Permissions.Extensions, cert.Permissions.Extensions)
		assert.Empty(t, cert.CriticalOptions)
		assert.NotEqual(t, legacy.KeyId, cert.KeyId)
		keyIDs = append(keyIDs, cert.KeyId)

		now := uint64(time.Now().Unix())
		assert.True(t, cert.ValidAfter < now)
		assert.True(t, cert.ValidBefore > now)

		checker := &ssh.CertChecker{}
		assert.Nil(t, checker.CheckCert(user, cert))
		assert.NotNil(t, checker.CheckCert(user+"x", cert))
		assert.NotNil(t, checker.CheckCert("", cert))

		sig, err := signers[0].Sign(rand.Reader, data)
		require.Nil(t, err)
		assert.Nil(t, cert.Key.Verify(data, sig))

		_, ok := signers[1].(*fallbackCertSigner)
		assert.True(t, ok)
		assert.Equal(t, signer.cert.PublicKey().Marshal(), signers[1].PublicKey().Marshal())
	}

	slices.Sort(keyIDs)
	assert.Equal(t, len(keyIDs), len(slices.Compact(keyIDs)), "every connection must get its own certificate")

	for _, user := range []string{"", "root,ubuntu", "*", "user\n", strings.Repeat("u", maxUpstreamUserPrincipalLen+1)} {
		calls := octeliumC.c.calls
		assert.Equal(t, []ssh.Signer{signer.cert}, signer.getSigners(ctx, octeliumC, "id", user), "%q", user)
		assert.Equal(t, calls, octeliumC.c.calls, "no certificate must be issued for %q", user)
	}

	logs := observeLogs(t)
	octeliumC.c.failAt = octeliumC.c.calls + 1
	assert.Equal(t, []ssh.Signer{signer.cert}, signer.getSigners(ctx, octeliumC, "id", "ubuntu"))
	assert.Equal(t, 1, logs.FilterMessage("Could not generate the upstream user certificate").Len())
}

type tstPlainSigner struct {
	signer ssh.Signer
}

func (s *tstPlainSigner) PublicKey() ssh.PublicKey {
	return s.signer.PublicKey()
}

func (s *tstPlainSigner) Sign(rand io.Reader, data []byte) (*ssh.Signature, error) {
	return s.signer.Sign(rand, data)
}

func TestFallbackCertSigner(t *testing.T) {
	ctx := t.Context()
	octeliumC, _ := newTstCAOcteliumC(t)

	signer, err := newUpstreamSigner(ctx, octeliumC, newTstSSHService())
	require.Nil(t, err)

	n := 0
	fallback := newFallbackCertSigner(signer.cert, func() { n++ })
	wrapped, ok := fallback.(*fallbackCertSigner)
	require.True(t, ok)
	assert.Equal(t, signer.cert.PublicKey().Marshal(), fallback.PublicKey().Marshal())
	assert.Equal(t, signer.cert.(ssh.MultiAlgorithmSigner).Algorithms(), wrapped.Algorithms())

	data := []byte("fallback")
	sig, err := fallback.Sign(rand.Reader, data)
	require.Nil(t, err)
	assert.Nil(t, fallback.PublicKey().Verify(data, sig))
	assert.Equal(t, 1, n)

	sig, err = wrapped.SignWithAlgorithm(rand.Reader, data, ssh.KeyAlgoED25519)
	require.Nil(t, err)
	assert.Nil(t, fallback.PublicKey().Verify(data, sig))
	assert.Equal(t, 2, n)

	plain := &tstPlainSigner{signer: signer.cert}
	assert.Same(t, plain, newFallbackCertSigner(plain, func() { n++ }))
}

type tstCertUpstream struct {
	addr string

	mu      sync.Mutex
	offered [][]string
	users   []string
}

func (u *tstCertUpstream) getOffered() ([][]string, []string) {
	u.mu.Lock()
	defer u.mu.Unlock()
	return slices.Clone(u.offered), slices.Clone(u.users)
}

func newTstCertUpstream(t *testing.T, octeliumC octeliumc.ClientInterface, ca ssh.PublicKey,
	hostSigner ssh.Signer, accept func(user string, cert *ssh.Certificate) bool) *tstCertUpstream {
	t.Helper()

	ret := &tstCertUpstream{}

	if hostSigner == nil {
		key, err := sshutils.GenerateSigner()
		require.Nil(t, err)
		hostSigner, err = sshutils.GenerateHostSigner(t.Context(), octeliumC, key)
		require.Nil(t, err)
	}

	config := &ssh.ServerConfig{
		PublicKeyCallback: func(conn ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			cert, ok := key.(*ssh.Certificate)
			if !ok {
				return nil, errors.Errorf("not a certificate")
			}

			ret.mu.Lock()
			ret.offered = append(ret.offered, slices.Clone(cert.ValidPrincipals))
			ret.users = append(ret.users, conn.User())
			ret.mu.Unlock()

			if cert.CertType != ssh.UserCert ||
				!bytes.Equal(cert.SignatureKey.Marshal(), ca.Marshal()) ||
				!accept(conn.User(), cert) {
				return nil, errors.Errorf("certificate rejected")
			}

			return &ssh.Permissions{}, nil
		},
	}
	config.AddHostKey(hostSigner)

	lis, err := net.Listen("tcp", "127.0.0.1:0")
	require.Nil(t, err)
	ret.addr = lis.Addr().String()

	var wg sync.WaitGroup
	wg.Go(func() {
		for {
			conn, err := lis.Accept()
			if err != nil {
				return
			}
			wg.Go(func() {
				defer conn.Close()
				sshConn, chans, reqs, err := ssh.NewServerConn(conn, config)
				if err != nil {
					return
				}
				defer sshConn.Close()
				go ssh.DiscardRequests(reqs)
				for nch := range chans {
					nch.Reject(ssh.Prohibited, "")
				}
			})
		}
	})

	t.Cleanup(func() {
		lis.Close()
		wg.Wait()
	})

	return ret
}

func closeTstUpstream(c *dctx) {
	if c.remoteConn.sshClient != nil {
		c.remoteConn.sshClient.Close()
	}
	if c.remoteConn.netConn != nil {
		c.remoteConn.netConn.Close()
	}
}

func newTstUpstreamDctx(upstream *loadbalancer.Upstream, downstreamUser string, cfg *corev1.Service_Spec_Config) *dctx {
	return &dctx{
		id: vutils.GenerateLogID(),
		opts: &modes.Opts{
			GetUpstream: func(ctx context.Context, opts *modes.Opts, reqCtx *corev1.RequestContext) (*loadbalancer.Upstream, error) {
				return upstream, nil
			},
		},
		sshConn:   &ssh.ServerConn{Conn: &tstSSHConn{user: downstreamUser}},
		svcConfig: cfg,
	}
}

func getTstSSHConfig(user string) *corev1.Service_Spec_Config {
	return &corev1.Service_Spec_Config{
		Type: &corev1.Service_Spec_Config_Ssh{Ssh: &corev1.Service_Spec_Config_SSH{User: user}},
	}
}

func TestConnectUpstreamUserCertificate(t *testing.T) {
	octeliumC, ca := newTstCAOcteliumC(t)
	svc := newTstSSHService()
	signer, err := newUpstreamSigner(t.Context(), octeliumC, svc)
	require.Nil(t, err)

	requirePrincipal := func(user string, cert *ssh.Certificate) bool {
		return slices.Contains(cert.ValidPrincipals, user)
	}
	allowEmpty := func(user string, cert *ssh.Certificate) bool {
		return len(cert.ValidPrincipals) == 0 || slices.Contains(cert.ValidPrincipals, user)
	}
	emptyOnly := func(user string, cert *ssh.Certificate) bool {
		return len(cert.ValidPrincipals) == 0
	}
	rejectAll := func(user string, cert *ssh.Certificate) bool {
		return false
	}

	for _, tc := range []struct {
		name           string
		accept         func(user string, cert *ssh.Certificate) bool
		downstreamUser string
		cfg            *corev1.Service_Spec_Config
		failAt         int
		wantUser       string
		wantOffered    [][]string
		wantErr        bool
		wantFallback   bool
	}{
		{
			name:           "principal required",
			accept:         requirePrincipal,
			downstreamUser: "alice",
			cfg:            getTstSSHConfig("ubuntu"),
			wantUser:       "ubuntu",
			wantOffered:    [][]string{{"ubuntu"}},
		},
		{
			name:           "principal required with the downstream user",
			accept:         requirePrincipal,
			downstreamUser: "alice",
			wantUser:       "alice",
			wantOffered:    [][]string{{"alice"}},
		},
		{
			name:           "principal required with an empty ssh config user",
			accept:         requirePrincipal,
			downstreamUser: "alice",
			cfg:            getTstSSHConfig(""),
			wantUser:       "alice",
			wantOffered:    [][]string{{"alice"}},
		},
		{
			name:           "empty principals allowed",
			accept:         allowEmpty,
			downstreamUser: "alice",
			cfg:            getTstSSHConfig("ubuntu"),
			wantUser:       "ubuntu",
			wantOffered:    [][]string{{"ubuntu"}},
		},
		{
			name:           "only empty principals allowed",
			accept:         emptyOnly,
			downstreamUser: "alice",
			cfg:            getTstSSHConfig("ubuntu"),
			wantUser:       "ubuntu",
			wantOffered:    [][]string{{"ubuntu"}, {}},
			wantFallback:   true,
		},
		{
			name:           "rejected",
			accept:         rejectAll,
			downstreamUser: "alice",
			cfg:            getTstSSHConfig("ubuntu"),
			wantUser:       "ubuntu",
			wantOffered:    [][]string{{"ubuntu"}, {}},
			wantErr:        true,
		},
		{
			name:           "invalid principal",
			accept:         allowEmpty,
			downstreamUser: "alice",
			cfg:            getTstSSHConfig("root,ubuntu"),
			wantUser:       "root,ubuntu",
			wantOffered:    [][]string{{}},
		},
		{
			name:           "invalid downstream principal",
			accept:         allowEmpty,
			downstreamUser: "*",
			wantUser:       "*",
			wantOffered:    [][]string{{}},
		},
		{
			name:           "certificate generation failure",
			accept:         allowEmpty,
			downstreamUser: "alice",
			cfg:            getTstSSHConfig("ubuntu"),
			failAt:         2,
			wantUser:       "ubuntu",
			wantOffered:    [][]string{{}},
		},
		{
			name:           "certificate generation failure with principal required",
			accept:         requirePrincipal,
			downstreamUser: "alice",
			cfg:            getTstSSHConfig("ubuntu"),
			failAt:         2,
			wantUser:       "ubuntu",
			wantOffered:    [][]string{{}},
			wantErr:        true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			logs := observeLogs(t)
			upstream := newTstCertUpstream(t, octeliumC, ca, nil, tc.accept)

			octeliumC.c.calls = 0
			octeliumC.c.failAt = tc.failAt
			t.Cleanup(func() { octeliumC.c.failAt = 0 })

			c := newTstUpstreamDctx(&loadbalancer.Upstream{HostPort: upstream.addr}, tc.downstreamUser, tc.cfg)
			err := c.connect(t.Context(), octeliumC, svc, nil, signer, nil)
			defer closeTstUpstream(c)

			if tc.wantErr {
				assert.NotNil(t, err)
			} else {
				require.Nil(t, err, "%+v", err)
				ok, _, err := c.remoteConn.sshClient.SendRequest("keepalive@openssh.com", true, nil)
				assert.Nil(t, err)
				assert.False(t, ok)
			}

			offered, users := upstream.getOffered()
			for i := range offered {
				if offered[i] == nil {
					offered[i] = []string{}
				}
			}
			assert.Equal(t, tc.wantOffered, offered)
			for _, user := range users {
				assert.Equal(t, tc.wantUser, user)
			}

			fallbackLogs := logs.FilterMessage("The upstream SSH server only accepted the user certificate without principals")
			if tc.wantFallback {
				require.Equal(t, 1, fallbackLogs.Len())
				assert.Equal(t, tc.wantUser, fallbackLogs.All()[0].ContextMap()["user"])
			} else {
				assert.Equal(t, 0, fallbackLogs.Len())
			}
		})
	}
}

func TestConnectUpstreamESSHUserCertificate(t *testing.T) {
	octeliumC, ca := newTstCAOcteliumC(t)
	svc := newTstSSHService()
	signer, err := newUpstreamSigner(t.Context(), octeliumC, svc)
	require.Nil(t, err)

	_, hostPriv, err := ed25519.GenerateKey(rand.Reader)
	require.Nil(t, err)
	hostSigner, err := ssh.NewSignerFromKey(hostPriv)
	require.Nil(t, err)

	allowEmpty := func(user string, cert *ssh.Certificate) bool {
		return len(cert.ValidPrincipals) == 0
	}

	for _, tc := range []struct {
		name     string
		host     ssh.Signer
		upstream func(addr string) *loadbalancer.Upstream
	}{
		{
			name: "embedded host key",
			host: hostSigner,
			upstream: func(addr string) *loadbalancer.Upstream {
				return &loadbalancer.Upstream{
					HostPort:         addr,
					IsESSH:           true,
					IsUser:           true,
					Ed25519PublicKey: hostPriv.Public().(ed25519.PublicKey),
				}
			},
		},
		{
			name: "no embedded host key",
			upstream: func(addr string) *loadbalancer.Upstream {
				return &loadbalancer.Upstream{
					HostPort: addr,
					IsESSH:   true,
					IsUser:   true,
				}
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			upstream := newTstCertUpstream(t, octeliumC, ca, tc.host, allowEmpty)

			c := newTstUpstreamDctx(tc.upstream(upstream.addr), "usr1-abcdef", nil)
			require.Nil(t, c.connect(t.Context(), octeliumC, svc, nil, signer, nil))
			defer closeTstUpstream(c)

			offered, users := upstream.getOffered()
			require.Equal(t, 1, len(offered))
			assert.Empty(t, offered[0])
			assert.Equal(t, []string{"usr1-abcdef"}, users)
		})
	}
}

type tstSyncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *tstSyncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *tstSyncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

type tstOpenSSHServer struct {
	addr string
	dir  string
	logs *tstSyncBuffer
}

func getTstSSHDPath(t *testing.T) string {
	t.Helper()

	if ret, err := exec.LookPath("sshd"); err == nil {
		return ret
	}
	if _, err := os.Stat("/usr/sbin/sshd"); err == nil {
		return "/usr/sbin/sshd"
	}

	t.Skip("sshd is not available")
	return ""
}

func startTstOpenSSHServer(t *testing.T, octeliumC octeliumc.ClientInterface,
	config func(t *testing.T, dir string) string) *tstOpenSSHServer {
	t.Helper()

	return startTstOpenSSHServerWithConfig(t, func(t *testing.T, dir string) string {
		_, hostPriv, err := ed25519.GenerateKey(rand.Reader)
		require.Nil(t, err)
		hostKey, err := ssh.MarshalPrivateKey(hostPriv, "")
		require.Nil(t, err)
		require.Nil(t, os.WriteFile(filepath.Join(dir, "host_key"), pem.EncodeToMemory(hostKey), 0o600))

		hostSigner, err := ssh.NewSignerFromKey(hostPriv)
		require.Nil(t, err)
		hostCert, err := sshutils.GenerateHostSigner(t.Context(), octeliumC, hostSigner)
		require.Nil(t, err)
		require.Nil(t, os.WriteFile(filepath.Join(dir, "host_key-cert.pub"),
			ssh.MarshalAuthorizedKey(hostCert.PublicKey()), 0o644))

		return fmt.Sprintf("HostKey %s\nHostCertificate %s\nLogLevel INFO\n%s",
			filepath.Join(dir, "host_key"), filepath.Join(dir, "host_key-cert.pub"), config(t, dir))
	})
}

func startTstOpenSSHServerWithConfig(t *testing.T, config func(t *testing.T, dir string) string) *tstOpenSSHServer {
	t.Helper()

	sshdPath := getTstSSHDPath(t)
	dir := t.TempDir()
	require.Nil(t, os.Chmod(dir, 0o755))

	lis, err := net.Listen("tcp", "127.0.0.1:0")
	require.Nil(t, err)
	addr := lis.Addr().String()
	_, port, err := net.SplitHostPort(addr)
	require.Nil(t, err)
	require.Nil(t, lis.Close())

	configPath := filepath.Join(dir, "sshd_config")
	require.Nil(t, os.WriteFile(configPath, []byte(fmt.Sprintf(`Port %s
ListenAddress 127.0.0.1
PidFile none
UsePAM no
StrictModes no
PasswordAuthentication no
KbdInteractiveAuthentication no
PubkeyAuthentication yes
%s
`, port, config(t, dir))), 0o644))

	ret := &tstOpenSSHServer{
		addr: addr,
		dir:  dir,
		logs: &tstSyncBuffer{},
	}

	cmd := exec.Command(sshdPath, "-D", "-e", "-f", configPath)
	cmd.Stdout = ret.logs
	cmd.Stderr = ret.logs
	require.Nil(t, cmd.Start())

	exitCh := make(chan struct{})
	go func() {
		cmd.Wait()
		close(exitCh)
	}()

	t.Cleanup(func() {
		cmd.Process.Kill()
		<-exitCh
	})

	deadline := time.Now().Add(10 * time.Second)
	for {
		select {
		case <-exitCh:
			t.Skipf("sshd could not be started: %s", ret.logs.String())
		default:
		}

		conn, err := net.DialTimeout("tcp", addr, time.Second)
		if err == nil {
			conn.Close()
			return ret
		}

		if time.Now().After(deadline) {
			t.Fatalf("sshd is not listening: %s", ret.logs.String())
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func getTstCAAuthorizedKeyLine(ca ssh.PublicKey) string {
	return fmt.Sprintf("cert-authority %s %s", ca.Type(), base64.StdEncoding.EncodeToString(ca.Marshal()))
}

func TestConnectUpstreamOpenSSH(t *testing.T) {
	octeliumC, ca := newTstCAOcteliumC(t)
	svc := newTstSSHService()
	signer, err := newUpstreamSigner(t.Context(), octeliumC, svc)
	require.Nil(t, err)

	usr, err := user.Current()
	require.Nil(t, err)
	legacyKeyID := getSignerCert(t, signer.cert).KeyId

	writeFile := func(t *testing.T, dir, name, content string) string {
		ret := filepath.Join(dir, name)
		require.Nil(t, os.WriteFile(ret, []byte(content+"\n"), 0o644))
		return ret
	}

	authorizedKeys := func(t *testing.T, dir string) string {
		return fmt.Sprintf("AuthorizedKeysFile %s",
			writeFile(t, dir, "authorized_keys",
				fmt.Sprintf("%s octelium-managed:example.com", getTstCAAuthorizedKeyLine(ca))))
	}
	trustedUserCAKeys := func(t *testing.T, dir string) string {
		return fmt.Sprintf("AuthorizedKeysFile none\nTrustedUserCAKeys %s",
			writeFile(t, dir, "user_ca.pub", strings.TrimSpace(string(ssh.MarshalAuthorizedKey(ca)))))
	}

	for _, tc := range []struct {
		name           string
		config         func(t *testing.T, dir string) string
		downstreamUser string
		cfg            *corev1.Service_Spec_Config
		wantErr        bool
	}{
		{
			name:           "authorized_keys",
			config:         authorizedKeys,
			downstreamUser: "other",
			cfg:            getTstSSHConfig(usr.Username),
		},
		{
			name:           "authorized_keys with the downstream user",
			config:         authorizedKeys,
			downstreamUser: usr.Username,
		},
		{
			name:           "TrustedUserCAKeys",
			config:         trustedUserCAKeys,
			downstreamUser: "other",
			cfg:            getTstSSHConfig(usr.Username),
		},
		{
			name:           "TrustedUserCAKeys with the downstream user",
			config:         trustedUserCAKeys,
			downstreamUser: usr.Username,
		},
		{
			name: "TrustedUserCAKeys with other authorized principals",
			config: func(t *testing.T, dir string) string {
				return fmt.Sprintf("%s\nAuthorizedPrincipalsFile %s", trustedUserCAKeys(t, dir),
					writeFile(t, dir, "principals", "someone-else"))
			},
			downstreamUser: usr.Username,
			wantErr:        true,
		},
		{
			name: "untrusted CA",
			config: func(t *testing.T, dir string) string {
				other, err := sshutils.GenerateSigner()
				require.Nil(t, err)
				return fmt.Sprintf("AuthorizedKeysFile none\nTrustedUserCAKeys %s",
					writeFile(t, dir, "user_ca.pub", strings.TrimSpace(string(ssh.MarshalAuthorizedKey(other.PublicKey())))))
			},
			downstreamUser: usr.Username,
			wantErr:        true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv := startTstOpenSSHServer(t, octeliumC, tc.config)

			c := newTstUpstreamDctx(&loadbalancer.Upstream{HostPort: srv.addr}, tc.downstreamUser, tc.cfg)
			err := c.connect(t.Context(), octeliumC, svc, nil, signer, nil)
			defer closeTstUpstream(c)

			if tc.wantErr {
				assert.NotNil(t, err)
				return
			}
			require.Nil(t, err, "%+v\n%s", err, srv.logs.String())

			session, err := c.remoteConn.sshClient.NewSession()
			require.Nil(t, err)
			out, err := session.Output("echo upstream-ok")
			session.Close()
			require.Nil(t, err, "%s", srv.logs.String())
			assert.Equal(t, "upstream-ok\n", string(out))

			closeTstUpstream(c)

			var logs string
			accepted := regexp.MustCompile(fmt.Sprintf(`Accepted publickey for %s .* ID (\S+) `, regexp.QuoteMeta(usr.Username)))
			require.Eventually(t, func() bool {
				logs = srv.logs.String()
				return accepted.MatchString(logs)
			}, 5*time.Second, 50*time.Millisecond)

			keyID := accepted.FindStringSubmatch(logs)[1]
			assert.NotEqual(t, legacyKeyID, keyID, "the certificate without principals was used:\n%s", logs)
			assert.NotContains(t, logs, "Refusing certificate", "the first certificate must be accepted:\n%s", logs)
		})
	}
}
