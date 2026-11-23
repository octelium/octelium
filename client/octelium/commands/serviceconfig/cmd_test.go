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

package serviceconfig

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/fatih/color"
	"github.com/octelium/octelium/apis/main/metav1"
	"github.com/octelium/octelium/apis/main/userv1"
	"github.com/octelium/octelium/client/octelium/internal/userexec"
	"github.com/octelium/octelium/pkg/common/pbutils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
)

func TestMain(m *testing.M) {
	userexec.Init()
	os.Exit(m.Run())
}

const tstDomain = "example.com"

const tstMarker = "octelium-managed:example.com"

func newTstCA(t *testing.T) ssh.Signer {
	t.Helper()

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	ret, err := ssh.NewSignerFromKey(priv)
	require.NoError(t, err)

	return ret
}

func getTstKnownHostsLine(ca ssh.PublicKey) string {
	return fmt.Sprintf("@cert-authority %s", knownhosts.Line([]string{"*"}, ca))
}

func getTstAuthorizedKeysLine(ca ssh.PublicKey) string {
	return fmt.Sprintf("cert-authority %s %s", ca.Type(), base64.StdEncoding.EncodeToString(ca.Marshal()))
}

func getTstPublicKeyLine(ca ssh.PublicKey) string {
	return fmt.Sprintf("%s %s", ca.Type(), base64.StdEncoding.EncodeToString(ca.Marshal()))
}

func newTstSSHConfig(ca ssh.PublicKey) *userv1.SetServiceConfigsResponse_Config {
	return &userv1.SetServiceConfigsResponse_Config{
		Type: &userv1.SetServiceConfigsResponse_Config_Ssh{
			Ssh: &userv1.SetServiceConfigsResponse_Config_SSH{
				KnownHosts:     []string{getTstKnownHostsLine(ca)},
				AuthorizedKeys: []string{getTstAuthorizedKeysLine(ca)},
			},
		},
	}
}

func newTstKubeconfig(content string) *userv1.SetServiceConfigsResponse_Config {
	return &userv1.SetServiceConfigsResponse_Config{
		Type: &userv1.SetServiceConfigsResponse_Config_Kubeconfig_{
			Kubeconfig: &userv1.SetServiceConfigsResponse_Config_Kubeconfig{
				Content: []byte(content),
			},
		},
	}
}

func newTstResponse(cfgs ...*userv1.SetServiceConfigsResponse_Config) *userv1.SetServiceConfigsResponse {
	return &userv1.SetServiceConfigsResponse{
		Configs: cfgs,
		Host:    "svc1.default.local.example.com",
		Port:    22,
		L3Mode:  userv1.SetServiceConfigsResponse_V4,
	}
}

type tstConfigAPI struct {
	userv1.UnimplementedMainServiceServer
	resp    *userv1.SetServiceConfigsResponse
	err     error
	getReqs []*metav1.GetOptions
	setReqs []*userv1.SetServiceConfigsRequest
}

func (s *tstConfigAPI) GetService(ctx context.Context, req *metav1.GetOptions) (*userv1.Service, error) {
	s.getReqs = append(s.getReqs, req)
	return &userv1.Service{
		Metadata: &metav1.Metadata{
			Name: "svc1.default",
		},
		Status: &userv1.Service_Status{
			PrimaryHostname: "svc1",
		},
	}, nil
}

func (s *tstConfigAPI) SetServiceConfigs(ctx context.Context, req *userv1.SetServiceConfigsRequest) (*userv1.SetServiceConfigsResponse, error) {
	s.setReqs = append(s.setReqs, req)
	if s.err != nil {
		return nil, s.err
	}
	return s.resp, nil
}

func startTstConfigAPI(t *testing.T, srv *tstConfigAPI) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("the authentication proxy transport uses Unix domain sockets")
	}

	dir, err := os.MkdirTemp("", "oct-cli-")
	require.NoError(t, err)
	t.Cleanup(func() { assert.NoError(t, os.RemoveAll(dir)) })
	socket := filepath.Join(dir, "api.sock")
	lis, err := net.Listen("unix", socket)
	require.NoError(t, err)
	grpcSrv := grpc.NewServer()
	userv1.RegisterMainServiceServer(grpcSrv, srv)
	go grpcSrv.Serve(lis)
	t.Cleanup(grpcSrv.Stop)
	t.Setenv("OCTELIUM_AUTH_PROXY_SOCKET", socket)
	t.Setenv("OCTELIUM_DOMAIN", tstDomain)
}

func newTstUserHome(t *testing.T, hasSSHDir bool) string {
	t.Helper()

	ret := t.TempDir()
	t.Setenv("OCTELIUM_USER_HOME", ret)
	t.Setenv("HOME", ret)
	if hasSSHDir {
		require.NoError(t, os.Mkdir(filepath.Join(ret, ".ssh"), 0700))
	}

	return ret
}

func captureTstStdout(t *testing.T, fn func() error) (string, error) {
	t.Helper()

	r, w, err := os.Pipe()
	require.NoError(t, err)

	stdout, colorOutput := os.Stdout, color.Output
	os.Stdout, color.Output = w, w
	restore := func() {
		os.Stdout, color.Output = stdout, colorOutput
	}
	defer restore()

	outC := make(chan string)
	go func() {
		b, _ := io.ReadAll(r)
		outC <- string(b)
	}()

	err = fn()
	restore()
	require.NoError(t, w.Close())

	return <-outC, err
}

func executeTstCmd(t *testing.T, cmdLineArgs ...string) (string, error) {
	t.Helper()

	cmdArgs = args{}
	Cmd.SilenceUsage, Cmd.SilenceErrors = true, true
	t.Cleanup(func() {
		cmdArgs = args{}
		Cmd.SilenceUsage, Cmd.SilenceErrors = false, false
	})

	Cmd.SetArgs(append([]string{}, cmdLineArgs...))
	return captureTstStdout(t, func() error {
		return Cmd.ExecuteContext(t.Context())
	})
}

func readTstLines(t *testing.T, filePath string) []string {
	t.Helper()

	b, err := os.ReadFile(filePath)
	require.NoError(t, err)

	var ret []string
	for line := range strings.Lines(string(b)) {
		if line = strings.TrimSpace(line); line != "" {
			ret = append(ret, line)
		}
	}

	return ret
}

func TestValidateArgs(t *testing.T) {
	t.Cleanup(func() { cmdArgs = args{} })

	for _, tc := range []struct {
		out       string
		sshFormat string
		err       string
	}{
		{},
		{out: "json"},
		{out: "yaml"},
		{out: "yml"},
		{sshFormat: "known-hosts"},
		{sshFormat: "authorized-keys"},
		{sshFormat: "ca-public-key"},
		{out: "xml", err: "Invalid output format: xml"},
		{sshFormat: "known_hosts", err: "Invalid SSH format: known_hosts"},
		{sshFormat: "public-key", err: "Invalid SSH format: public-key"},
		{sshFormat: "KNOWN-HOSTS", err: "Invalid SSH format: KNOWN-HOSTS"},
		{out: "json", sshFormat: "known-hosts", err: "cannot be used together"},
		{out: "yaml", sshFormat: "ca-public-key", err: "cannot be used together"},
	} {
		t.Run(fmt.Sprintf("%s/%s", tc.out, tc.sshFormat), func(t *testing.T) {
			cmdArgs = args{Out: tc.out, SSHFormat: tc.sshFormat}
			err := validateArgs()
			if tc.err == "" {
				assert.NoError(t, err)
				return
			}
			require.Error(t, err)
			assert.Contains(t, err.Error(), tc.err)
		})
	}

	err := validateSSHFormat("invalid")
	require.Error(t, err)
	assert.Equal(t, "Invalid SSH format: invalid. It must be either `known-hosts`, `authorized-keys` or `ca-public-key`", err.Error())
}

func TestGetSSHCAPublicKeys(t *testing.T) {
	ca := newTstCA(t).PublicKey()
	otherCA := newTstCA(t).PublicKey()

	_, edKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	hostKey, err := ssh.NewPublicKey(edKey.Public())
	require.NoError(t, err)

	marshal := func(keys []ssh.PublicKey) []string {
		var ret []string
		for _, key := range keys {
			ret = append(ret, string(key.Marshal()))
		}
		return ret
	}

	for _, tc := range []struct {
		name           string
		knownHosts     []string
		authorizedKeys []string
		want           []ssh.PublicKey
		err            string
	}{
		{
			name: "Empty",
		},
		{
			name:           "Server",
			knownHosts:     []string{getTstKnownHostsLine(ca)},
			authorizedKeys: []string{getTstAuthorizedKeysLine(ca)},
			want:           []ssh.PublicKey{ca},
		},
		{
			name:       "KnownHostsOnly",
			knownHosts: []string{getTstKnownHostsLine(ca)},
			want:       []ssh.PublicKey{ca},
		},
		{
			name:           "AuthorizedKeysOnly",
			authorizedKeys: []string{getTstAuthorizedKeysLine(ca)},
			want:           []ssh.PublicKey{ca},
		},
		{
			name:           "TwoCAs",
			knownHosts:     []string{getTstKnownHostsLine(otherCA), getTstKnownHostsLine(ca)},
			authorizedKeys: []string{getTstAuthorizedKeysLine(ca), getTstAuthorizedKeysLine(otherCA)},
			want:           []ssh.PublicKey{otherCA, ca},
		},
		{
			name:           "OptionCase",
			authorizedKeys: []string{fmt.Sprintf("CERT-AUTHORITY %s", getTstPublicKeyLine(ca))},
			want:           []ssh.PublicKey{ca},
		},
		{
			name:           "OtherOptions",
			authorizedKeys: []string{fmt.Sprintf(`principals="root",cert-authority %s comment`, getTstPublicKeyLine(ca))},
			want:           []ssh.PublicKey{ca},
		},
		{
			name: "PlainKeys",
			knownHosts: []string{
				knownhosts.Line([]string{"host.example.com"}, hostKey),
				fmt.Sprintf("@revoked %s", knownhosts.Line([]string{"*"}, otherCA)),
			},
			authorizedKeys: []string{getTstPublicKeyLine(hostKey), fmt.Sprintf(`no-pty %s`, getTstPublicKeyLine(otherCA))},
		},
		{
			name:       "InvalidKnownHosts",
			knownHosts: []string{"@cert-authority * ecdsa-sha2-nistp256 invalid"},
			err:        "Could not parse the known_hosts entry",
		},
		{
			name:           "InvalidAuthorizedKeys",
			authorizedKeys: []string{"cert-authority ecdsa-sha2-nistp256"},
			err:            "Could not parse the authorized_keys entry",
		},
		{
			name:           "MismatchedKeyType",
			authorizedKeys: []string{fmt.Sprintf("cert-authority ssh-ed25519 %s", base64.StdEncoding.EncodeToString(ca.Marshal()))},
			err:            "Could not parse the authorized_keys entry",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			keys, err := getSSHCAPublicKeys(&userv1.SetServiceConfigsResponse_Config_SSH{
				KnownHosts:     tc.knownHosts,
				AuthorizedKeys: tc.authorizedKeys,
			})
			if tc.err != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tc.err)
				assert.Nil(t, keys)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, marshal(tc.want), marshal(keys))
		})
	}
}

func TestGetSSHConfigLines(t *testing.T) {
	ca := newTstCA(t).PublicKey()
	cfg := newTstSSHConfig(ca).GetSsh()

	lines, err := getSSHConfigLines(cfg, sshFormatKnownHosts)
	require.NoError(t, err)
	assert.Equal(t, []string{getTstKnownHostsLine(ca)}, lines)
	assert.Equal(t, []string{fmt.Sprintf("@cert-authority * %s", getTstPublicKeyLine(ca))}, lines)

	lines, err = getSSHConfigLines(cfg, sshFormatAuthorizedKeys)
	require.NoError(t, err)
	assert.Equal(t, []string{fmt.Sprintf("cert-authority %s", getTstPublicKeyLine(ca))}, lines)

	lines, err = getSSHConfigLines(cfg, sshFormatCAPublicKey)
	require.NoError(t, err)
	assert.Equal(t, []string{getTstPublicKeyLine(ca)}, lines)

	for _, format := range []string{"", "invalid"} {
		_, err = getSSHConfigLines(cfg, format)
		assert.Error(t, err, format)
	}

	_, err = getSSHConfigLines(&userv1.SetServiceConfigsResponse_Config_SSH{
		AuthorizedKeys: []string{"cert-authority invalid"},
	}, sshFormatCAPublicKey)
	assert.Error(t, err)

	lines, err = getSSHConfigLines(&userv1.SetServiceConfigsResponse_Config_SSH{
		AuthorizedKeys: []string{"cert-authority invalid"},
	}, sshFormatAuthorizedKeys)
	require.NoError(t, err)
	assert.Equal(t, []string{"cert-authority invalid"}, lines)
}

func TestPrintConfigs(t *testing.T) {
	ca := newTstCA(t).PublicKey()
	kubeconfig := "apiVersion: v1\nkind: Config\n"

	for _, tc := range []struct {
		name string
		resp *userv1.SetServiceConfigsResponse
		want string
	}{
		{
			name: "SSH",
			resp: newTstResponse(newTstSSHConfig(ca)),
			want: fmt.Sprintf("# known_hosts\n@cert-authority * %s\n# authorized_keys\ncert-authority %s\n",
				getTstPublicKeyLine(ca), getTstPublicKeyLine(ca)),
		},
		{
			name: "SSHKnownHostsOnly",
			resp: newTstResponse(&userv1.SetServiceConfigsResponse_Config{
				Type: &userv1.SetServiceConfigsResponse_Config_Ssh{
					Ssh: &userv1.SetServiceConfigsResponse_Config_SSH{
						KnownHosts: []string{getTstKnownHostsLine(ca)},
					},
				},
			}),
			want: fmt.Sprintf("# known_hosts\n@cert-authority * %s\n", getTstPublicKeyLine(ca)),
		},
		{
			name: "Kubeconfig",
			resp: newTstResponse(newTstKubeconfig(kubeconfig)),
			want: kubeconfig,
		},
		{
			name: "None",
			resp: newTstResponse(),
		},
		{
			name: "Unsupported",
			resp: newTstResponse(&userv1.SetServiceConfigsResponse_Config{}),
		},
		{
			name: "UnsupportedAndSSH",
			resp: newTstResponse(&userv1.SetServiceConfigsResponse_Config{}, newTstSSHConfig(ca)),
			want: fmt.Sprintf("# known_hosts\n@cert-authority * %s\n# authorized_keys\ncert-authority %s\n",
				getTstPublicKeyLine(ca), getTstPublicKeyLine(ca)),
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer
			_, err := captureTstStdout(t, func() error {
				return printConfigs(&buf, tc.resp)
			})
			require.NoError(t, err)
			assert.Equal(t, tc.want, buf.String())
		})
	}
}

func TestPrintSSHConfigs(t *testing.T) {
	ca := newTstCA(t).PublicKey()
	otherCA := newTstCA(t).PublicKey()

	for _, tc := range []struct {
		name   string
		resp   *userv1.SetServiceConfigsResponse
		format string
		want   string
		err    string
	}{
		{
			name:   "KnownHosts",
			resp:   newTstResponse(newTstSSHConfig(ca)),
			format: sshFormatKnownHosts,
			want:   fmt.Sprintf("@cert-authority * %s\n", getTstPublicKeyLine(ca)),
		},
		{
			name:   "AuthorizedKeys",
			resp:   newTstResponse(newTstSSHConfig(ca)),
			format: sshFormatAuthorizedKeys,
			want:   fmt.Sprintf("cert-authority %s\n", getTstPublicKeyLine(ca)),
		},
		{
			name:   "CAPublicKey",
			resp:   newTstResponse(newTstSSHConfig(ca)),
			format: sshFormatCAPublicKey,
			want:   fmt.Sprintf("%s\n", getTstPublicKeyLine(ca)),
		},
		{
			name:   "Duplicates",
			resp:   newTstResponse(newTstSSHConfig(ca), newTstSSHConfig(ca)),
			format: sshFormatAuthorizedKeys,
			want:   fmt.Sprintf("cert-authority %s\n", getTstPublicKeyLine(ca)),
		},
		{
			name:   "TwoCAs",
			resp:   newTstResponse(newTstSSHConfig(ca), newTstSSHConfig(otherCA)),
			format: sshFormatCAPublicKey,
			want:   fmt.Sprintf("%s\n%s\n", getTstPublicKeyLine(ca), getTstPublicKeyLine(otherCA)),
		},
		{
			name:   "IgnoresOtherTypes",
			resp:   newTstResponse(newTstKubeconfig("kind: Config\n"), &userv1.SetServiceConfigsResponse_Config{}, newTstSSHConfig(ca)),
			format: sshFormatCAPublicKey,
			want:   fmt.Sprintf("%s\n", getTstPublicKeyLine(ca)),
		},
		{
			name:   "Kubeconfig",
			resp:   newTstResponse(newTstKubeconfig("kind: Config\n")),
			format: sshFormatKnownHosts,
			err:    "The --ssh-format flag can only be used with SSH Services",
		},
		{
			name:   "None",
			resp:   newTstResponse(),
			format: sshFormatCAPublicKey,
			err:    "The --ssh-format flag can only be used with SSH Services",
		},
		{
			name: "Empty",
			resp: newTstResponse(&userv1.SetServiceConfigsResponse_Config{
				Type: &userv1.SetServiceConfigsResponse_Config_Ssh{
					Ssh: &userv1.SetServiceConfigsResponse_Config_SSH{
						KnownHosts: []string{getTstKnownHostsLine(ca)},
					},
				},
			}),
			format: sshFormatAuthorizedKeys,
			err:    "The SSH configuration of this Service has no entries in the authorized-keys format",
		},
		{
			name: "NoCA",
			resp: newTstResponse(&userv1.SetServiceConfigsResponse_Config{
				Type: &userv1.SetServiceConfigsResponse_Config_Ssh{
					Ssh: &userv1.SetServiceConfigsResponse_Config_SSH{
						AuthorizedKeys: []string{getTstPublicKeyLine(ca)},
					},
				},
			}),
			format: sshFormatCAPublicKey,
			err:    "The SSH configuration of this Service has no entries in the ca-public-key format",
		},
		{
			name: "InvalidCA",
			resp: newTstResponse(&userv1.SetServiceConfigsResponse_Config{
				Type: &userv1.SetServiceConfigsResponse_Config_Ssh{
					Ssh: &userv1.SetServiceConfigsResponse_Config_SSH{
						AuthorizedKeys: []string{"cert-authority invalid"},
					},
				},
			}),
			format: sshFormatCAPublicKey,
			err:    "Could not parse the authorized_keys entry",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer
			err := printSSHConfigs(&buf, tc.resp, tc.format)
			if tc.err != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tc.err)
				assert.Empty(t, buf.String())
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tc.want, buf.String())
		})
	}
}

func TestPrintedSSHConfigsAreUsable(t *testing.T) {
	caSigner := newTstCA(t)
	ca := caSigner.PublicKey()
	resp := newTstResponse(newTstSSHConfig(ca))

	_, edKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	keySigner, err := ssh.NewSignerFromKey(edKey)
	require.NoError(t, err)

	newCert := func(t *testing.T, signer ssh.Signer, certType uint32, principals ...string) *ssh.Certificate {
		t.Helper()
		ret := &ssh.Certificate{
			Key:             keySigner.PublicKey(),
			CertType:        certType,
			ValidPrincipals: principals,
			ValidAfter:      uint64(time.Now().Add(-time.Minute).Unix()),
			ValidBefore:     uint64(time.Now().Add(time.Hour).Unix()),
		}
		require.NoError(t, ret.SignCert(rand.Reader, signer))
		return ret
	}

	printFormat := func(t *testing.T, format string) string {
		t.Helper()
		var buf bytes.Buffer
		require.NoError(t, printSSHConfigs(&buf, resp, format))
		return buf.String()
	}

	t.Run("KnownHosts", func(t *testing.T) {
		filePath := filepath.Join(t.TempDir(), "known_hosts")
		require.NoError(t, os.WriteFile(filePath, []byte(printFormat(t, sshFormatKnownHosts)), 0600))
		callback, err := knownhosts.New(filePath)
		require.NoError(t, err)

		addr := &net.TCPAddr{IP: net.ParseIP("10.0.0.5"), Port: 22}
		assert.NoError(t, callback("svc1:22", addr, newCert(t, caSigner, ssh.HostCert, "svc1")))
		assert.Error(t, callback("svc1:22", addr, newCert(t, newTstCA(t), ssh.HostCert, "svc1")))
		assert.Error(t, callback("svc1:22", addr, keySigner.PublicKey()))
	})

	t.Run("AuthorizedKeys", func(t *testing.T) {
		key, _, options, rest, err := ssh.ParseAuthorizedKey([]byte(printFormat(t, sshFormatAuthorizedKeys)))
		require.NoError(t, err)
		assert.Empty(t, rest)
		assert.Equal(t, []string{"cert-authority"}, options)
		assert.Equal(t, ca.Marshal(), key.Marshal())
	})

	t.Run("CAPublicKey", func(t *testing.T) {
		key, comment, options, rest, err := ssh.ParseAuthorizedKey([]byte(printFormat(t, sshFormatCAPublicKey)))
		require.NoError(t, err)
		assert.Empty(t, rest)
		assert.Empty(t, options)
		assert.Empty(t, comment)

		checker := &ssh.CertChecker{
			IsUserAuthority: func(auth ssh.PublicKey) bool {
				return bytes.Equal(auth.Marshal(), key.Marshal())
			},
		}
		_, err = checker.Authenticate(testConnMetadata("root"), newCert(t, caSigner, ssh.UserCert, "root"))
		assert.NoError(t, err)
		_, err = checker.Authenticate(testConnMetadata("root"), newCert(t, newTstCA(t), ssh.UserCert, "root"))
		assert.Error(t, err)
	})
}

type testConnMetadata string

func (m testConnMetadata) User() string          { return string(m) }
func (m testConnMetadata) SessionID() []byte     { return nil }
func (m testConnMetadata) ClientVersion() []byte { return nil }
func (m testConnMetadata) ServerVersion() []byte { return nil }
func (m testConnMetadata) RemoteAddr() net.Addr  { return &net.TCPAddr{} }
func (m testConnMetadata) LocalAddr() net.Addr   { return &net.TCPAddr{} }

func TestCmdSSH(t *testing.T) {
	ca := newTstCA(t).PublicKey()
	knownHostsLine := fmt.Sprintf("@cert-authority * %s", getTstPublicKeyLine(ca))
	authorizedKeysLine := fmt.Sprintf("cert-authority %s", getTstPublicKeyLine(ca))

	assertNoSSHFiles := func(t *testing.T, homeDir string) {
		t.Helper()
		entries, err := os.ReadDir(homeDir)
		require.NoError(t, err)
		for _, entry := range entries {
			if entry.Name() != ".ssh" {
				t.Errorf("unexpected file in the home directory: %s", entry.Name())
			}
		}
		entries, err = os.ReadDir(filepath.Join(homeDir, ".ssh"))
		if err == nil {
			assert.Empty(t, entries)
		}
	}

	t.Run("Apply", func(t *testing.T) {
		srv := &tstConfigAPI{resp: newTstResponse(newTstSSHConfig(ca))}
		startTstConfigAPI(t, srv)
		homeDir := newTstUserHome(t, true)
		sshDir := filepath.Join(homeDir, ".ssh")
		knownHostsPath := filepath.Join(sshDir, "known_hosts")
		authorizedKeysPath := filepath.Join(sshDir, "authorized_keys")

		userKey := "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIB6mZ0Ck0dPl0hLQ1nLnLnQ0Q1lQ0lQ0lQ0lQ0lQ0lQ0 user@laptop"
		require.NoError(t, os.WriteFile(authorizedKeysPath, []byte(userKey+"\n"), 0600))

		for range 3 {
			out, err := executeTstCmd(t, "svc1")
			require.NoError(t, err)
			assert.Contains(t, out, fmt.Sprintf("Set the SSH configuration of the Service in %s\n", knownHostsPath))
			assert.Contains(t, out, fmt.Sprintf("Set the SSH configuration of the Service in %s\n", authorizedKeysPath))
			assert.Contains(t, out, fmt.Sprintf("The SHA256 fingerprint of the Cluster SSH CA: %s\n", ssh.FingerprintSHA256(ca)))
			assert.Contains(t, out, "These entries are removed once the octelium client disconnects from the Cluster\n")
			assert.Contains(t, out, "Configuration successfully applied for Service: svc1\n")
			assert.NotContains(t, out, "not support")
		}

		assert.Equal(t, []string{fmt.Sprintf("%s %s", knownHostsLine, tstMarker)}, readTstLines(t, knownHostsPath))
		assert.Equal(t, []string{userKey, fmt.Sprintf("%s %s", authorizedKeysLine, tstMarker)}, readTstLines(t, authorizedKeysPath))

		fi, err := os.Stat(knownHostsPath)
		require.NoError(t, err)
		assert.Equal(t, os.FileMode(0600), fi.Mode().Perm())

		require.Len(t, srv.getReqs, 3)
		require.Len(t, srv.setReqs, 3)
		assert.Equal(t, "svc1", srv.getReqs[0].Name)
		assert.Equal(t, "svc1.default", srv.setReqs[0].Name)
	})

	t.Run("ApplyKeepsUnmanagedCA", func(t *testing.T) {
		startTstConfigAPI(t, &tstConfigAPI{resp: newTstResponse(newTstSSHConfig(ca))})
		homeDir := newTstUserHome(t, true)
		authorizedKeysPath := filepath.Join(homeDir, ".ssh", "authorized_keys")
		require.NoError(t, os.WriteFile(authorizedKeysPath, []byte(authorizedKeysLine+"\n"), 0600))

		_, err := executeTstCmd(t, "svc1")
		require.NoError(t, err)
		assert.Equal(t, []string{authorizedKeysLine}, readTstLines(t, authorizedKeysPath))
	})

	t.Run("ApplyWithoutSSHDir", func(t *testing.T) {
		startTstConfigAPI(t, &tstConfigAPI{resp: newTstResponse(newTstSSHConfig(ca))})
		homeDir := newTstUserHome(t, false)

		out, err := executeTstCmd(t, "svc1")
		require.Error(t, err)
		assert.Contains(t, err.Error(), filepath.Join(homeDir, ".ssh"))
		assert.Contains(t, err.Error(), "--print")
		assert.NotContains(t, out, "successfully")

		_, err = os.Stat(filepath.Join(homeDir, ".ssh"))
		assert.True(t, os.IsNotExist(err))
	})

	t.Run("Print", func(t *testing.T) {
		startTstConfigAPI(t, &tstConfigAPI{resp: newTstResponse(newTstSSHConfig(ca))})
		homeDir := newTstUserHome(t, true)

		out, err := executeTstCmd(t, "svc1", "--print")
		require.NoError(t, err)
		assert.Equal(t, fmt.Sprintf("# known_hosts\n%s\n# authorized_keys\n%s\n", knownHostsLine, authorizedKeysLine), out)
		assertNoSSHFiles(t, homeDir)
	})

	for _, tc := range []struct {
		args []string
		want string
	}{
		{args: []string{"--ssh-format", "known-hosts"}, want: knownHostsLine},
		{args: []string{"--ssh-format", "authorized-keys"}, want: authorizedKeysLine},
		{args: []string{"--ssh-format", "ca-public-key"}, want: getTstPublicKeyLine(ca)},
		{args: []string{"--ssh-format=ca-public-key", "--print"}, want: getTstPublicKeyLine(ca)},
	} {
		t.Run(strings.Join(tc.args, " "), func(t *testing.T) {
			startTstConfigAPI(t, &tstConfigAPI{resp: newTstResponse(newTstSSHConfig(ca))})
			homeDir := newTstUserHome(t, true)

			out, err := executeTstCmd(t, append([]string{"svc1"}, tc.args...)...)
			require.NoError(t, err)
			assert.Equal(t, tc.want+"\n", out)
			assertNoSSHFiles(t, homeDir)
		})
	}

	for _, format := range []string{"json", "yaml"} {
		t.Run(format, func(t *testing.T) {
			srv := &tstConfigAPI{resp: newTstResponse(newTstSSHConfig(ca))}
			startTstConfigAPI(t, srv)
			homeDir := newTstUserHome(t, true)

			out, err := executeTstCmd(t, "svc1", "-o", format, "--print")
			require.NoError(t, err)

			resp := &userv1.SetServiceConfigsResponse{}
			if format == "json" {
				require.NoError(t, pbutils.UnmarshalJSON([]byte(out), resp))
			} else {
				require.NoError(t, pbutils.UnmarshalYAML([]byte(out), resp))
			}
			assert.True(t, proto.Equal(srv.resp, resp), "%s", out)
			assert.Contains(t, out, knownHostsLine)
			assert.Contains(t, out, authorizedKeysLine)
			assertNoSSHFiles(t, homeDir)
		})
	}
}

func TestCmdKubeconfig(t *testing.T) {
	kubeconfig := "apiVersion: v1\nkind: Config\n"

	t.Run("Apply", func(t *testing.T) {
		startTstConfigAPI(t, &tstConfigAPI{resp: newTstResponse(newTstKubeconfig(kubeconfig))})
		homeDir := newTstUserHome(t, false)
		kubeConfigPath := filepath.Join(homeDir, ".kube", "svc1.example.com")

		out, err := executeTstCmd(t, "svc1")
		require.NoError(t, err)
		assert.Equal(t, fmt.Sprintf("Set the following environment variable to use kubectl commands for the Service svc1:\nexport KUBECONFIG=%s\nConfiguration successfully applied for Service: svc1\n", kubeConfigPath), out)

		b, err := os.ReadFile(kubeConfigPath)
		require.NoError(t, err)
		assert.Equal(t, kubeconfig, string(b))
		_, err = os.Stat(filepath.Join(homeDir, ".ssh"))
		assert.True(t, os.IsNotExist(err))
	})

	t.Run("Print", func(t *testing.T) {
		startTstConfigAPI(t, &tstConfigAPI{resp: newTstResponse(newTstKubeconfig(kubeconfig))})
		homeDir := newTstUserHome(t, false)

		out, err := executeTstCmd(t, "svc1", "--print")
		require.NoError(t, err)
		assert.Equal(t, kubeconfig, out)
		_, err = os.Stat(filepath.Join(homeDir, ".kube"))
		assert.True(t, os.IsNotExist(err))
	})

	t.Run("SSHFormat", func(t *testing.T) {
		startTstConfigAPI(t, &tstConfigAPI{resp: newTstResponse(newTstKubeconfig(kubeconfig))})
		homeDir := newTstUserHome(t, false)

		out, err := executeTstCmd(t, "svc1", "--ssh-format", "known-hosts")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "The --ssh-format flag can only be used with SSH Services")
		assert.Empty(t, out)
		_, err = os.Stat(filepath.Join(homeDir, ".kube"))
		assert.True(t, os.IsNotExist(err))
	})
}

func TestCmdOther(t *testing.T) {
	t.Run("None", func(t *testing.T) {
		startTstConfigAPI(t, &tstConfigAPI{resp: newTstResponse()})
		newTstUserHome(t, true)

		out, err := executeTstCmd(t, "svc1")
		require.NoError(t, err)
		assert.Equal(t, "This Service does not need a configuration to be set\n", out)

		out, err = executeTstCmd(t, "svc1", "--print")
		require.NoError(t, err)
		assert.Equal(t, "This Service does not need a configuration to be set\n", out)
	})

	t.Run("Unsupported", func(t *testing.T) {
		startTstConfigAPI(t, &tstConfigAPI{resp: newTstResponse(&userv1.SetServiceConfigsResponse_Config{})})
		newTstUserHome(t, true)

		out, err := executeTstCmd(t, "svc1")
		require.NoError(t, err)
		assert.Equal(t, "This Service has 1 configuration(s) that this octelium CLI version does not support. You can use the --out flag to print them\n", out)

		out, err = executeTstCmd(t, "svc1", "--print")
		require.NoError(t, err)
		assert.Empty(t, out)
	})

	t.Run("UnsupportedAndSSH", func(t *testing.T) {
		ca := newTstCA(t).PublicKey()
		startTstConfigAPI(t, &tstConfigAPI{resp: newTstResponse(&userv1.SetServiceConfigsResponse_Config{}, newTstSSHConfig(ca))})
		newTstUserHome(t, true)

		out, err := executeTstCmd(t, "svc1")
		require.NoError(t, err)
		assert.Contains(t, out, "This Service has 1 configuration(s) that this octelium CLI version does not support")
		assert.Contains(t, out, "Configuration successfully applied for Service: svc1\n")
	})

	t.Run("NotConnected", func(t *testing.T) {
		srv := &tstConfigAPI{err: status.Error(codes.InvalidArgument, "You must be connected first to set a Service config")}
		startTstConfigAPI(t, srv)
		homeDir := newTstUserHome(t, true)

		for _, cmdLineArgs := range [][]string{
			{"svc1"},
			{"svc1", "--print"},
			{"svc1", "--ssh-format", "ca-public-key"},
			{"svc1", "-o", "json"},
		} {
			out, err := executeTstCmd(t, cmdLineArgs...)
			require.Error(t, err)
			assert.Contains(t, err.Error(), "You must be connected first")
			assert.Empty(t, out)
		}
		assert.Len(t, srv.setReqs, 4)

		entries, err := os.ReadDir(filepath.Join(homeDir, ".ssh"))
		require.NoError(t, err)
		assert.Empty(t, entries)
	})

	t.Run("InvalidArgs", func(t *testing.T) {
		srv := &tstConfigAPI{resp: newTstResponse()}
		startTstConfigAPI(t, srv)
		newTstUserHome(t, true)

		for _, cmdLineArgs := range [][]string{
			{"svc1", "-o", "xml"},
			{"svc1", "--ssh-format", "invalid"},
			{"svc1", "-o", "json", "--ssh-format", "known-hosts"},
		} {
			_, err := executeTstCmd(t, cmdLineArgs...)
			assert.Error(t, err, "%v", cmdLineArgs)
		}

		_, err := executeTstCmd(t)
		assert.Error(t, err)
		_, err = executeTstCmd(t, "svc1", "svc2")
		assert.Error(t, err)

		assert.Empty(t, srv.getReqs)
		assert.Empty(t, srv.setReqs)
	})
}
