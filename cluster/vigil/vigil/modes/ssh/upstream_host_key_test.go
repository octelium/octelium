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
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/mldsa"
	"crypto/rand"
	"crypto/rsa"
	"encoding/binary"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"os"
	"os/user"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/cluster/common/octeliumc"
	"github.com/octelium/octelium/cluster/common/sshutils"
	"github.com/octelium/octelium/cluster/vigil/vigil/loadbalancer"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
)

type tstHostKey struct {
	priv   crypto.Signer
	signer ssh.Signer
	cert   ssh.Signer
}

func newTstHostKey(t *testing.T, octeliumC octeliumc.ClientInterface, typ string) *tstHostKey {
	t.Helper()

	var priv crypto.Signer
	var err error
	switch typ {
	case ssh.KeyAlgoED25519:
		_, priv, err = ed25519.GenerateKey(rand.Reader)
	case ssh.KeyAlgoECDSA256:
		priv, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	case ssh.KeyAlgoECDSA384:
		priv, err = ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	case ssh.KeyAlgoECDSA521:
		priv, err = ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	case ssh.KeyAlgoRSA:
		priv, err = rsa.GenerateKey(rand.Reader, 2048)
	case ssh.KeyAlgoMLDSA65:
		priv, err = mldsa.GenerateKey(mldsa.MLDSA65())
	default:
		t.Fatalf("Unsupported host key type %s", typ)
	}
	require.Nil(t, err)

	signer, err := ssh.NewSignerFromSigner(priv)
	require.Nil(t, err)
	cert, err := sshutils.GenerateHostSigner(t.Context(), octeliumC, signer)
	require.Nil(t, err)

	return &tstHostKey{
		priv:   priv,
		signer: signer,
		cert:   cert,
	}
}

func getTstAuthorizedKey(key ssh.PublicKey) string {
	return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(key)))
}

func getTstHostKeyConfig(key string) *corev1.Service_Spec_Config {
	return &corev1.Service_Spec_Config{
		Type: &corev1.Service_Spec_Config_Ssh{
			Ssh: &corev1.Service_Spec_Config_SSH{
				UpstreamHostKey: &corev1.Service_Spec_Config_SSH_UpstreamHostKey{
					Type: &corev1.Service_Spec_Config_SSH_UpstreamHostKey_Key{
						Key: key,
					},
				},
			},
		},
	}
}

type tstKexInitMsg struct {
	Cookie                  [16]byte `sshtype:"20"`
	KexAlgos                []string
	ServerHostKeyAlgos      []string
	CiphersClientServer     []string
	CiphersServerClient     []string
	MACsClientServer        []string
	MACsServerClient        []string
	CompressionClientServer []string
	CompressionServerClient []string
	LanguagesClientServer   []string
	LanguagesServerClient   []string
	FirstKexFollows         bool
	Reserved                uint32
}

func getTstOfferedHostKeyAlgorithms(t *testing.T, config *ssh.ClientConfig) []string {
	t.Helper()

	clientConn, serverConn := net.Pipe()
	defer serverConn.Close()
	require.Nil(t, serverConn.SetDeadline(time.Now().Add(10*time.Second)))

	doneCh := make(chan struct{})
	go func() {
		defer close(doneCh)
		defer clientConn.Close()
		ssh.NewClientConn(clientConn, "127.0.0.1:22", config)
	}()

	reader := bufio.NewReader(serverConn)
	_, err := reader.ReadString('\n')
	require.Nil(t, err)
	_, err = serverConn.Write([]byte("SSH-2.0-OpenSSH_10.5\r\n"))
	require.Nil(t, err)

	var length uint32
	require.Nil(t, binary.Read(reader, binary.BigEndian, &length))
	require.Less(t, length, uint32(64*1024))
	packet := make([]byte, length)
	_, err = io.ReadFull(reader, packet)
	require.Nil(t, err)
	require.Greater(t, len(packet), int(packet[0]))

	msg := &tstKexInitMsg{}
	require.Nil(t, ssh.Unmarshal(packet[1:len(packet)-int(packet[0])], msg))

	serverConn.Close()
	<-doneCh

	return msg.ServerHostKeyAlgos
}

func getTstDefaultHostKeyAlgorithms(t *testing.T) []string {
	t.Helper()

	return getTstOfferedHostKeyAlgorithms(t, &ssh.ClientConfig{
		User:            "root",
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	})
}

func TestGetUpstreamHostKeyAlgorithms(t *testing.T) {
	octeliumC, _ := newTstCAOcteliumC(t)
	defaultAlgos := getTstDefaultHostKeyAlgorithms(t)

	require.NotEmpty(t, defaultAlgos)
	assert.True(t, slices.Contains(defaultAlgos, ssh.KeyAlgoRSA), "%v", defaultAlgos)
	assert.Less(t, slices.Index(defaultAlgos, ssh.KeyAlgoECDSA256), slices.Index(defaultAlgos, ssh.KeyAlgoRSASHA256))
	assert.Less(t, slices.Index(defaultAlgos, ssh.KeyAlgoRSASHA256), slices.Index(defaultAlgos, ssh.KeyAlgoED25519))
	assert.Less(t, slices.Index(defaultAlgos, ssh.CertAlgoED25519v01), slices.Index(defaultAlgos, ssh.KeyAlgoECDSA256))

	ed25519Key := newTstHostKey(t, octeliumC, ssh.KeyAlgoED25519)
	ecdsa256Key := newTstHostKey(t, octeliumC, ssh.KeyAlgoECDSA256)
	ecdsa384Key := newTstHostKey(t, octeliumC, ssh.KeyAlgoECDSA384)
	ecdsa521Key := newTstHostKey(t, octeliumC, ssh.KeyAlgoECDSA521)
	rsaKey := newTstHostKey(t, octeliumC, ssh.KeyAlgoRSA)
	mldsaKey := newTstHostKey(t, octeliumC, ssh.KeyAlgoMLDSA65)

	skEd25519Key, err := ssh.ParsePublicKey(ssh.Marshal(struct {
		Name        string
		KeyBytes    []byte
		Application string
	}{
		Name:        ssh.KeyAlgoSKED25519,
		KeyBytes:    make([]byte, ed25519.PublicKeySize),
		Application: "ssh:",
	}))
	require.Nil(t, err)

	ecdsaWire := struct {
		Name  string
		Curve string
		Point []byte
	}{}
	require.Nil(t, ssh.Unmarshal(ecdsa256Key.signer.PublicKey().Marshal(), &ecdsaWire))
	skECDSAKey, err := ssh.ParsePublicKey(ssh.Marshal(struct {
		Name        string
		Curve       string
		Point       []byte
		Application string
	}{
		Name:        ssh.KeyAlgoSKECDSA256,
		Curve:       ecdsaWire.Curve,
		Point:       ecdsaWire.Point,
		Application: "ssh:",
	}))
	require.Nil(t, err)

	for _, tc := range []struct {
		name string
		key  ssh.PublicKey
		want []string
	}{
		{"ed25519", ed25519Key.signer.PublicKey(), []string{ssh.KeyAlgoED25519}},
		{"ecdsa p256", ecdsa256Key.signer.PublicKey(), []string{ssh.KeyAlgoECDSA256}},
		{"ecdsa p384", ecdsa384Key.signer.PublicKey(), []string{ssh.KeyAlgoECDSA384}},
		{"ecdsa p521", ecdsa521Key.signer.PublicKey(), []string{ssh.KeyAlgoECDSA521}},
		{"rsa", rsaKey.signer.PublicKey(), []string{ssh.KeyAlgoRSASHA256, ssh.KeyAlgoRSASHA512, ssh.KeyAlgoRSA}},
		{"ml-dsa", mldsaKey.signer.PublicKey(), []string{ssh.KeyAlgoMLDSA65}},
		{"ed25519 certificate", ed25519Key.cert.PublicKey(), []string{ssh.CertAlgoED25519v01}},
		{"ecdsa p256 certificate", ecdsa256Key.cert.PublicKey(), []string{ssh.CertAlgoECDSA256v01}},
		{"ecdsa p384 certificate", ecdsa384Key.cert.PublicKey(), []string{ssh.CertAlgoECDSA384v01}},
		{"ecdsa p521 certificate", ecdsa521Key.cert.PublicKey(), []string{ssh.CertAlgoECDSA521v01}},
		{"rsa certificate", rsaKey.cert.PublicKey(),
			[]string{ssh.CertAlgoRSASHA256v01, ssh.CertAlgoRSASHA512v01, ssh.CertAlgoRSAv01}},
		{"ml-dsa certificate", mldsaKey.cert.PublicKey(), []string{ssh.CertAlgoMLDSA65v01Go}},
		{"security key ed25519", skEd25519Key, nil},
		{"security key ecdsa", skECDSAKey, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			algos := getUpstreamHostKeyAlgorithms(tc.key)
			assert.Equal(t, tc.want, algos)

			defaultForKey := slices.DeleteFunc(slices.Clone(defaultAlgos), func(algo string) bool {
				return getHostKeyAlgorithmFormat(algo) != tc.key.Type()
			})
			if len(defaultForKey) == 0 {
				defaultForKey = nil
			}
			assert.Equal(t, defaultForKey, algos,
				"the algorithms must be the default ones for the key, in the default order")
		})
	}
}

func TestGetHostKeyAlgorithmFormat(t *testing.T) {
	for _, tc := range []struct {
		algo string
		want string
	}{
		{ssh.KeyAlgoRSASHA256, ssh.KeyAlgoRSA},
		{ssh.KeyAlgoRSASHA512, ssh.KeyAlgoRSA},
		{ssh.KeyAlgoRSA, ssh.KeyAlgoRSA},
		{ssh.CertAlgoRSASHA256v01, ssh.CertAlgoRSAv01},
		{ssh.CertAlgoRSASHA512v01, ssh.CertAlgoRSAv01},
		{ssh.CertAlgoRSAv01, ssh.CertAlgoRSAv01},
		{ssh.KeyAlgoED25519, ssh.KeyAlgoED25519},
		{ssh.KeyAlgoECDSA256, ssh.KeyAlgoECDSA256},
		{ssh.CertAlgoED25519v01, ssh.CertAlgoED25519v01},
		{"unknown", "unknown"},
	} {
		assert.Equal(t, tc.want, getHostKeyAlgorithmFormat(tc.algo), tc.algo)
	}
}

func TestClientConfigUpstreamHostKeyAlgorithms(t *testing.T) {
	octeliumC, _ := newTstCAOcteliumC(t)
	svc := newTstSSHService()
	signer, err := newUpstreamSigner(t.Context(), octeliumC, svc)
	require.Nil(t, err)

	ed25519Key := newTstHostKey(t, octeliumC, ssh.KeyAlgoED25519)
	ecdsaKey := newTstHostKey(t, octeliumC, ssh.KeyAlgoECDSA256)
	rsaKey := newTstHostKey(t, octeliumC, ssh.KeyAlgoRSA)
	otherKey := newTstHostKey(t, octeliumC, ssh.KeyAlgoED25519)

	rsaAlgos := []string{ssh.KeyAlgoRSASHA256, ssh.KeyAlgoRSASHA512, ssh.KeyAlgoRSA}

	for _, tc := range []struct {
		name     string
		cfg      *corev1.Service_Spec_Config
		upstream *loadbalancer.Upstream
		accepted []ssh.PublicKey
		want     []string
	}{
		{
			name:     "ed25519",
			cfg:      getTstHostKeyConfig(getTstAuthorizedKey(ed25519Key.signer.PublicKey())),
			accepted: []ssh.PublicKey{ed25519Key.signer.PublicKey()},
			want:     []string{ssh.KeyAlgoED25519},
		},
		{
			name:     "ecdsa",
			cfg:      getTstHostKeyConfig(getTstAuthorizedKey(ecdsaKey.signer.PublicKey())),
			accepted: []ssh.PublicKey{ecdsaKey.signer.PublicKey()},
			want:     []string{ssh.KeyAlgoECDSA256},
		},
		{
			name:     "rsa",
			cfg:      getTstHostKeyConfig(getTstAuthorizedKey(rsaKey.signer.PublicKey())),
			accepted: []ssh.PublicKey{rsaKey.signer.PublicKey()},
			want:     rsaAlgos,
		},
		{
			name:     "certificate",
			cfg:      getTstHostKeyConfig(getTstAuthorizedKey(ed25519Key.cert.PublicKey())),
			accepted: []ssh.PublicKey{ed25519Key.cert.PublicKey()},
			want:     []string{ssh.CertAlgoED25519v01},
		},
		{
			name: "comment and known_hosts style",
			cfg: getTstHostKeyConfig(fmt.Sprintf("# upstream\n[upstream.example.com]:2222 %s",
				getTstAuthorizedKey(rsaKey.signer.PublicKey()))),
			accepted: []ssh.PublicKey{rsaKey.signer.PublicKey()},
			want:     rsaAlgos,
		},
		{
			name: "only the first key is used",
			cfg: getTstHostKeyConfig(fmt.Sprintf("%s\n%s",
				getTstAuthorizedKey(ed25519Key.signer.PublicKey()),
				getTstAuthorizedKey(rsaKey.signer.PublicKey()))),
			accepted: []ssh.PublicKey{ed25519Key.signer.PublicKey()},
			want:     []string{ssh.KeyAlgoED25519},
		},
		{
			name: "invalid lines before the key are skipped",
			cfg: getTstHostKeyConfig(fmt.Sprintf("ssh-ed25519 invalid\n%s",
				getTstAuthorizedKey(ecdsaKey.signer.PublicKey()))),
			accepted: []ssh.PublicKey{ecdsaKey.signer.PublicKey()},
			want:     []string{ssh.KeyAlgoECDSA256},
		},
		{
			name: "insecure",
			cfg: &corev1.Service_Spec_Config{
				Type: &corev1.Service_Spec_Config_Ssh{
					Ssh: &corev1.Service_Spec_Config_SSH{
						UpstreamHostKey: &corev1.Service_Spec_Config_SSH_UpstreamHostKey{
							Type: &corev1.Service_Spec_Config_SSH_UpstreamHostKey_InsecureIgnoreHostKey{
								InsecureIgnoreHostKey: true,
							},
						},
					},
				},
			},
			accepted: []ssh.PublicKey{ed25519Key.signer.PublicKey(), rsaKey.signer.PublicKey(), otherKey.signer.PublicKey()},
		},
		{
			name:     "cluster CA",
			cfg:      getTstSSHConfig("root"),
			accepted: []ssh.PublicKey{ed25519Key.cert.PublicKey(), rsaKey.cert.PublicKey()},
		},
		{
			name:     "no config",
			accepted: []ssh.PublicKey{ecdsaKey.cert.PublicKey()},
		},
		{
			name:     "embedded SSH",
			cfg:      getTstHostKeyConfig(getTstAuthorizedKey(rsaKey.signer.PublicKey())),
			upstream: &loadbalancer.Upstream{IsESSH: true, Ed25519PublicKey: ed25519Key.priv.Public().(ed25519.PublicKey)},
			accepted: []ssh.PublicKey{ed25519Key.signer.PublicKey()},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			upstream := tc.upstream
			if upstream == nil {
				upstream = &loadbalancer.Upstream{}
			}

			c := newTstUpstreamDctx(upstream, "root", tc.cfg)
			cfg, err := c.getClientConfig(t.Context(), octeliumC, svc, signer, nil, upstream)
			require.Nil(t, err)

			assert.Equal(t, tc.want, cfg.HostKeyAlgorithms)
			for _, key := range tc.accepted {
				assert.Nil(t, cfg.HostKeyCallback("upstream:22", &net.TCPAddr{}, key))
			}
			if !tc.cfg.GetSsh().GetUpstreamHostKey().GetInsecureIgnoreHostKey() {
				assert.NotNil(t, cfg.HostKeyCallback("upstream:22", &net.TCPAddr{}, otherKey.signer.PublicKey()))
			}

			offered := getTstOfferedHostKeyAlgorithms(t, cfg)
			if tc.want == nil {
				assert.Equal(t, getTstDefaultHostKeyAlgorithms(t), offered)
			} else {
				assert.Equal(t, tc.want, offered)
			}
		})
	}
}

func newTstHostKeyUpstream(t *testing.T, hostKeys []ssh.Signer) string {
	t.Helper()

	config := &ssh.ServerConfig{
		NoClientAuth: true,
	}
	for _, hostKey := range hostKeys {
		config.AddHostKey(hostKey)
	}

	lis, err := net.Listen("tcp", "127.0.0.1:0")
	require.Nil(t, err)

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

	return lis.Addr().String()
}

func getTstNegotiatedHostKeyAlgorithm(conn ssh.Conn) string {
	return conn.(ssh.AlgorithmsConnMetadata).Algorithms().HostKey
}

type tstHostKeyResult struct {
	algo       string
	err        error
	legacyAlgo string
	legacyErr  error
}

func connectTstUpstreamHostKey(t *testing.T, octeliumC octeliumc.ClientInterface,
	signer *upstreamSigner, addr, user string, cfg *corev1.Service_Spec_Config) *tstHostKeyResult {
	t.Helper()

	ret := &tstHostKeyResult{}
	svc := newTstSSHService()
	upstream := &loadbalancer.Upstream{HostPort: addr}

	legacyConfig, err := newTstUpstreamDctx(upstream, user, cfg).getClientConfig(t.Context(), octeliumC, svc, signer, nil, upstream)
	require.Nil(t, err)
	legacyConfig.HostKeyAlgorithms = nil

	legacyClient, err := ssh.Dial("tcp", addr, legacyConfig)
	ret.legacyErr = err
	if err == nil {
		ret.legacyAlgo = getTstNegotiatedHostKeyAlgorithm(legacyClient.Conn)
		legacyClient.Close()
	}

	c := newTstUpstreamDctx(upstream, user, cfg)
	ret.err = c.connect(t.Context(), octeliumC, svc, nil, signer, nil)
	if ret.err == nil {
		ret.algo = getTstNegotiatedHostKeyAlgorithm(c.remoteConn.sshClient.Conn)
	}
	closeTstUpstream(c)

	return ret
}

func TestConnectUpstreamHostKeyCompatibility(t *testing.T) {
	octeliumC, _ := newTstCAOcteliumC(t)
	signer, err := newUpstreamSigner(t.Context(), octeliumC, newTstSSHService())
	require.Nil(t, err)

	ed25519Key := newTstHostKey(t, octeliumC, ssh.KeyAlgoED25519)
	ecdsaKey := newTstHostKey(t, octeliumC, ssh.KeyAlgoECDSA256)
	rsaKey := newTstHostKey(t, octeliumC, ssh.KeyAlgoRSA)
	otherEd25519Key := newTstHostKey(t, octeliumC, ssh.KeyAlgoED25519)
	otherRSAKey := newTstHostKey(t, octeliumC, ssh.KeyAlgoRSA)

	rsaSHA1Signer, err := ssh.NewSignerWithAlgorithms(rsaKey.signer.(ssh.AlgorithmSigner), []string{ssh.KeyAlgoRSA})
	require.Nil(t, err)

	type slot struct {
		name    string
		signers []ssh.Signer
	}
	getSlots := func(key *tstHostKey, name string) []slot {
		return []slot{
			{},
			{name, []ssh.Signer{key.signer}},
			{name + "-cert", []ssh.Signer{key.cert}},
			{name + "+cert", []ssh.Signer{key.signer, key.cert}},
		}
	}

	pins := []struct {
		name string
		key  ssh.PublicKey
	}{
		{"ed25519", ed25519Key.signer.PublicKey()},
		{"ed25519 certificate", ed25519Key.cert.PublicKey()},
		{"ecdsa", ecdsaKey.signer.PublicKey()},
		{"ecdsa certificate", ecdsaKey.cert.PublicKey()},
		{"rsa", rsaKey.signer.PublicKey()},
		{"rsa certificate", rsaKey.cert.PublicKey()},
		{"other ed25519", otherEd25519Key.signer.PublicKey()},
		{"other rsa", otherRSAKey.signer.PublicKey()},
	}

	var mu sync.Mutex
	fixed := 0
	total := 0

	t.Run("matrix", func(t *testing.T) {
		for _, ed25519Slot := range getSlots(ed25519Key, "ed25519") {
			for _, ecdsaSlot := range getSlots(ecdsaKey, "ecdsa") {
				for _, rsaSlot := range append(getSlots(rsaKey, "rsa"), slot{"rsa-sha1", []ssh.Signer{rsaSHA1Signer}}) {
					hostKeys := slices.Concat(ed25519Slot.signers, ecdsaSlot.signers, rsaSlot.signers)
					if len(hostKeys) == 0 {
						continue
					}

					name := strings.Join(slices.DeleteFunc([]string{ed25519Slot.name, ecdsaSlot.name, rsaSlot.name},
						func(s string) bool { return s == "" }), ",")

					t.Run(name, func(t *testing.T) {
						t.Parallel()

						addr := newTstHostKeyUpstream(t, hostKeys)

						for _, pin := range pins {
							res := connectTstUpstreamHostKey(t, octeliumC, signer, addr, "root",
								getTstHostKeyConfig(getTstAuthorizedKey(pin.key)))

							served := slices.ContainsFunc(hostKeys, func(s ssh.Signer) bool {
								return bytes.Equal(s.PublicKey().Marshal(), pin.key.Marshal())
							})

							assert.Equal(t, served, res.err == nil, "pin %s: %+v", pin.name, res.err)
							if res.legacyErr == nil {
								assert.Nil(t, res.err, "pin %s worked before but not anymore", pin.name)
								assert.Equal(t, res.legacyAlgo, res.algo, "pin %s negotiated another algorithm", pin.name)
							}
							if res.err == nil {
								assert.Equal(t, pin.key.Type(), getHostKeyAlgorithmFormat(res.algo), "pin %s", pin.name)
							}

							mu.Lock()
							total++
							if res.legacyErr != nil && res.err == nil {
								fixed++
							}
							mu.Unlock()
						}
					})
				}
			}
		}
	})

	assert.Equal(t, 79*len(pins), total)
	assert.Greater(t, fixed, 0)
	t.Logf("%d of %d combinations failed before and now work", fixed, total)
}

func TestConnectUpstreamHostKeyServerDefaults(t *testing.T) {
	octeliumC, _ := newTstCAOcteliumC(t)
	signer, err := newUpstreamSigner(t.Context(), octeliumC, newTstSSHService())
	require.Nil(t, err)

	ed25519Key := newTstHostKey(t, octeliumC, ssh.KeyAlgoED25519)
	ecdsaKey := newTstHostKey(t, octeliumC, ssh.KeyAlgoECDSA256)
	rsaKey := newTstHostKey(t, octeliumC, ssh.KeyAlgoRSA)
	mldsaKey := newTstHostKey(t, octeliumC, ssh.KeyAlgoMLDSA65)

	addr := newTstHostKeyUpstream(t, []ssh.Signer{rsaKey.signer, ecdsaKey.signer, ed25519Key.signer, mldsaKey.signer})

	for _, tc := range []struct {
		name       string
		key        ssh.PublicKey
		want       string
		legacyWant string
	}{
		{"ed25519", ed25519Key.signer.PublicKey(), ssh.KeyAlgoED25519, ""},
		{"ecdsa", ecdsaKey.signer.PublicKey(), ssh.KeyAlgoECDSA256, ssh.KeyAlgoECDSA256},
		{"rsa", rsaKey.signer.PublicKey(), ssh.KeyAlgoRSASHA256, ""},
		{"ml-dsa", mldsaKey.signer.PublicKey(), ssh.KeyAlgoMLDSA65, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			res := connectTstUpstreamHostKey(t, octeliumC, signer, addr, "root",
				getTstHostKeyConfig(getTstAuthorizedKey(tc.key)))
			require.Nil(t, res.err)
			assert.Equal(t, tc.want, res.algo)

			if tc.legacyWant == "" {
				require.NotNil(t, res.legacyErr)
				assert.Contains(t, res.legacyErr.Error(), "host key mismatch")
			} else {
				require.Nil(t, res.legacyErr)
				assert.Equal(t, tc.legacyWant, res.legacyAlgo)
			}
		})
	}

	t.Run("missing type", func(t *testing.T) {
		addr := newTstHostKeyUpstream(t, []ssh.Signer{rsaKey.signer, ed25519Key.signer})
		res := connectTstUpstreamHostKey(t, octeliumC, signer, addr, "root",
			getTstHostKeyConfig(getTstAuthorizedKey(ecdsaKey.signer.PublicKey())))
		require.NotNil(t, res.err)
		assert.Contains(t, res.err.Error(), "no common algorithm for host key")
		require.NotNil(t, res.legacyErr)
		assert.Contains(t, res.legacyErr.Error(), "host key mismatch")
	})
}

func writeTstOpenSSHHostKey(t *testing.T, dir, name string, key *tstHostKey, withCert bool) string {
	t.Helper()

	block, err := ssh.MarshalPrivateKey(key.priv, "")
	require.Nil(t, err)
	path := filepath.Join(dir, name)
	require.Nil(t, os.WriteFile(path, pem.EncodeToMemory(block), 0o600))

	ret := fmt.Sprintf("HostKey %s", path)
	if withCert {
		require.Nil(t, os.WriteFile(path+"-cert.pub", ssh.MarshalAuthorizedKey(key.cert.PublicKey()), 0o644))
		ret = fmt.Sprintf("%s\nHostCertificate %s-cert.pub", ret, path)
	}

	return ret
}

func TestConnectUpstreamOpenSSHHostKey(t *testing.T) {
	getTstSSHDPath(t)

	octeliumC, ca := newTstCAOcteliumC(t)
	svc := newTstSSHService()
	signer, err := newUpstreamSigner(t.Context(), octeliumC, svc)
	require.Nil(t, err)

	usr, err := user.Current()
	require.Nil(t, err)

	ed25519Key := newTstHostKey(t, octeliumC, ssh.KeyAlgoED25519)
	ecdsaKey := newTstHostKey(t, octeliumC, ssh.KeyAlgoECDSA256)
	rsaKey := newTstHostKey(t, octeliumC, ssh.KeyAlgoRSA)
	otherKey := newTstHostKey(t, octeliumC, ssh.KeyAlgoED25519)

	type hostKey struct {
		name     string
		key      *tstHostKey
		withCert bool
	}

	defaultHostKeys := []hostKey{{"rsa", rsaKey, false}, {"ecdsa", ecdsaKey, false}, {"ed25519", ed25519Key, false}}

	for _, tc := range []struct {
		name       string
		hostKeys   []hostKey
		config     string
		pin        ssh.PublicKey
		want       string
		legacyWant string
	}{
		{
			name:     "default host keys with ed25519",
			hostKeys: defaultHostKeys,
			pin:      ed25519Key.signer.PublicKey(),
			want:     ssh.KeyAlgoED25519,
		},
		{
			name:       "default host keys with ecdsa",
			hostKeys:   defaultHostKeys,
			pin:        ecdsaKey.signer.PublicKey(),
			want:       ssh.KeyAlgoECDSA256,
			legacyWant: ssh.KeyAlgoECDSA256,
		},
		{
			name:     "default host keys with rsa",
			hostKeys: defaultHostKeys,
			pin:      rsaKey.signer.PublicKey(),
			want:     ssh.KeyAlgoRSASHA256,
		},
		{
			name:       "rsa and ed25519 with rsa",
			hostKeys:   []hostKey{{"rsa", rsaKey, false}, {"ed25519", ed25519Key, false}},
			pin:        rsaKey.signer.PublicKey(),
			want:       ssh.KeyAlgoRSASHA256,
			legacyWant: ssh.KeyAlgoRSASHA256,
		},
		{
			name:     "rsa and ed25519 with ed25519",
			hostKeys: []hostKey{{"rsa", rsaKey, false}, {"ed25519", ed25519Key, false}},
			pin:      ed25519Key.signer.PublicKey(),
			want:     ssh.KeyAlgoED25519,
		},
		{
			name:     "rsa and ed25519 with ecdsa",
			hostKeys: []hostKey{{"rsa", rsaKey, false}, {"ed25519", ed25519Key, false}},
			pin:      ecdsaKey.signer.PublicKey(),
		},
		{
			name:       "ed25519 only",
			hostKeys:   []hostKey{{"ed25519", ed25519Key, false}},
			pin:        ed25519Key.signer.PublicKey(),
			want:       ssh.KeyAlgoED25519,
			legacyWant: ssh.KeyAlgoED25519,
		},
		{
			name:     "ed25519 only with another key",
			hostKeys: []hostKey{{"ed25519", ed25519Key, false}},
			pin:      otherKey.signer.PublicKey(),
		},
		{
			name:     "host certificates with ed25519",
			hostKeys: []hostKey{{"ecdsa", ecdsaKey, true}, {"ed25519", ed25519Key, true}},
			pin:      ed25519Key.signer.PublicKey(),
			want:     ssh.KeyAlgoED25519,
		},
		{
			name:     "host certificates with ecdsa",
			hostKeys: []hostKey{{"ecdsa", ecdsaKey, true}, {"ed25519", ed25519Key, true}},
			pin:      ecdsaKey.signer.PublicKey(),
			want:     ssh.KeyAlgoECDSA256,
		},
		{
			name:       "host certificates with the ecdsa certificate",
			hostKeys:   []hostKey{{"ecdsa", ecdsaKey, true}, {"ed25519", ed25519Key, true}},
			pin:        ecdsaKey.cert.PublicKey(),
			want:       ssh.CertAlgoECDSA256v01,
			legacyWant: ssh.CertAlgoECDSA256v01,
		},
		{
			name:     "host certificates with the ed25519 certificate",
			hostKeys: []hostKey{{"ecdsa", ecdsaKey, true}, {"ed25519", ed25519Key, true}},
			pin:      ed25519Key.cert.PublicKey(),
			want:     ssh.CertAlgoED25519v01,
		},
		{
			name:       "rsa with sha1 only",
			hostKeys:   []hostKey{{"rsa", rsaKey, false}, {"ed25519", ed25519Key, false}},
			config:     "HostKeyAlgorithms ssh-rsa",
			pin:        rsaKey.signer.PublicKey(),
			want:       ssh.KeyAlgoRSA,
			legacyWant: ssh.KeyAlgoRSA,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv := startTstOpenSSHServerWithConfig(t, func(t *testing.T, dir string) string {
				var lines []string
				for _, hostKey := range tc.hostKeys {
					lines = append(lines, writeTstOpenSSHHostKey(t, dir, hostKey.name, hostKey.key, hostKey.withCert))
				}
				authorizedKeys := filepath.Join(dir, "authorized_keys")
				require.Nil(t, os.WriteFile(authorizedKeys,
					[]byte(fmt.Sprintf("%s octelium-managed:example.com\n", getTstCAAuthorizedKeyLine(ca))), 0o644))

				lines = append(lines, "LogLevel INFO", fmt.Sprintf("AuthorizedKeysFile %s", authorizedKeys))
				if tc.config != "" {
					lines = append(lines, tc.config)
				}
				return strings.Join(lines, "\n")
			})

			cfg := getTstHostKeyConfig(getTstAuthorizedKey(tc.pin))
			cfg.GetSsh().User = usr.Username

			res := connectTstUpstreamHostKey(t, octeliumC, signer, srv.addr, "other", cfg)

			if tc.legacyWant == "" {
				assert.NotNil(t, res.legacyErr)
			} else {
				require.Nil(t, res.legacyErr, "%+v\n%s", res.legacyErr, srv.logs.String())
				assert.Equal(t, tc.legacyWant, res.legacyAlgo)
			}

			if tc.want == "" {
				assert.NotNil(t, res.err)
				return
			}
			require.Nil(t, res.err, "%+v\n%s", res.err, srv.logs.String())
			assert.Equal(t, tc.want, res.algo)

			c := newTstUpstreamDctx(&loadbalancer.Upstream{HostPort: srv.addr}, "other", cfg)
			require.Nil(t, c.connect(t.Context(), octeliumC, svc, nil, signer, nil))
			defer closeTstUpstream(c)

			session, err := c.remoteConn.sshClient.NewSession()
			require.Nil(t, err)
			out, err := session.Output("echo upstream-ok")
			session.Close()
			require.Nil(t, err, "%s", srv.logs.String())
			assert.Equal(t, "upstream-ok\n", string(out))
		})
	}
}
