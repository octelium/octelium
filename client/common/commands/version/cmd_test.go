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

package version

import (
	"bufio"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"bytes"
	"github.com/fatih/color"
	"github.com/octelium/octelium/client/common/cliutils"
	"github.com/octelium/octelium/pkg/utils/ldflags"
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"sigs.k8s.io/yaml"
)

type releaseHTTPResponse struct {
	code int
	body string
}

var releaseResponse atomic.Value
var releaseRequests = make(chan *http.Request, 32)

func TestMain(m *testing.M) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), DNSNames: []string{"api.github.com"},
		NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, IsCA: true, BasicConstraintsValid: true}
	der, err := x509.CreateCertificate(rand.Reader, template, template, publicKey, privateKey)
	if err != nil {
		panic(err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	cert := tls.Certificate{Certificate: [][]byte{der}, PrivateKey: privateKey}
	releaseResponse.Store(releaseHTTPResponse{code: http.StatusOK, body: `{"tag_name":"v1.2.3"}`})
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodConnect || r.Host != "api.github.com:443" {
			http.Error(w, "unexpected target", http.StatusBadGateway)
			return
		}
		conn, _, err := w.(http.Hijacker).Hijack()
		if err != nil {
			return
		}
		defer conn.Close()
		conn.SetDeadline(time.Now().Add(5 * time.Second))
		if _, err := io.WriteString(conn, "HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
			return
		}
		tlsConn := tls.Server(conn, &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12})
		defer tlsConn.Close()
		req, err := http.ReadRequest(bufio.NewReader(tlsConn))
		if err != nil {
			return
		}
		defer req.Body.Close()
		releaseRequests <- req
		resp := releaseResponse.Load().(releaseHTTPResponse)
		fmt.Fprintf(tlsConn, "HTTP/1.1 %d %s\r\nContent-Type: application/json\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s", resp.code, http.StatusText(resp.code), len(resp.body), resp.body)
	}))
	if err := os.Setenv("GODEBUG", os.Getenv("GODEBUG")+",x509usefallbackroots=1"); err != nil {
		panic(err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(certPEM) {
		panic("could not load test certificate")
	}
	x509.SetFallbackRoots(roots)
	for key, value := range map[string]string{"HTTPS_PROXY": proxy.URL, "https_proxy": proxy.URL, "NO_PROXY": "", "no_proxy": ""} {
		if err := os.Setenv(key, value); err != nil {
			panic(err)
		}
	}
	code := m.Run()
	proxy.Close()
	os.Exit(code)
}

func TestNormalizeVersionTag(t *testing.T) {
	for _, itm := range []struct {
		arg  string
		want string
	}{
		{"v1.2.3", "1.2.3"}, {"1.2.3", "1.2.3"}, {" \tv1.2.3\n", "1.2.3"},
		{"v1.2.3-rc.1+build", "1.2.3-rc.1+build"}, {"", ""},
	} {
		assert.Equal(t, itm.want, normalizeVersionTag(itm.arg))
	}
}

func TestVersionOutput(t *testing.T) {
	previousArgs := cmdArgs
	t.Cleanup(func() { cmdArgs = previousArgs })
	for _, format := range []string{"json", "yaml", "yml", ""} {
		t.Run(format, func(t *testing.T) {
			cmdArgs = args{Out: format}
			file, err := os.Create(filepath.Join(t.TempDir(), "stdout"))
			require.NoError(t, err)
			previous := os.Stdout
			os.Stdout = file
			defer func() { os.Stdout = previous; file.Close() }()
			cmd := &cobra.Command{}
			cmd.SetContext(context.Background())
			require.NoError(t, Cmd.RunE(cmd, nil))
			_, err = file.Seek(0, io.SeekStart)
			require.NoError(t, err)
			out, err := io.ReadAll(file)
			require.NoError(t, err)
			ret := &OcteliumVersion{}
			if format == "json" {
				require.NoError(t, json.Unmarshal(out, ret))
			} else {
				require.NoError(t, yaml.Unmarshal(out, ret))
			}
			assert.Equal(t, *cliutils.GetOcteliumCommonVersion(), ret.OcteliumCommonVersion)
		})
	}
	cmdArgs = args{Out: "xml"}
	assert.ErrorContains(t, doCmd(&cobra.Command{}, nil), "Invalid output format")
}

func TestVersionCheckCanceled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	ret, err := getLatestVersion(ctx)
	assert.Nil(t, ret)
	assert.ErrorIs(t, err, context.Canceled)
	assert.ErrorIs(t, doCheckClient(ctx), context.Canceled)
	previous := cmdArgs
	t.Cleanup(func() { cmdArgs = previous })
	cmdArgs = args{CheckMode: true}
	cmd := &cobra.Command{}
	cmd.SetContext(ctx)
	assert.ErrorIs(t, doCmd(cmd, nil), context.Canceled)
}

func TestLatestReleaseHTTP(t *testing.T) {
	for _, itm := range []struct {
		name string
		code int
		body string
		want string
		err  string
	}{
		{"release", 200, `{"tag_name":"v1.2.3"}`, "1.2.3", ""},
		{"prerelease", 200, `{"tag_name":"v2.0.0-rc.1"}`, "2.0.0-rc.1", ""},
		{"API failure", 403, `{"message":"rate limited"}`, "", "403 Forbidden"},
		{"invalid JSON", 200, `{`, "", "unexpected end"},
		{"invalid version", 200, `{"tag_name":"invalid"}`, "", "malformed version"},
		{"missing tag", 200, `{}`, "", "malformed version"},
	} {
		t.Run(itm.name, func(t *testing.T) {
			releaseResponse.Store(releaseHTTPResponse{code: itm.code, body: itm.body})
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			ret, err := getLatestVersion(ctx)
			if itm.err != "" {
				assert.ErrorContains(t, err, itm.err)
				assert.Nil(t, ret)
			} else {
				require.NoError(t, err)
				assert.Equal(t, itm.want, ret.String())
			}
			select {
			case req := <-releaseRequests:
				assert.Equal(t, http.MethodGet, req.Method)
				assert.Equal(t, "/repos/octelium/octelium/releases/latest", req.URL.Path)
				assert.Equal(t, "application/vnd.github+json", req.Header.Get("Accept"))
				assert.Equal(t, "2026-03-10", req.Header.Get("X-GitHub-Api-Version"))
			case <-ctx.Done():
				t.Fatal("release API request was not received")
			}
		})
	}
}

func TestVersionCheckHTTP(t *testing.T) {
	previousVersion, previousOut := ldflags.SemVer, color.Output
	t.Cleanup(func() { ldflags.SemVer, color.Output = previousVersion, previousOut })
	for _, itm := range []struct {
		current string
		latest  string
		want    string
	}{
		{"1.2.3", "v1.2.3", "up-to-date"}, {"2.0.0", "v1.2.3", "up-to-date"}, {"1.2.3", "v2.0.0", "can be upgraded"},
	} {
		ldflags.SemVer = itm.current
		releaseResponse.Store(releaseHTTPResponse{code: 200, body: fmt.Sprintf(`{"tag_name":%q}`, itm.latest)})
		var out bytes.Buffer
		color.Output = &out
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		err := doCheckClient(ctx)
		cancel()
		require.NoError(t, err)
		assert.Contains(t, out.String(), itm.want)
	}
	ldflags.SemVer = "invalid"
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	assert.Error(t, doCheckClient(ctx))
	for len(releaseRequests) > 0 {
		<-releaseRequests
	}
}
