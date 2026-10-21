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
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/apis/main/metav1"
	"github.com/octelium/octelium/cluster/common/vutils"
	"github.com/octelium/octelium/cluster/e2e/harness"
	"github.com/octelium/octelium/pkg/apiutils/ucorev1"
	"github.com/octelium/octelium/pkg/utils/utilrand"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	k8scorev1 "k8s.io/api/core/v1"
	k8smetav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func testIngress(t *testing.T, h *harness.H) {
	h.Require(t, capHostPortIngress)

	t.Run("UnknownHost", func(t *testing.T) {
		url := fmt.Sprintf("https://%s.%s", utilrand.GetRandomStringCanonical(10), h.Domain)
		h.GetStatus(t, h.HTTP(), url, http.StatusNotFound)
	})

	t.Run("PublicToggle", func(t *testing.T) {
		svc := h.CreateService(t, &corev1.Service{
			Spec: &corev1.Service_Spec{
				Mode: corev1.Service_Spec_HTTP,
				Config: &corev1.Service_Spec_Config{
					Upstream: &corev1.Service_Spec_Config_Upstream{
						Type: &corev1.Service_Spec_Config_Upstream_Container_{
							Container: &corev1.Service_Spec_Config_Upstream_Container{
								Image: "nginx",
								Port:  80,
							},
						},
					},
				},
			},
		})

		h.MustWaitService(t, svc.Metadata.Name)

		c := h.ServiceClient(svc, "")

		h.WaitStatus(t, c, "/", http.StatusNotFound)

		svc.Spec.IsPublic = true
		svc = h.UpdateService(t, svc)

		published := h.WaitStatus(t, c, "/", http.StatusUnauthorized)

		svc.Spec.IsPublic = false
		svc = h.UpdateService(t, svc)

		withdrawn := h.WaitStatus(t, c, "/", http.StatusNotFound)

		zap.L().Info("Ingress route propagation",
			zap.Duration("published", published), zap.Duration("withdrawn", withdrawn))

		assert.Less(t, published, propagationBudget,
			"publishing a Service took %s, budget is %s", published, propagationBudget)
		assert.Less(t, withdrawn, propagationBudget,
			"withdrawing a Service took %s, budget is %s", withdrawn, propagationBudget)
	})

	t.Run("NamespacedHostname", func(t *testing.T) {
		ns := h.EnsureTestNamespace(t)
		svc := h.NewPublicService(t, ns.Metadata.Name)

		assert.Equal(t, fmt.Sprintf("https://%s.%s", svc.Metadata.Name, h.Domain),
			h.ServiceURL(svc))

		h.WaitStatus(t, h.ServiceClient(svc, ""), "/", http.StatusUnauthorized)
	})

	t.Run("GlobalResponseHeaders", func(t *testing.T) {
		res, err := h.HTTP().R().Get(h.PublicURL("demo-nginx"))
		require.Nil(t, err)

		assert.Equal(t, "octelium", res.Header().Get("Server"))
		assert.Equal(t, "max-age=2592000", res.Header().Get("Strict-Transport-Security"))
	})

	t.Run("Certificate", func(t *testing.T) {
		conn, err := tls.Dial("tcp", fmt.Sprintf("%s:443", h.Domain), &tls.Config{
			ServerName: fmt.Sprintf("demo-nginx.%s", h.Domain),
		})
		require.Nil(t, err, "the Ingress certificate is not trusted by the host")
		defer conn.Close()

		certs := conn.ConnectionState().PeerCertificates
		require.True(t, len(certs) > 0)

		assert.Nil(t, certs[0].VerifyHostname(fmt.Sprintf("demo-nginx.%s", h.Domain)))
	})

	t.Run("AnonymousLargeBody", func(t *testing.T) {
		upstream := h.StartHTTPUpstream(t, nil)

		var got atomic.Int64
		upstream.SetServeFn(func(w http.ResponseWriter, r *http.Request) {
			var n int64
			buf := make([]byte, 32*1024)
			for {
				read, err := r.Body.Read(buf)
				n += int64(read)
				if err != nil {
					break
				}
			}
			got.Store(n)
			w.WriteHeader(http.StatusOK)
		})

		svc := h.CreateService(t, &corev1.Service{
			Metadata: &metav1.Metadata{
				Name: fmt.Sprintf("%s.default", utilrand.GetRandomStringCanonical(8)),
			},
			Spec: &corev1.Service_Spec{
				Mode:        corev1.Service_Spec_HTTP,
				IsPublic:    true,
				IsAnonymous: true,
				Config: &corev1.Service_Spec_Config{
					Upstream: &corev1.Service_Spec_Config_Upstream{
						Type: &corev1.Service_Spec_Config_Upstream_Url{
							Url: fmt.Sprintf("http://localhost:%d", upstream.Port),
						},
						User: "root",
					},
				},
			},
		})

		h.MustWaitService(t, svc.Metadata.Name)

		h.Connect(t, harness.ConnectOpts{Serve: []string{svc.Metadata.Name}})

		body := utilrand.GetRandomBytesMust(4 * 1024 * 1024)

		h.Eventually(t, "the Ingress to carry a large body to the upstream",
			harness.DecisionBudget, func(ctx context.Context) error {
				got.Store(0)

				res, err := h.HTTP().R().SetContext(ctx).
					SetHeader("Content-Type", "application/octet-stream").
					SetBody(body).
					Post(h.ServiceURL(svc) + "/")
				if err != nil {
					return err
				}
				if res.StatusCode() != http.StatusOK {
					return errUnexpectedStatus(res.StatusCode(), http.StatusOK)
				}
				if got.Load() != int64(len(body)) {
					return errors.Errorf("the upstream received %d bytes, want %d",
						got.Load(), len(body))
				}
				return nil
			})
	})
}

func testIngressCompression(t *testing.T, h *harness.H) {
	h.Require(t, capHostPortIngress)
	v := newVigilCtx(t, h)
	v.svc.Spec.IsAnonymous = true
	v.svc = h.UpdateService(t, v.svc)
	v.upstream.SetServeFn(func(w http.ResponseWriter, r *http.Request) {
		size, _ := strconv.Atoi(r.URL.Query().Get("size"))
		w.Header().Set("Content-Type", r.URL.Query().Get("type"))
		w.Header().Set("Content-Length", strconv.Itoa(size))
		if etag := r.URL.Query().Get("etag"); etag != "" {
			w.Header().Set("ETag", etag)
		}
		io.WriteString(w, strings.Repeat("a", size))
	})
	url := h.ServiceURL(v.svc)
	h.WaitStatus(t, h.HTTPNoRetry(), url+"/?size=1&type=text/plain", http.StatusOK)
	c := h.HTTPNoRetry().GetClient()
	t.Cleanup(c.CloseIdleConnections)
	for _, tc := range []struct {
		name     string
		mime     string
		size     int
		etag     string
		encoding string
		want     bool
	}{
		{"XML", "application/xml", 4096, "", "gzip", true},
		{"XHTML", "application/xhtml+xml", 4096, "", "gzip", true},
		{"JavaScript", "application/javascript", 4096, "", "gzip", true},
		{"LegacyJavaScript", "application/x-javascript", 4096, "", "gzip", true},
		{"HTML", "text/html", 4096, "", "gzip", true},
		{"CSS", "text/css", 4096, "", "gzip", true},
		{"PlainText", "text/plain; charset=utf-8", 4096, "", "gzip", true},
		{"TextXML", "text/xml", 4096, "", "gzip", true},
		{"CaseInsensitive", "TEXT/PLAIN", 4096, "", "gzip", true},
		{"MinimumLength", "text/plain", 1024, "", "gzip", true},
		{"BelowMinimumLength", "text/plain", 1023, "", "gzip", false},
		{"JSON", "application/json", 4096, "", "gzip", false},
		{"Binary", "application/octet-stream", 4096, "", "gzip", false},
		{"SVG", "image/svg+xml", 4096, "", "gzip", false},
		{"StrongETag", "text/plain", 4096, `"version"`, "gzip", false},
		{"WeakETag", "text/plain", 4096, `W/"version"`, "gzip", false},
		{"Identity", "text/plain", 4096, "", "identity", false},
		{"GzipDisabled", "text/plain", 4096, "", "gzip;q=0", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, url, nil)
			require.Nil(t, err)
			query := req.URL.Query()
			query.Set("size", strconv.Itoa(tc.size))
			query.Set("type", tc.mime)
			query.Set("etag", tc.etag)
			req.URL.RawQuery = query.Encode()
			req.Header.Set("Accept-Encoding", tc.encoding)
			res, err := c.Do(req)
			require.Nil(t, err)
			defer res.Body.Close()
			require.Equal(t, http.StatusOK, res.StatusCode)
			body, err := io.ReadAll(res.Body)
			require.Nil(t, err)
			if tc.want {
				require.Equal(t, "gzip", res.Header.Get("Content-Encoding"))
				assert.Less(t, len(body), tc.size)
				reader, err := gzip.NewReader(bytes.NewReader(body))
				require.Nil(t, err)
				defer reader.Close()
				body, err = io.ReadAll(reader)
				require.Nil(t, err)
			} else {
				assert.Empty(t, res.Header.Get("Content-Encoding"))
			}
			assert.Equal(t, strings.Repeat("a", tc.size), string(body))
			assert.Equal(t, tc.etag, res.Header.Get("ETag"))
		})
	}
}

func testIngressTLSBoundaries(t *testing.T, h *harness.H) {
	h.Require(t, capHostPortIngress)
	roots, err := h.TLSRoots()
	require.Nil(t, err)
	for _, tc := range []struct {
		name    string
		version uint16
		sni     string
		alpn    string
		want    bool
	}{
		{"TLS12HTTP1", tls.VersionTLS12, "demo-nginx." + h.Domain, "http/1.1", true},
		{"TLS13HTTP1", tls.VersionTLS13, "demo-nginx." + h.Domain, "http/1.1", true},
		{"TLS12HTTP2", tls.VersionTLS12, "demo-nginx." + h.Domain, "h2", true},
		{"TLS13HTTP2", tls.VersionTLS13, "demo-nginx." + h.Domain, "h2", true},
		{"TLS10", tls.VersionTLS10, "demo-nginx." + h.Domain, "http/1.1", false},
		{"TLS11", tls.VersionTLS11, "demo-nginx." + h.Domain, "http/1.1", false},
		{"MissingSNI", tls.VersionTLS13, "", "http/1.1", false},
		{"ForeignSNI", tls.VersionTLS13, "attacker.invalid", "http/1.1", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
			defer cancel()
			dialer := net.Dialer{Timeout: 5 * time.Second}
			raw, err := dialer.DialContext(ctx, "tcp", h.IngressAddr())
			require.Nil(t, err)
			defer raw.Close()
			conn := tls.Client(raw, &tls.Config{
				RootCAs: roots, ServerName: tc.sni, MinVersion: tc.version, MaxVersion: tc.version,
				NextProtos: []string{tc.alpn}, InsecureSkipVerify: !tc.want,
			})
			err = conn.HandshakeContext(ctx)
			if !tc.want {
				assert.NotNil(t, err)
				return
			}
			require.Nil(t, err)
			assert.Equal(t, tc.version, conn.ConnectionState().Version)
			assert.Equal(t, tc.alpn, conn.ConnectionState().NegotiatedProtocol)
			assert.NotEmpty(t, conn.ConnectionState().VerifiedChains)
		})
	}
}

func testIngressHTTPProtocolsLoad(t *testing.T, h *harness.H) {
	h.Require(t, capHostPortIngress)
	v := newVigilCtx(t, h)
	v.svc.Spec.IsAnonymous = true
	v.svc = h.UpdateService(t, v.svc)
	var requests atomic.Int64
	v.upstream.SetServeFn(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		if !strings.HasPrefix(r.URL.Path, "/known/") {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		io.WriteString(w, "ingress-load")
	})
	url := h.ServiceURL(v.svc)
	h.WaitStatus(t, h.HTTPNoRetry(), url+"/known/ready", http.StatusOK)
	unknown := h.PublicURL("unknown-" + h.Name())
	for _, tc := range []struct {
		name  string
		http2 bool
		fresh bool
	}{
		{"HTTP1", false, false},
		{"HTTP2", true, false},
		{"FreshTLS", false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			before := requests.Load()
			result, err := h.HTTPLoad(t.Context(), harness.HTTPLoadOpts{
				URL: url, Workers: 16, Requests: 160, Timeout: 10 * time.Second,
				HTTP2: tc.http2, NewConnPerRequest: tc.fresh,
				Request: func(worker, iteration int) harness.HTTPRequestSpec {
					if iteration%3 == 0 {
						return harness.HTTPRequestSpec{Class: "unknown", Path: unknown + "/unknown"}
					}
					return harness.HTTPRequestSpec{Class: "known", Path: fmt.Sprintf("/known/%d/%d", worker, iteration)}
				},
			})
			require.Nil(t, err)
			t.Log(result.String())
			require.Zero(t, result.Failed())
			assert.Positive(t, result.Count("known", http.StatusOK))
			assert.Positive(t, result.Count("unknown", http.StatusNotFound))
			assert.Zero(t, result.CountOther("known", http.StatusOK))
			assert.Zero(t, result.CountOther("unknown", http.StatusNotFound))
			assert.Equal(t, int64(result.Count("known", http.StatusOK)), requests.Load()-before)
		})
	}
	v.svc.Spec.IsPublic = false
	v.svc = h.UpdateService(t, v.svc)
	h.WaitStatus(t, h.HTTPNoRetry(), url+"/known/withdrawn", http.StatusNotFound)
	before := requests.Load()
	result, err := h.HTTPLoad(t.Context(), harness.HTTPLoadOpts{
		URL: url + "/known/withdrawn", Workers: 16, Requests: 160, Timeout: 10 * time.Second, HTTP2: true,
	})
	require.Nil(t, err)
	require.Zero(t, result.Failed())
	assert.Equal(t, result.Total, result.Count("default", http.StatusNotFound))
	assert.Equal(t, before, requests.Load())
	v.svc.Spec.IsPublic = true
	v.svc = h.UpdateService(t, v.svc)
	h.WaitStatus(t, h.HTTPNoRetry(), url+"/known/republished", http.StatusOK)
}

func testIngressHTTPValidation(t *testing.T, h *harness.H) {
	h.Require(t, capHostPortIngress)
	v := newVigilCtx(t, h)
	v.svc.Spec.IsAnonymous = true
	v.svc = h.UpdateService(t, v.svc)
	var requests atomic.Int64
	v.upstream.SetServeFn(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		io.WriteString(w, "ok")
	})
	address := h.ServiceURL(v.svc)
	h.WaitStatus(t, h.HTTPNoRetry(), address, http.StatusOK)
	parsed, err := url.Parse(address)
	require.Nil(t, err)
	roots, err := h.TLSRoots()
	require.Nil(t, err)
	for _, tc := range []struct {
		name    string
		headers string
		status  []int
	}{
		{"HeaderName", "Bad Header: value\r\n", []int{http.StatusBadRequest}},
		{"HeaderNUL", "X-Test: value\x00malicious\r\n", []int{http.StatusBadRequest}},
		{"DuplicateHost", "Host: attacker.invalid\r\n", []int{http.StatusBadRequest, http.StatusNotFound}},
		{"ConflictingLength", "Content-Length: 1\r\nContent-Length: 2\r\n", []int{http.StatusBadRequest}},
		{"ChunkedLength", "Content-Length: 0\r\nTransfer-Encoding: chunked\r\n", []int{http.StatusBadRequest}},
		{"HeaderLimit", "X-Large: " + strings.Repeat("a", 40*1024) + "\r\n", []int{http.StatusRequestHeaderFieldsTooLarge}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
			defer cancel()
			dialer := net.Dialer{Timeout: 5 * time.Second}
			raw, err := dialer.DialContext(ctx, "tcp", h.IngressAddr())
			require.Nil(t, err)
			defer raw.Close()
			conn := tls.Client(raw, &tls.Config{RootCAs: roots, ServerName: parsed.Hostname(), MinVersion: tls.VersionTLS12})
			require.Nil(t, conn.HandshakeContext(ctx))
			deadline, _ := ctx.Deadline()
			require.Nil(t, conn.SetDeadline(deadline))
			before := requests.Load()
			_, err = io.WriteString(conn, fmt.Sprintf("GET /invalid-input/%s HTTP/1.1\r\nHost: %s\r\n%s\r\n", tc.name, parsed.Host, tc.headers))
			require.Nil(t, err)
			response, err := http.ReadResponse(bufio.NewReader(conn), nil)
			require.Nil(t, err)
			defer response.Body.Close()
			_, err = io.ReadAll(response.Body)
			require.Nil(t, err)
			assert.Contains(t, tc.status, response.StatusCode)
			assert.Equal(t, before, requests.Load())
		})
	}
	h.GetStatus(t, h.HTTPNoRetry(), address, http.StatusOK)
}

func testIngressCertificateRotation(t *testing.T, h *harness.H) {
	h.Require(t, capHostPortIngress)

	h.Eventually(t, "the Ingress to keep serving during a certificate reinstall",
		harness.DecisionBudget, func(ctx context.Context) error {
			res, err := h.HTTP().R().SetContext(ctx).Get(h.ClusterURL())
			if err != nil {
				return err
			}
			if res.StatusCode() != http.StatusOK {
				return errUnexpectedStatus(res.StatusCode(), http.StatusOK)
			}
			return nil
		})

	h.MustRun(t, fmt.Sprintf("octops cert %s --key %s --cert %s --kubeconfig %s",
		h.Domain, h.State.KeyPath, h.State.CertPath, h.State.KubeconfigPath))

	h.Consistently(t, "the Ingress to keep answering after the certificate reinstall",
		3*decisionSettle, func(ctx context.Context) error {
			res, err := h.HTTP().R().SetContext(ctx).Get(h.ClusterURL())
			if err != nil {
				return err
			}
			if res.StatusCode() != http.StatusOK {
				return errUnexpectedStatus(res.StatusCode(), http.StatusOK)
			}
			return nil
		})
}

func testIngressSnapshotRetry(t *testing.T, h *harness.H) {
	h.Require(t, capHostPortIngress)
	v := newVigilCtx(t, h)
	v.record(t, http.StatusOK, "snapshot-retry")
	v.svc.Spec.IsAnonymous = true
	v.svc = h.UpdateService(t, v.svc)
	c := h.HTTPNoRetry()
	t.Cleanup(c.GetClient().CloseIdleConnections)
	h.WaitStatus(t, c, h.ServiceURL(v.svc), http.StatusOK)
	svc := h.CreateService(t, &corev1.Service{
		Spec: &corev1.Service_Spec{
			Mode: corev1.Service_Spec_HTTP,
			Config: &corev1.Service_Spec_Config{
				Upstream: &corev1.Service_Spec_Config_Upstream{
					Type: &corev1.Service_Spec_Config_Upstream_Url{Url: "http://example.invalid"},
				},
			},
		},
	})
	h.MustWaitService(t, svc.Metadata.Name)
	h.WaitStatus(t, c, h.ServiceURL(svc), http.StatusNotFound)
	secret := h.CreateSecret(t, "", "snapshot-retry")
	db, err := h.ClusterDB(t.Context())
	require.Nil(t, err)
	var original []byte
	require.Nil(t, db.QueryRowContext(t.Context(),
		`SELECT resource FROM octelium_resources WHERE api = $1 AND kind = $2 AND resource->'metadata'->>'uid' = $3`,
		ucorev1.API, ucorev1.KindSecret, secret.Metadata.Uid).Scan(&original))
	restored := false
	restore := func(ctx context.Context) error {
		_, err := db.ExecContext(ctx,
			`UPDATE octelium_resources SET resource = $1::jsonb WHERE api = $2 AND kind = $3 AND resource->'metadata'->>'uid' = $4`,
			string(original), ucorev1.API, ucorev1.KindSecret, secret.Metadata.Uid)
		return err
	}
	t.Cleanup(func() {
		if !restored {
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			defer cancel()
			assert.Nil(t, restore(ctx))
		}
	})
	pods, err := h.ComponentPods(t.Context(), "ingress")
	require.Nil(t, err)
	since := k8smetav1.NewTime(time.Now())
	result, err := db.ExecContext(t.Context(),
		`UPDATE octelium_resources SET resource = jsonb_set(jsonb_set(resource, '{metadata,systemLabels}', '{"octelium-cert":"true"}'::jsonb), '{data}', '{"value":123}'::jsonb) WHERE api = $1 AND kind = $2 AND resource->'metadata'->>'uid' = $3`,
		ucorev1.API, ucorev1.KindSecret, secret.Metadata.Uid)
	require.Nil(t, err)
	changed, err := result.RowsAffected()
	require.Nil(t, err)
	require.Equal(t, int64(1), changed)
	svc.Spec.IsPublic = true
	svc = h.UpdateService(t, svc)
	h.Eventually(t, "every ingress controller to report a failed snapshot", harness.DecisionBudget,
		func(ctx context.Context) error {
			for _, pod := range pods {
				limit := int64(256 * 1024)
				logs, err := h.K8sC().CoreV1().Pods(vutils.K8sNS).GetLogs(pod.Name, &k8scorev1.PodLogOptions{
					Container: pod.Spec.Containers[0].Name, SinceTime: &since, LimitBytes: &limit,
				}).DoRaw(ctx)
				if err != nil {
					return err
				}
				if !strings.Contains(string(logs), "Failed to perform Envoy snapshot") {
					return errors.Errorf("the ingress controller %s has not reported a failed snapshot", pod.Name)
				}
			}
			return nil
		})
	h.GetStatus(t, c, h.ServiceURL(svc), http.StatusNotFound)
	h.GetStatus(t, c, h.ServiceURL(v.svc), http.StatusOK)
	require.Nil(t, restore(t.Context()))
	restored = true
	h.WaitStatus(t, c, h.ServiceURL(svc), http.StatusUnauthorized)
	h.GetStatus(t, c, h.ServiceURL(v.svc), http.StatusOK)
	after, err := h.ComponentPods(t.Context(), "ingress")
	require.Nil(t, err)
	require.Len(t, after, len(pods))
	for _, before := range pods {
		current, err := h.K8sC().CoreV1().Pods(vutils.K8sNS).Get(t.Context(), before.Name, k8smetav1.GetOptions{})
		require.Nil(t, err)
		assert.Equal(t, before.UID, current.UID)
		for i, container := range before.Status.ContainerStatuses {
			require.Greater(t, len(current.Status.ContainerStatuses), i)
			assert.Equal(t, container.RestartCount, current.Status.ContainerStatuses[i].RestartCount)
		}
	}
}
