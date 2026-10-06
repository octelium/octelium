package octelium

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

type testRoundTripper func(*http.Request) (*http.Response, error)

func (f testRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) { return f(req) }

type testRequestBody struct{ closed atomic.Int32 }

func (b *testRequestBody) Read(p []byte) (int, error) { return 0, io.EOF }
func (b *testRequestBody) Close() error               { b.closed.Add(1); return nil }

func TestHTTPFailuresCloseRequestBody(t *testing.T) {
	tests := []struct {
		name    string
		prepare func(*Client, *http.Request) http.RoundTripper
	}{
		{name: "unauthorized", prepare: func(c *Client, r *http.Request) http.RoundTripper {
			r.URL.Host = "attacker.test"
			return c.HTTPTransport()
		}},
		{name: "invalid request", prepare: func(c *Client, r *http.Request) http.RoundTripper { r.URL = nil; return c.HTTPTransport() }},
		{name: "invalid transport", prepare: func(c *Client, r *http.Request) http.RoundTripper { return (*authRoundTripper)(nil) }},
		{name: "canceled", prepare: func(c *Client, r *http.Request) http.RoundTripper {
			ctx, cancel := context.WithCancel(r.Context())
			cancel()
			*r = *r.WithContext(ctx)
			return c.HTTPTransport()
		}},
		{name: "closed", prepare: func(c *Client, r *http.Request) http.RoundTripper { _ = c.Close(); return c.HTTPTransport() }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := newTestClient(t, WithAccessToken("access"))
			req, err := http.NewRequest(http.MethodPost, "https://svc.example.com", nil)
			if err != nil {
				t.Fatal(err)
			}
			body := &testRequestBody{}
			req.Body = body
			transport := tt.prepare(client, req)
			if _, err := transport.RoundTrip(req); err == nil {
				t.Fatal("expected request failure")
			}
			if body.closed.Load() != 1 {
				t.Fatalf("request body closed %d times", body.closed.Load())
			}
		})
	}
}

func TestHTTPTransportUsesAuthoritativeHeaderAndPreservesRequest(t *testing.T) {
	var captured *http.Request
	client := newTestClient(t, WithAccessToken("access"), WithHTTPTransport(testRoundTripper(func(req *http.Request) (*http.Response, error) {
		captured = req
		_ = req.Body.Close()
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader("response"))}, nil
	})))
	req, err := http.NewRequest(http.MethodPost, "https://svc.example.com", nil)
	if err != nil {
		t.Fatal(err)
	}
	body := &testRequestBody{}
	req.Body = body
	req.Header[metadataKeyAuth] = []string{"stale"}
	req.Header.Set("Authorization", "Bearer other")
	resp, err := client.HTTPTransport().RoundTrip(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if token := captured.Header.Get(metadataKeyAuth); token != "access" {
		t.Fatalf("unexpected access header %q", token)
	}
	for key, values := range captured.Header {
		if strings.EqualFold(key, metadataKeyAuth) && (len(values) != 1 || values[0] != "access") {
			t.Fatalf("conflicting access header: %v", values)
		}
	}
	if req.Header[metadataKeyAuth][0] != "stale" || req.Header.Get("Authorization") != "Bearer other" {
		t.Fatal("caller request was modified")
	}
	if body.closed.Load() != 1 {
		t.Fatalf("delegated body closed %d times", body.closed.Load())
	}
	if _, err := io.ReadAll(resp.Body); err != nil {
		t.Fatal(err)
	}
	if !errors.Is(captured.Context().Err(), context.Canceled) {
		t.Fatal("response completion did not release request context")
	}
}

func TestHTTPUnauthorizedInvalidatesOnlyRequestGeneration(t *testing.T) {
	var calls atomic.Int32
	started := make(chan struct{})
	release := make(chan struct{})
	client := newTestClient(t, WithAccessTokenProvider(AccessTokenProviderFunc(func(ctx context.Context) (AccessToken, error) {
		calls.Add(1)
		return AccessToken{Value: "same-token"}, nil
	})), WithHTTPTransport(testRoundTripper(func(req *http.Request) (*http.Response, error) {
		close(started)
		<-release
		return &http.Response{StatusCode: http.StatusUnauthorized, Header: http.Header{"X-Octelium-Unauthorized": []string{"true"}}, Body: http.NoBody}, nil
	})))
	result := make(chan error, 1)
	go func() {
		req, _ := http.NewRequest(http.MethodGet, "https://svc.example.com", nil)
		resp, err := client.HTTPTransport().RoundTrip(req)
		if resp != nil {
			_ = resp.Body.Close()
		}
		result <- err
	}()
	awaitTest(t, started)
	client.InvalidateAccessToken()
	if _, err := client.AccessToken(context.Background()); err != nil {
		t.Fatal(err)
	}
	close(release)
	if err := awaitTest(t, result); err != nil {
		t.Fatal(err)
	}
	if _, err := client.AccessToken(context.Background()); err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 2 {
		t.Fatalf("late HTTP rejection invalidated new token: %d calls", calls.Load())
	}
	client.httpTransport = testRoundTripper(func(req *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusUnauthorized, Header: http.Header{"X-Octelium-Unauthorized": []string{"true"}}, Body: http.NoBody}, nil
	})
	req, _ := http.NewRequest(http.MethodGet, "https://svc.example.com", nil)
	resp, err := client.HTTPTransport().RoundTrip(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if _, err := client.AccessToken(context.Background()); err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 3 {
		t.Fatalf("current HTTP rejection did not invalidate token: %d calls", calls.Load())
	}
}

func TestCloseCancelsActiveHTTPRequest(t *testing.T) {
	started := make(chan struct{})
	stopped := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(started)
		<-r.Context().Done()
		close(stopped)
	}))
	defer server.Close()
	client := newTestClient(t, WithAccessToken("access"), WithAllowInsecureHTTP(), WithAuthorizedHTTPHosts("127.0.0.1"))
	result := make(chan error, 1)
	go func() {
		resp, err := client.HTTPClient().Get(server.URL)
		if resp != nil {
			_ = resp.Body.Close()
		}
		result <- err
	}()
	awaitTest(t, started)
	if err := client.Close(); err != nil {
		t.Fatal(err)
	}
	if err := awaitTest(t, result); !errors.Is(err, context.Canceled) {
		t.Fatalf("expected HTTP cancellation, got %v", err)
	}
	awaitTest(t, stopped)
}

type testClosingTransport struct {
	started chan struct{}
	release chan struct{}
	err     error
}

func (r *testClosingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	return nil, errors.New("unused transport")
}
func (r *testClosingTransport) Close() error { close(r.started); <-r.release; return r.err }

func TestConcurrentCloseWaitsForCleanupAndSharesError(t *testing.T) {
	failure := errors.New("cleanup failed")
	transport := &testClosingTransport{started: make(chan struct{}), release: make(chan struct{}), err: failure}
	client, err := New(context.Background(), WithDomain("example.com"), WithAccessToken("access"), WithHTTPTransport(transport))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })
	client.cfg.ownsHTTPTransport = true
	first := make(chan error, 1)
	go func() { first <- client.Close() }()
	awaitTest(t, transport.started)
	second := make(chan error, 1)
	go func() { second <- client.Close() }()
	select {
	case err := <-second:
		t.Fatalf("concurrent Close returned before cleanup: %v", err)
	case <-time.After(20 * time.Millisecond):
	}
	close(transport.release)
	if err := awaitTest(t, first); !errors.Is(err, failure) {
		t.Fatalf("unexpected cleanup error %v", err)
	}
	if err := awaitTest(t, second); !errors.Is(err, failure) {
		t.Fatalf("concurrent Close lost cleanup error %v", err)
	}
	if err := client.Close(); !errors.Is(err, failure) {
		t.Fatalf("repeated Close lost cleanup error %v", err)
	}
}

func TestClosePreservesCallerOwnedTransport(t *testing.T) {
	transport := &testClosingTransport{started: make(chan struct{}), release: make(chan struct{})}
	client := newTestClient(t, WithAccessToken("access"), WithHTTPTransport(transport))
	if err := client.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-transport.started:
		t.Fatal("caller-owned transport was closed")
	default:
	}
}

func TestHTTPAuthorizationErrorPreservesCause(t *testing.T) {
	cause := errors.New("policy failed")
	client := newTestClient(t, WithAccessToken("access"), WithHTTPAuthorizationPolicy(func(req *http.Request) error { return cause }))
	req, _ := http.NewRequest(http.MethodGet, "https://svc.example.com", nil)
	_, err := client.HTTPTransport().RoundTrip(req)
	var authorizationError *HTTPAuthorizationError
	if !errors.Is(err, ErrHTTPDestinationNotAuthorized) || !errors.Is(err, cause) || !errors.As(err, &authorizationError) {
		t.Fatalf("error chain did not preserve sentinel, cause and type: %v", err)
	}
}

func TestHTTPApplicationUnauthorizedDoesNotInvalidateToken(t *testing.T) {
	var calls atomic.Int32
	client := newTestClient(t, WithAccessTokenProvider(AccessTokenProviderFunc(func(ctx context.Context) (AccessToken, error) {
		calls.Add(1)
		return AccessToken{Value: "access"}, nil
	})), WithHTTPTransport(testRoundTripper(func(req *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusUnauthorized, Body: http.NoBody}, nil
	})))
	for range 2 {
		req, _ := http.NewRequest(http.MethodGet, "https://svc.example.com", nil)
		resp, err := client.HTTPTransport().RoundTrip(req)
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
	}
	if calls.Load() != 1 {
		t.Fatalf("application 401 invalidated Cluster credential: %d calls", calls.Load())
	}
}

type testReadWriteBody struct {
	strings.Reader
	written strings.Builder
}

func (b *testReadWriteBody) Write(p []byte) (int, error) { return b.written.Write(p) }
func (b *testReadWriteBody) Close() error                { return nil }

func TestHTTPUpgradePreservesWritableBody(t *testing.T) {
	body := &testReadWriteBody{}
	client := newTestClient(t, WithAccessToken("access"), WithHTTPTransport(testRoundTripper(func(req *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusSwitchingProtocols, Body: body}, nil
	})))
	req, _ := http.NewRequest(http.MethodGet, "https://svc.example.com", nil)
	req.Header = nil
	resp, err := client.HTTPTransport().RoundTrip(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	writer, ok := resp.Body.(io.Writer)
	if !ok {
		t.Fatal("upgraded response body lost its Writer interface")
	}
	if _, err := writer.Write([]byte("message")); err != nil {
		t.Fatal(err)
	}
	if body.written.String() != "message" {
		t.Fatal("upgraded body write was not forwarded")
	}
	if req.Header != nil {
		t.Fatal("nil caller headers were modified")
	}
}
