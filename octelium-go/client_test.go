package octelium

import (
	"context"
	"errors"
	"fmt"
	"math"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/octelium/octelium/apis/main/authv1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
)

type testAuthServer struct {
	authv1.UnimplementedMainServiceServer
	authenticate func(context.Context, *authv1.AuthenticateWithAuthenticationTokenRequest) (*authv1.SessionToken, error)
	refresh      func(context.Context) (*authv1.SessionToken, error)
	logout       func(context.Context) error
}

func (s *testAuthServer) AuthenticateWithAuthenticationToken(ctx context.Context, req *authv1.AuthenticateWithAuthenticationTokenRequest) (*authv1.SessionToken, error) {
	return s.authenticate(ctx, req)
}

func (s *testAuthServer) AuthenticateWithRefreshToken(ctx context.Context, req *authv1.AuthenticateWithRefreshTokenRequest) (*authv1.SessionToken, error) {
	return s.refresh(ctx)
}

func (s *testAuthServer) Logout(ctx context.Context, req *authv1.LogoutRequest) (*authv1.LogoutResponse, error) {
	return &authv1.LogoutResponse{}, s.logout(ctx)
}

func testSession(access, refresh string) *authv1.SessionToken {
	return &authv1.SessionToken{AccessToken: access, RefreshToken: refresh, ExpiresIn: 1800, RefreshTokenExpiresIn: 3600}
}

func newTestClient(t *testing.T, opts ...Option) *Client {
	t.Helper()
	opts = append([]Option{WithDomain("example.com"), WithoutEnvironmentCredentials()}, opts...)
	client, err := New(context.Background(), opts...)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := client.Close(); err != nil {
			t.Error(err)
		}
	})
	return client
}

func newTestManagedClient(t *testing.T, service *testAuthServer) *Client {
	t.Helper()
	listener := bufconn.Listen(1024 * 1024)
	server := grpc.NewServer()
	authv1.RegisterMainServiceServer(server, service)
	go func() { _ = server.Serve(listener) }()
	t.Cleanup(func() {
		server.Stop()
		_ = listener.Close()
	})
	return newTestClient(t,
		WithAuthenticator(AuthenticationToken("credential")),
		WithAPIEndpoint("passthrough:///bufnet"),
		WithGRPCTransportCredentials(insecure.NewCredentials()),
		WithGRPCDialOptions(grpc.WithContextDialer(func(ctx context.Context, target string) (net.Conn, error) {
			return listener.DialContext(ctx)
		})),
	)
}

func awaitTest[T any](t *testing.T, ch <-chan T) T {
	t.Helper()
	select {
	case result := <-ch:
		return result
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for operation")
		var zero T
		return zero
	}
}

func TestTokenCallerCancellationPreservesRotatingSession(t *testing.T) {
	started := make(chan struct{})
	release := make(chan struct{})
	var calls atomic.Int32
	service := &testAuthServer{
		authenticate: func(ctx context.Context, req *authv1.AuthenticateWithAuthenticationTokenRequest) (*authv1.SessionToken, error) {
			if req.AuthenticationToken != "credential" {
				return nil, status.Error(codes.Unauthenticated, "missing credential")
			}
			return testSession("access-1", "refresh-1"), nil
		},
		refresh: func(ctx context.Context) (*authv1.SessionToken, error) {
			md, _ := metadata.FromIncomingContext(ctx)
			if values := md.Get(metadataKeyRefreshToken); len(values) != 1 || values[0] != "refresh-1" {
				return nil, status.Error(codes.Unauthenticated, "missing refresh token")
			}
			calls.Add(1)
			close(started)
			select {
			case <-release:
				return testSession("access-2", "refresh-2"), nil
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		},
	}
	client := newTestManagedClient(t, service)
	if _, err := client.AccessToken(context.Background()); err != nil {
		t.Fatal(err)
	}
	client.InvalidateAccessToken()
	ctx, cancel := context.WithCancel(context.Background())
	first := make(chan error, 1)
	go func() {
		_, err := client.AccessToken(ctx)
		first <- err
	}()
	awaitTest(t, started)
	cancel()
	if err := awaitTest(t, first); !errors.Is(err, context.Canceled) {
		t.Fatalf("expected canceled caller, got %v", err)
	}
	second := make(chan error, 1)
	go func() {
		token, err := client.AccessToken(context.Background())
		if err == nil && token != "access-2" {
			err = fmt.Errorf("unexpected token %q", token)
		}
		second <- err
	}()
	close(release)
	if err := awaitTest(t, second); err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 1 {
		t.Fatalf("expected one refresh, got %d", calls.Load())
	}
	if token, ok := client.tokens.refreshToken(); !ok || token != "refresh-2" {
		t.Fatalf("rotated refresh token was lost: %q", token)
	}
}

func TestTokenCanceledWaiterReturnsPromptly(t *testing.T) {
	started := make(chan struct{})
	release := make(chan struct{})
	client := newTestClient(t, WithAccessTokenProvider(AccessTokenProviderFunc(func(ctx context.Context) (AccessToken, error) {
		close(started)
		select {
		case <-release:
			return AccessToken{Value: "access"}, nil
		case <-ctx.Done():
			return AccessToken{}, ctx.Err()
		}
	})))
	first := make(chan error, 1)
	go func() {
		_, err := client.AccessToken(context.Background())
		first <- err
	}()
	awaitTest(t, started)
	ctx, cancel := context.WithCancel(context.Background())
	second := make(chan error, 1)
	go func() {
		_, err := client.AccessToken(ctx)
		second <- err
	}()
	cancel()
	if err := awaitTest(t, second); !errors.Is(err, context.Canceled) {
		t.Fatalf("expected cancellation, got %v", err)
	}
	close(release)
	if err := awaitTest(t, first); err != nil {
		t.Fatal(err)
	}
	if _, err := client.AccessToken(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("cached token ignored cancellation: %v", err)
	}
}

func TestTokenConcurrentFailuresAreShared(t *testing.T) {
	failure := errors.New("provider unavailable")
	var calls atomic.Int32
	client := newTestClient(t, WithAccessTokenProvider(AccessTokenProviderFunc(func(ctx context.Context) (AccessToken, error) {
		calls.Add(1)
		return AccessToken{}, failure
	})))
	start := make(chan struct{})
	results := make(chan error, 100)
	var ready sync.WaitGroup
	ready.Add(100)
	for range 100 {
		go func() {
			ready.Done()
			<-start
			_, err := client.AccessToken(context.Background())
			results <- err
		}()
	}
	ready.Wait()
	close(start)
	for range 100 {
		if err := awaitTest(t, results); !errors.Is(err, failure) {
			t.Fatalf("expected shared provider error, got %v", err)
		}
	}
	if calls.Load() != 1 {
		t.Fatalf("expected one exchange, got %d", calls.Load())
	}
}

func TestTokenRefreshFailureBackoffNeverUsesExpiredToken(t *testing.T) {
	failure := errors.New("provider unavailable")
	var calls atomic.Int32
	client := newTestClient(t, WithAccessTokenProvider(AccessTokenProviderFunc(func(ctx context.Context) (AccessToken, error) {
		calls.Add(1)
		return AccessToken{}, failure
	})))
	now := time.Now()
	client.tokens.setExternal(AccessToken{Value: "still-valid", Expiry: now.Add(time.Minute)}, now, defaultRefreshBefore)
	client.tokens.mu.Lock()
	client.tokens.token.refreshAt = now.Add(-time.Second)
	client.tokens.mu.Unlock()
	for range 5 {
		if token, err := client.AccessToken(context.Background()); err != nil || token != "still-valid" {
			t.Fatalf("expected valid fallback, got %q, %v", token, err)
		}
	}
	client.tokens.mu.Lock()
	client.tokens.token.expiresAt = now.Add(-time.Second)
	client.tokens.mu.Unlock()
	if _, err := client.AccessToken(context.Background()); !errors.Is(err, failure) {
		t.Fatalf("expected provider failure after expiry, got %v", err)
	}
	if calls.Load() != 1 {
		t.Fatalf("expected refresh backoff, got %d calls", calls.Load())
	}
}

func TestAuthenticationTokenIsNotReplayedAfterFailure(t *testing.T) {
	var calls atomic.Int32
	client := newTestClient(t, WithAuthenticator(AuthenticatorFunc(func(ctx context.Context, service authv1.MainServiceClient, scopes []string) (*authv1.SessionToken, error) {
		calls.Add(1)
		return nil, errors.New("response lost")
	})))
	if _, err := client.AccessToken(context.Background()); err == nil {
		t.Fatal("expected authentication failure")
	}
	client.ForgetSession()
	if _, err := client.AccessToken(context.Background()); !errors.Is(err, ErrSessionExpired) {
		t.Fatalf("expected terminal one-time session error, got %v", err)
	}
	if calls.Load() != 1 {
		t.Fatalf("one-time authenticator was replayed %d times", calls.Load())
	}
}

func TestCloseDuringTokenAcquisition(t *testing.T) {
	started := make(chan struct{})
	stopped := make(chan struct{})
	client := newTestClient(t, WithAccessTokenProvider(AccessTokenProviderFunc(func(ctx context.Context) (AccessToken, error) {
		close(started)
		<-ctx.Done()
		close(stopped)
		return AccessToken{}, ctx.Err()
	})))
	result := make(chan error, 1)
	go func() {
		_, err := client.AccessToken(context.Background())
		result <- err
	}()
	awaitTest(t, started)
	if err := client.Close(); err != nil {
		t.Fatal(err)
	}
	awaitTest(t, stopped)
	if err := awaitTest(t, result); !errors.Is(err, ErrClientClosed) {
		t.Fatalf("expected closed client, got %v", err)
	}
	if client.tokens.snapshot().accessToken != "" {
		t.Fatal("closed client retained its access token")
	}
}

func TestLateTokenPublicationAfterCloseOrForget(t *testing.T) {
	for _, closeClient := range []bool{false, true} {
		t.Run(fmt.Sprint(closeClient), func(t *testing.T) {
			started := make(chan struct{})
			release := make(chan struct{})
			client := newTestClient(t, WithAccessTokenProvider(AccessTokenProviderFunc(func(ctx context.Context) (AccessToken, error) {
				close(started)
				<-release
				return AccessToken{Value: "late-token"}, nil
			})))
			result := make(chan error, 1)
			go func() {
				_, err := client.AccessToken(context.Background())
				result <- err
			}()
			awaitTest(t, started)
			client.operationMu.Lock()
			op := client.operation
			client.operationMu.Unlock()
			if closeClient {
				if err := client.Close(); err != nil {
					t.Fatal(err)
				}
			} else {
				client.ForgetSession()
			}
			close(release)
			awaitTest(t, op.done)
			if err := awaitTest(t, result); err == nil {
				t.Fatal("expected canceled token acquisition")
			}
			if client.tokens.snapshot().accessToken != "" {
				t.Fatal("in-flight acquisition resurrected a cleared token")
			}
		})
	}
}

func TestProviderCanCloseClient(t *testing.T) {
	var client *Client
	client = newTestClient(t, WithAccessTokenProvider(AccessTokenProviderFunc(func(ctx context.Context) (AccessToken, error) {
		return AccessToken{Value: "access"}, client.Close()
	})))
	result := make(chan error, 1)
	go func() {
		_, err := client.AccessToken(context.Background())
		result <- err
	}()
	if err := awaitTest(t, result); !errors.Is(err, ErrClientClosed) {
		t.Fatalf("expected closed client, got %v", err)
	}
}

func TestTokenAuthenticationTimeout(t *testing.T) {
	client := newTestClient(t, WithAuthenticationTimeout(20*time.Millisecond), WithAccessTokenProvider(AccessTokenProviderFunc(func(ctx context.Context) (AccessToken, error) {
		<-ctx.Done()
		return AccessToken{}, ctx.Err()
	})))
	if _, err := client.AccessToken(context.Background()); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("expected authentication deadline, got %v", err)
	}
}

func TestLogoutUsesRefreshToken(t *testing.T) {
	service := &testAuthServer{
		authenticate: func(ctx context.Context, req *authv1.AuthenticateWithAuthenticationTokenRequest) (*authv1.SessionToken, error) {
			return testSession("access", "refresh"), nil
		},
		logout: func(ctx context.Context) error {
			md, _ := metadata.FromIncomingContext(ctx)
			if values := md.Get(metadataKeyRefreshToken); len(values) != 1 || values[0] != "refresh" {
				return status.Error(codes.Unauthenticated, "wrong refresh metadata")
			}
			if values := md.Get(metadataKeyAuth); len(values) != 0 {
				return status.Error(codes.InvalidArgument, "unexpected access metadata")
			}
			return nil
		},
	}
	client := newTestManagedClient(t, service)
	if _, err := client.AccessToken(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := client.Logout(context.Background()); err != nil {
		t.Fatal(err)
	}
	if client.tokens.snapshot().accessToken != "" {
		t.Fatal("logout retained the session")
	}
}

func TestLogoutWaitHonorsDeadline(t *testing.T) {
	started := make(chan struct{})
	release := make(chan struct{})
	client := newTestClient(t, WithAuthenticator(AuthenticatorFunc(func(ctx context.Context, service authv1.MainServiceClient, scopes []string) (*authv1.SessionToken, error) {
		close(started)
		select {
		case <-release:
			return testSession("access", "refresh"), nil
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	})))
	result := make(chan error, 1)
	go func() {
		_, err := client.AccessToken(context.Background())
		result <- err
	}()
	awaitTest(t, started)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if err := client.Logout(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("expected logout deadline, got %v", err)
	}
	close(release)
	if err := awaitTest(t, result); err != nil {
		t.Fatal(err)
	}
}

func TestMalformedSessionTokensAreRejected(t *testing.T) {
	tests := []struct {
		name   string
		change func(*authv1.SessionToken)
	}{
		{name: "empty access", change: func(s *authv1.SessionToken) { s.AccessToken = " " }},
		{name: "empty refresh", change: func(s *authv1.SessionToken) { s.RefreshToken = " " }},
		{name: "zero access lifetime", change: func(s *authv1.SessionToken) { s.ExpiresIn = 0 }},
		{name: "negative access lifetime", change: func(s *authv1.SessionToken) { s.ExpiresIn = -1 }},
		{name: "overflow access lifetime", change: func(s *authv1.SessionToken) { s.ExpiresIn = math.MaxInt64 }},
		{name: "zero refresh lifetime", change: func(s *authv1.SessionToken) { s.RefreshTokenExpiresIn = 0 }},
		{name: "negative refresh lifetime", change: func(s *authv1.SessionToken) { s.RefreshTokenExpiresIn = -1 }},
		{name: "overflow refresh lifetime", change: func(s *authv1.SessionToken) { s.RefreshTokenExpiresIn = math.MaxInt64 }},
		{name: "shorter refresh lifetime", change: func(s *authv1.SessionToken) { s.RefreshTokenExpiresIn = 1 }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			session := testSession("access", "refresh")
			tt.change(session)
			client := newTestClient(t, WithAuthenticator(AuthenticatorFunc(func(ctx context.Context, service authv1.MainServiceClient, scopes []string) (*authv1.SessionToken, error) {
				return session, nil
			})))
			if _, err := client.AccessToken(context.Background()); err == nil {
				t.Fatal("malformed session was accepted")
			}
			if client.tokens.snapshot().accessToken != "" {
				t.Fatal("malformed session was published")
			}
		})
	}
}

func TestExpiredRefreshTokenIsNotUsed(t *testing.T) {
	client := newTestClient(t, WithAuthenticator(AuthenticationToken("credential")))
	client.tokens.setSession(testSession("access", "refresh"), time.Now().Add(-2*time.Hour), defaultRefreshBefore)
	if _, err := client.AccessToken(context.Background()); !errors.Is(err, ErrSessionExpired) {
		t.Fatalf("expected expired session without another exchange, got %v", err)
	}
}

func TestNormalizeDomain(t *testing.T) {
	client := newTestClient(t, WithDomain(" Example.COM. "), WithAccessToken("access"))
	if client.Domain() != "example.com" {
		t.Fatalf("expected example.com, got %q", client.Domain())
	}
}

func TestTokenTimeoutUsesValidFallbackWithBackoff(t *testing.T) {
	var calls atomic.Int32
	client := newTestClient(t, WithAuthenticationTimeout(20*time.Millisecond), WithAccessTokenProvider(AccessTokenProviderFunc(func(ctx context.Context) (AccessToken, error) {
		calls.Add(1)
		<-ctx.Done()
		return AccessToken{}, ctx.Err()
	})))
	now := time.Now()
	client.tokens.setExternal(AccessToken{Value: "still-valid", Expiry: now.Add(time.Minute)}, now, defaultRefreshBefore)
	client.tokens.mu.Lock()
	client.tokens.token.refreshAt = now.Add(-time.Second)
	client.tokens.mu.Unlock()
	for range 3 {
		if token, err := client.AccessToken(context.Background()); err != nil || token != "still-valid" {
			t.Fatalf("expected valid fallback after timeout, got %q, %v", token, err)
		}
	}
	if calls.Load() != 1 {
		t.Fatalf("expected backoff after timeout, got %d calls", calls.Load())
	}
}

func TestMalformedRefreshDoesNotReplaceSession(t *testing.T) {
	service := &testAuthServer{
		authenticate: func(ctx context.Context, req *authv1.AuthenticateWithAuthenticationTokenRequest) (*authv1.SessionToken, error) {
			return testSession("access-1", "refresh-1"), nil
		},
		refresh: func(ctx context.Context) (*authv1.SessionToken, error) {
			return testSession("access-2", ""), nil
		},
	}
	client := newTestManagedClient(t, service)
	if _, err := client.AccessToken(context.Background()); err != nil {
		t.Fatal(err)
	}
	client.InvalidateAccessToken()
	if _, err := client.AccessToken(context.Background()); err == nil {
		t.Fatal("missing rotating refresh token was accepted")
	}
	if snapshot := client.tokens.snapshot(); snapshot.accessToken == "access-2" {
		t.Fatal("malformed refresh response was published")
	}
}
