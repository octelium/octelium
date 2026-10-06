package octelium

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

func TestLateUnaryRejectionKeepsNewGeneration(t *testing.T) {
	var calls atomic.Int32
	client := newTestClient(t, WithAccessTokenProvider(AccessTokenProviderFunc(func(ctx context.Context) (AccessToken, error) {
		calls.Add(1)
		return AccessToken{Value: "same-token"}, nil
	})))
	started := make(chan struct{})
	release := make(chan struct{})
	result := make(chan error, 1)
	go func() {
		result <- client.AuthUnaryClientInterceptor()(context.Background(), "test", nil, nil, nil, func(ctx context.Context, method string, req, reply any, conn *grpc.ClientConn, opts ...grpc.CallOption) error {
			md, _ := metadata.FromOutgoingContext(ctx)
			if values := md.Get(metadataKeyAuth); len(values) != 1 || values[0] != "same-token" {
				return errors.New("missing access metadata")
			}
			close(started)
			<-release
			return status.Error(codes.Unauthenticated, "old generation rejected")
		})
	}()
	awaitTest(t, started)
	client.InvalidateAccessToken()
	if _, err := client.AccessToken(context.Background()); err != nil {
		t.Fatal(err)
	}
	close(release)
	if err := awaitTest(t, result); status.Code(err) != codes.Unauthenticated {
		t.Fatalf("unexpected RPC result: %v", err)
	}
	if _, err := client.AccessToken(context.Background()); err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 2 {
		t.Fatalf("old rejection invalidated new generation: %d calls", calls.Load())
	}
}

type testClientStream struct {
	grpc.ClientStream
	err error
}

func (s *testClientStream) Header() (metadata.MD, error) { return nil, s.err }
func (s *testClientStream) SendMsg(msg any) error        { return s.err }
func (s *testClientStream) RecvMsg(msg any) error        { return s.err }
func (s *testClientStream) CloseSend() error             { return s.err }

func TestStreamAuthenticationRejectionInvalidatesGeneration(t *testing.T) {
	tests := []struct {
		name string
		call func(grpc.ClientStream) error
	}{
		{name: "header", call: func(s grpc.ClientStream) error { _, err := s.Header(); return err }},
		{name: "send", call: func(s grpc.ClientStream) error { return s.SendMsg(nil) }},
		{name: "receive", call: func(s grpc.ClientStream) error { return s.RecvMsg(nil) }},
		{name: "close", call: func(s grpc.ClientStream) error { return s.CloseSend() }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var calls atomic.Int32
			client := newTestClient(t, WithAccessTokenProvider(AccessTokenProviderFunc(func(ctx context.Context) (AccessToken, error) {
				calls.Add(1)
				return AccessToken{Value: "access"}, nil
			})))
			stream, err := client.AuthStreamClientInterceptor()(context.Background(), nil, nil, "test", func(ctx context.Context, desc *grpc.StreamDesc, conn *grpc.ClientConn, method string, opts ...grpc.CallOption) (grpc.ClientStream, error) {
				return &testClientStream{err: status.Error(codes.Unauthenticated, "rejected")}, nil
			})
			if err != nil {
				t.Fatal(err)
			}
			if err := tt.call(stream); status.Code(err) != codes.Unauthenticated {
				t.Fatalf("unexpected stream result: %v", err)
			}
			if _, err := client.AccessToken(context.Background()); err != nil {
				t.Fatal(err)
			}
			if calls.Load() != 2 {
				t.Fatalf("stream rejection did not invalidate token: %d calls", calls.Load())
			}
			if err := tt.call(stream); status.Code(err) != codes.Unauthenticated {
				t.Fatal(err)
			}
			if _, err := client.AccessToken(context.Background()); err != nil {
				t.Fatal(err)
			}
			if calls.Load() != 2 {
				t.Fatalf("late stream rejection invalidated new token: %d calls", calls.Load())
			}
		})
	}
}
