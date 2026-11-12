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

package rscserver

import (
	"context"
	"fmt"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/octelium/octelium/apis/cluster/csecretmanv1"
	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/apis/main/metav1"
	"github.com/octelium/octelium/apis/rsc/rmetav1"
	"github.com/octelium/octelium/cluster/common/cache"
	"github.com/octelium/octelium/cluster/common/vutils"
	"github.com/octelium/octelium/cluster/rscserver/rscserver/rerr"
	"github.com/octelium/octelium/pkg/apiutils/ucorev1"
	"github.com/octelium/octelium/pkg/apiutils/umetav1"
	"github.com/octelium/octelium/pkg/common/pbutils"
	"github.com/octelium/octelium/pkg/utils/utilrand"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"
)

type tstSecretMan struct {
	csecretmanv1.MainServiceServer
	c   *cache.Cache[string, []byte]
	lis net.Listener
}

func (s *tstSecretMan) GetSecret(ctx context.Context, req *csecretmanv1.GetSecretRequest) (*csecretmanv1.GetSecretResponse, error) {
	data, ok := s.c.Get(req.SecretRef.Uid)
	if !ok {
		return nil, rerr.NotFound("")
	}

	return &csecretmanv1.GetSecretResponse{
		Data: data,
	}, nil
}

func (s *tstSecretMan) SetSecret(ctx context.Context, req *csecretmanv1.SetSecretRequest) (*csecretmanv1.SetSecretResponse, error) {
	s.c.Set(req.SecretRef.Uid, req.Data)
	return &csecretmanv1.SetSecretResponse{}, nil
}

func (s *tstSecretMan) DeleteSecret(ctx context.Context, req *csecretmanv1.DeleteSecretRequest) (*csecretmanv1.DeleteSecretResponse, error) {
	s.c.Delete(req.SecretRef.Uid)
	return &csecretmanv1.DeleteSecretResponse{}, nil
}

func (s *tstSecretMan) ListSecret(ctx context.Context, req *csecretmanv1.ListSecretRequest) (*csecretmanv1.ListSecretResponse, error) {
	ret := &csecretmanv1.ListSecretResponse{}
	for _, ref := range req.SecretRefs {
		resp, err := s.GetSecret(ctx, &csecretmanv1.GetSecretRequest{
			SecretRef: ref,
		})
		if err != nil {
			return nil, err
		}

		ret.Items = append(ret.Items, &csecretmanv1.ListSecretResponse_Item{
			SecretRef: ref,
			Data:      resp.Data,
		})
	}

	return ret, nil
}

func newTstSecretMan(t *testing.T) *tstSecretMan {
	return &tstSecretMan{
		c: cache.New[string, []byte](nil),
	}
}

func (t *tstSecretMan) run(ctx context.Context) error {
	srv := grpc.NewServer()
	csecretmanv1.RegisterMainServiceServer(srv, t)

	lis, err := net.Listen("tcp", ":12012")
	if err != nil {
		return err
	}

	t.lis = lis

	go func() {
		zap.L().Debug("running gRPC server.")
		if err := srv.Serve(lis); err != nil {
			zap.L().Info("gRPC server closed", zap.Error(err))
		}
	}()

	return nil
}

func (t *tstSecretMan) close() {
	t.lis.Close()
}

func TestSecretMan(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	tst, err := initTest()
	assert.Nil(t, err)
	t.Cleanup(func() {
		tst.Destroy()
	})

	tstSecretManSrv := newTstSecretMan(t)
	tstSecretManSrv.run(ctx)
	defer tstSecretManSrv.close()

	time.Sleep(2 * time.Second)

	srv, err := NewServer(ctx, &Opts{})
	assert.Nil(t, err)

	grpcConn, err := grpc.NewClient(
		"127.0.0.1:12012", grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	assert.Nil(t, err, "%+v", err)
	srv.secretmanC = csecretmanv1.NewMainServiceClient(grpcConn)

	srv.hasSecretManager = true

	sec1 := &corev1.Secret{
		ApiVersion: ucorev1.APIVersion,
		Kind:       ucorev1.KindSecret,
		Metadata: &metav1.Metadata{
			Uid:  vutils.UUIDv4(),
			Name: utilrand.GetRandomStringCanonical(8),
		},
		Spec:   &corev1.Secret_Spec{},
		Status: &corev1.Secret_Status{},
		Data: &corev1.Secret_Data{
			Type: &corev1.Secret_Data_Value{
				Value: utilrand.GetRandomString(12),
			},
		},
	}

	sec11, err := srv.handleSecretManagerSet(ctx, sec1, ucorev1.API, ucorev1.Version, sec1.Kind)
	assert.Nil(t, err)

	assert.Nil(t, sec11.(*corev1.Secret).Data, nil)

	sec12, err := srv.handleSecretManagerGet(ctx, sec11, ucorev1.API, ucorev1.Version, sec1.Kind)
	assert.Nil(t, err)

	assert.True(t, pbutils.IsEqual(sec1.Data, sec12.(*corev1.Secret).Data))
	assert.True(t, pbutils.IsEqual(sec1, sec12.(*corev1.Secret)))

	sec2 := &corev1.Secret{
		ApiVersion: ucorev1.APIVersion,
		Kind:       ucorev1.KindSecret,
		Metadata: &metav1.Metadata{
			Uid:  vutils.UUIDv4(),
			Name: utilrand.GetRandomStringCanonical(8),
		},
		Spec:   &corev1.Secret_Spec{},
		Status: &corev1.Secret_Status{},
		Data: &corev1.Secret_Data{
			Type: &corev1.Secret_Data_Value{
				Value: utilrand.GetRandomString(12),
			},
		},
	}

	sec21, err := srv.handleSecretManagerSet(ctx, sec2, ucorev1.API, ucorev1.Version, sec1.Kind)
	assert.Nil(t, err)

	{
		secLst, err := srv.handleSecretManagerList(ctx, []umetav1.ResourceObjectI{
			sec11, sec21,
		}, ucorev1.API, ucorev1.Version, sec1.Kind)
		assert.Nil(t, err)

		assert.Equal(t, 2, len(secLst))
		assert.True(t, pbutils.IsEqual(sec1, secLst[0].(*corev1.Secret)))
		assert.True(t, pbutils.IsEqual(sec2, secLst[1].(*corev1.Secret)))
	}

	err = srv.handleSecretManagerDelete(ctx, sec1, ucorev1.API, ucorev1.Version, sec1.Kind)
	assert.Nil(t, err)

	{
		secLst, err := srv.handleSecretManagerList(ctx, []umetav1.ResourceObjectI{
			sec21,
		}, ucorev1.API, ucorev1.Version, sec1.Kind)
		assert.Nil(t, err)

		assert.Equal(t, 1, len(secLst))
		assert.True(t, pbutils.IsEqual(sec2, secLst[0].(*corev1.Secret)))
	}
}

func TestSecretManOps(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	tst, err := initTest()
	assert.Nil(t, err)
	t.Cleanup(func() {
		tst.Destroy()
	})

	tstSecretManSrv := newTstSecretMan(t)
	tstSecretManSrv.run(ctx)
	defer tstSecretManSrv.close()

	time.Sleep(2 * time.Second)

	srv, err := NewServer(ctx, &Opts{})
	assert.Nil(t, err)

	grpcConn, err := grpc.NewClient(
		"127.0.0.1:12012", grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	assert.Nil(t, err, "%+v", err)
	srv.secretmanC = csecretmanv1.NewMainServiceClient(grpcConn)

	srv.hasSecretManager = true

	sec1 := &corev1.Secret{
		ApiVersion: ucorev1.APIVersion,
		Kind:       ucorev1.KindSecret,
		Metadata: &metav1.Metadata{
			Uid:  vutils.UUIDv4(),
			Name: utilrand.GetRandomStringCanonical(8),
		},
		Spec:   &corev1.Secret_Spec{},
		Status: &corev1.Secret_Status{},
		Data: &corev1.Secret_Data{
			Type: &corev1.Secret_Data_Value{
				Value: utilrand.GetRandomString(12),
			},
		},
	}

	sec11, err := srv.doCreate(ctx, sec1, ucorev1.API, ucorev1.Version, sec1.Kind)
	assert.Nil(t, err)

	assert.True(t, pbutils.IsEqual(sec11.(*corev1.Secret).Data, sec1.Data))
	{
		_, ok := tstSecretManSrv.c.Get(sec11.GetMetadata().Uid)
		assert.True(t, ok)
	}

	sec12, err := srv.doGet(ctx, &rmetav1.GetOptions{
		Uid: sec11.GetMetadata().Uid,
	}, ucorev1.API, ucorev1.Version, sec1.Kind)
	assert.Nil(t, err)

	assert.True(t, pbutils.IsEqual(sec11.(*corev1.Secret), sec12))

	sec12.(*corev1.Secret).Data = &corev1.Secret_Data{
		Type: &corev1.Secret_Data_Value{
			Value: utilrand.GetRandomString(32),
		},
	}

	sec13, _, err := srv.doUpdate(ctx, sec12, ucorev1.API, ucorev1.Version, sec1.Kind)
	assert.Nil(t, err)
	assert.True(t, pbutils.IsEqual(sec13.(*corev1.Secret).Data, sec12.(*corev1.Secret).Data))

	_, err = srv.doDelete(ctx, &rmetav1.DeleteOptions{
		Uid: sec13.GetMetadata().Uid,
	}, ucorev1.API, ucorev1.Version, sec1.Kind)
	assert.Nil(t, err)
	_, ok := tstSecretManSrv.c.Get(sec13.GetMetadata().Uid)
	assert.False(t, ok)
}

type testSecretManClient struct {
	csecretmanv1.MainServiceClient
	get    func(context.Context, *csecretmanv1.GetSecretRequest) (*csecretmanv1.GetSecretResponse, error)
	set    func(context.Context, *csecretmanv1.SetSecretRequest) (*csecretmanv1.SetSecretResponse, error)
	list   func(context.Context, *csecretmanv1.ListSecretRequest) (*csecretmanv1.ListSecretResponse, error)
	delete func(context.Context, *csecretmanv1.DeleteSecretRequest) (*csecretmanv1.DeleteSecretResponse, error)
}

func (c *testSecretManClient) GetSecret(ctx context.Context, req *csecretmanv1.GetSecretRequest, _ ...grpc.CallOption) (*csecretmanv1.GetSecretResponse, error) {
	return c.get(ctx, req)
}
func (c *testSecretManClient) SetSecret(ctx context.Context, req *csecretmanv1.SetSecretRequest, _ ...grpc.CallOption) (*csecretmanv1.SetSecretResponse, error) {
	return c.set(ctx, req)
}
func (c *testSecretManClient) ListSecret(ctx context.Context, req *csecretmanv1.ListSecretRequest, _ ...grpc.CallOption) (*csecretmanv1.ListSecretResponse, error) {
	return c.list(ctx, req)
}
func (c *testSecretManClient) DeleteSecret(ctx context.Context, req *csecretmanv1.DeleteSecretRequest, _ ...grpc.CallOption) (*csecretmanv1.DeleteSecretResponse, error) {
	return c.delete(ctx, req)
}

func TestSecretManagerBypass(t *testing.T) {
	ctx := t.Context()
	srv := &Server{hasSecretManager: true}
	user := newTestUser("user")
	ret, err := srv.handleSecretManagerSet(ctx, user, "core", "v1", ucorev1.KindUser)
	require.Nil(t, err)
	assert.Same(t, user, ret)
	ret, err = srv.handleSecretManagerGet(ctx, user, "core", "v1", ucorev1.KindUser)
	require.Nil(t, err)
	assert.Same(t, user, ret)
	assert.Nil(t, srv.handleSecretManagerDelete(ctx, user, "core", "v1", ucorev1.KindUser))
	items, err := srv.handleSecretManagerList(ctx, []umetav1.ResourceObjectI{user}, "core", "v1", ucorev1.KindUser)
	require.Nil(t, err)
	assert.Same(t, user, items[0])
	items, err = srv.handleSecretManagerList(ctx, nil, "core", "v1", ucorev1.KindSecret)
	require.Nil(t, err)
	assert.Empty(t, items)
	secret := &corev1.Secret{Kind: ucorev1.KindSecret, Metadata: &metav1.Metadata{Uid: vutils.UUIDv4()}}
	ret, err = srv.handleSecretManagerSet(ctx, secret, "core", "v1", ucorev1.KindSecret)
	require.Nil(t, err)
	assert.Same(t, secret, ret)
	assert.Nil(t, srv.handleSecretManagerDelete(ctx, secret, "core", "v1", ucorev1.KindSecret))
}

func TestSecretManagerErrors(t *testing.T) {
	ctx := t.Context()
	backendErr := status.Error(codes.Unavailable, "secret backend unavailable")
	client := &testSecretManClient{
		get: func(context.Context, *csecretmanv1.GetSecretRequest) (*csecretmanv1.GetSecretResponse, error) {
			return nil, backendErr
		},
		set: func(context.Context, *csecretmanv1.SetSecretRequest) (*csecretmanv1.SetSecretResponse, error) {
			return nil, backendErr
		},
		list: func(context.Context, *csecretmanv1.ListSecretRequest) (*csecretmanv1.ListSecretResponse, error) {
			return nil, backendErr
		},
		delete: func(context.Context, *csecretmanv1.DeleteSecretRequest) (*csecretmanv1.DeleteSecretResponse, error) {
			return nil, backendErr
		},
	}
	srv := &Server{
		hasSecretManager: true,
		secretmanC:       client,
		opts:             &Opts{NewResourceObject: vutils.NewResourceObject},
	}
	secret := &corev1.Secret{
		Kind:     ucorev1.KindSecret,
		Metadata: &metav1.Metadata{Uid: vutils.UUIDv4()},
		Data:     &corev1.Secret_Data{Type: &corev1.Secret_Data_Value{Value: "private"}},
	}
	_, err := srv.handleSecretManagerSet(ctx, secret, "core", "v1", ucorev1.KindSecret)
	assert.ErrorIs(t, err, backendErr)
	_, err = srv.handleSecretManagerGet(ctx, secret, "core", "v1", ucorev1.KindSecret)
	assert.ErrorIs(t, err, backendErr)
	_, err = srv.handleSecretManagerList(ctx, []umetav1.ResourceObjectI{secret}, "core", "v1", ucorev1.KindSecret)
	assert.ErrorIs(t, err, backendErr)
	assert.ErrorIs(t, srv.handleSecretManagerDelete(ctx, secret, "core", "v1", ucorev1.KindSecret), backendErr)

	client.get = func(context.Context, *csecretmanv1.GetSecretRequest) (*csecretmanv1.GetSecretResponse, error) {
		return &csecretmanv1.GetSecretResponse{Data: []byte("invalid")}, nil
	}
	_, err = srv.handleSecretManagerGet(ctx, secret, "core", "v1", ucorev1.KindSecret)
	assert.Equal(t, codes.Internal, status.Code(err))
	client.list = func(context.Context, *csecretmanv1.ListSecretRequest) (*csecretmanv1.ListSecretResponse, error) {
		return &csecretmanv1.ListSecretResponse{
			Items: []*csecretmanv1.ListSecretResponse_Item{{SecretRef: umetav1.GetObjectReference(secret), Data: []byte("invalid")}},
		}, nil
	}
	_, err = srv.handleSecretManagerList(ctx, []umetav1.ResourceObjectI{secret}, "core", "v1", ucorev1.KindSecret)
	assert.Equal(t, codes.Internal, status.Code(err))
	client.get = func(context.Context, *csecretmanv1.GetSecretRequest) (*csecretmanv1.GetSecretResponse, error) {
		return &csecretmanv1.GetSecretResponse{Data: []byte(`{"value": 42}`)}, nil
	}
	_, err = srv.handleSecretManagerGet(ctx, secret, "core", "v1", ucorev1.KindSecret)
	assert.NotNil(t, err)
	srv.opts.NewResourceObject = func(string, string, string) (umetav1.ResourceObjectI, error) {
		return nil, fmt.Errorf("factory failed")
	}
	_, err = srv.handleSecretManagerSet(ctx, secret, "core", "v1", ucorev1.KindSecret)
	assert.Equal(t, codes.Internal, status.Code(err))
	client.get = func(context.Context, *csecretmanv1.GetSecretRequest) (*csecretmanv1.GetSecretResponse, error) {
		return &csecretmanv1.GetSecretResponse{Data: []byte(`{"value": "private"}`)}, nil
	}
	_, err = srv.handleSecretManagerGet(ctx, secret, "core", "v1", ucorev1.KindSecret)
	assert.Equal(t, codes.Internal, status.Code(err))
}

func TestSecretManagerStorageIsolation(t *testing.T) {
	srv := newTestServer(t, nil)
	backend := newTstSecretMan(t)
	srv.hasSecretManager = true
	srv.secretmanC = &testSecretManClient{
		get:    backend.GetSecret,
		set:    backend.SetSecret,
		list:   backend.ListSecret,
		delete: backend.DeleteSecret,
	}
	ctx := t.Context()
	created, err := srv.doCreate(ctx, &corev1.Secret{
		Metadata: &metav1.Metadata{Name: "secret-isolation"},
		Data:     &corev1.Secret_Data{Type: &corev1.Secret_Data_Value{Value: "private"}},
	}, "core", "v1", ucorev1.KindSecret)
	require.Nil(t, err)
	assert.Equal(t, "private", created.(*corev1.Secret).Data.GetValue())
	var data []byte
	require.Nil(t, srv.db.QueryRowContext(ctx, `SELECT resource FROM octelium_resources WHERE uid = $1`, created.GetMetadata().Uid).Scan(&data))
	stored := &corev1.Secret{}
	require.Nil(t, pbutils.UnmarshalJSON(data, stored))
	assert.Nil(t, stored.Data)
	for _, key := range []string{
		getObjectKeyByUID(created.GetMetadata().Uid),
		getObjectKeyByName("core", "v1", ucorev1.KindSecret, created.GetMetadata().Name),
	} {
		count, err := srv.redisC.Exists(ctx, key).Result()
		require.Nil(t, err)
		assert.Zero(t, count)
	}
	items, _, err := srv.doList(ctx, &rmetav1.ListOptions{}, "core", "v1", ucorev1.KindSecret)
	require.Nil(t, err)
	require.Len(t, items, 1)
	assert.True(t, pbutils.IsEqual(created, items[0]))
}

func TestSecretManagerConcurrentCreate(t *testing.T) {
	srv := newTestServer(t, nil)
	backend := newTstSecretMan(t)
	srv.hasSecretManager = true
	srv.secretmanC = &testSecretManClient{
		get: backend.GetSecret, set: backend.SetSecret,
		list: backend.ListSecret, delete: backend.DeleteSecret,
	}
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancel()
	const count = 8
	entered := make(chan struct{}, count)
	release := make(chan struct{})
	srv.opts.PreCreate = func(ctx context.Context, _ umetav1.ResourceObjectI, _, _, _ string) error {
		entered <- struct{}{}
		select {
		case <-release:
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	name := utilrand.GetRandomStringCanonical(12)
	var wg sync.WaitGroup
	var mu sync.Mutex
	var winners []umetav1.ResourceObjectI
	for i := range count {
		wg.Go(func() {
			created, err := srv.doCreate(ctx, &corev1.Secret{
				Metadata: &metav1.Metadata{Name: name},
				Data: &corev1.Secret_Data{
					Type: &corev1.Secret_Data_Value{Value: fmt.Sprintf("secret-%d", i)},
				},
			}, "core", "v1", ucorev1.KindSecret)
			mu.Lock()
			defer mu.Unlock()
			if err == nil {
				winners = append(winners, created)
			} else {
				assert.Equal(t, codes.AlreadyExists, status.Code(err))
			}
		})
	}
	for range count {
		select {
		case <-entered:
		case <-ctx.Done():
			require.FailNow(t, "Timed out waiting for Secret creates")
		}
	}
	close(release)
	wg.Wait()
	require.Len(t, winners, 1)
	assert.Equal(t, 1, backend.c.Len())
	items, _, err := srv.doList(ctx, &rmetav1.ListOptions{}, "core", "v1", ucorev1.KindSecret)
	require.Nil(t, err)
	require.Len(t, items, 1)
	assert.True(t, pbutils.IsEqual(winners[0], items[0]))
}

func newSecretMsg() proto.Message {
	return &corev1.Secret{}
}

func newSecretWatchEvent(typ string, items ...umetav1.ResourceObjectI) *rmetav1.WatchEvent {
	ret := &rmetav1.WatchEvent{
		Event: &rmetav1.WatchEvent_Event{
			ApiVersion: ucorev1.APIVersion,
			Kind:       ucorev1.KindSecret,
		},
	}

	switch typ {
	case eventTypeCreate:
		ret.Event.Type = &rmetav1.WatchEvent_Event_Create_{
			Create: &rmetav1.WatchEvent_Event_Create{Item: pbutils.MessageToAnyMust(items[0])},
		}
	case eventTypeUpdate:
		ret.Event.Type = &rmetav1.WatchEvent_Event_Update_{
			Update: &rmetav1.WatchEvent_Event_Update{
				NewItem: pbutils.MessageToAnyMust(items[0]),
				OldItem: pbutils.MessageToAnyMust(items[1]),
			},
		}
	case eventTypeDelete:
		ret.Event.Type = &rmetav1.WatchEvent_Event_Delete_{
			Delete: &rmetav1.WatchEvent_Event_Delete{Item: pbutils.MessageToAnyMust(items[0])},
		}
	}

	return ret
}

func getSecretWatchEventItems(t *testing.T, ev *rmetav1.WatchEvent) []*corev1.Secret {
	t.Helper()
	var items []*anypb.Any
	switch getEventType(ev) {
	case eventTypeCreate:
		items = append(items, ev.Event.GetCreate().Item)
	case eventTypeUpdate:
		items = append(items, ev.Event.GetUpdate().NewItem, ev.Event.GetUpdate().OldItem)
	case eventTypeDelete:
		items = append(items, ev.Event.GetDelete().Item)
	}
	var ret []*corev1.Secret
	for _, itm := range items {
		secret := &corev1.Secret{}
		require.Nil(t, itm.UnmarshalTo(secret))
		ret = append(ret, secret)
	}
	return ret
}

func TestSecretWatchData(t *testing.T) {
	for _, hasSecretManager := range []bool{false, true} {
		t.Run(fmt.Sprintf("secretManager-%t", hasSecretManager), func(t *testing.T) {
			srv := newTestServer(t, nil)
			if hasSecretManager {
				backend := newTstSecretMan(t)
				srv.hasSecretManager = true
				srv.secretmanC = &testSecretManClient{
					get: backend.GetSecret, set: backend.SetSecret,
					list: backend.ListSecret, delete: backend.DeleteSecret,
				}
			}
			ctx := t.Context()
			require.Nil(t, srv.eventHub.Start(ctx))
			streamKey := getRscStreamKey(ucorev1.API, ucorev1.Version, ucorev1.KindSecret)
			startID, err := srv.eventHub.getLastID(ctx, streamKey)
			require.Nil(t, err)
			stream := newFakeStream(ctx)
			go srv.doHandleStreamRequest(&rmetav1.WatchOptions{SkipInitial: true}, stream,
				ucorev1.API, ucorev1.Version, ucorev1.KindSecret)
			require.Eventually(t, func() bool {
				return srv.eventHub.hasSubscribers(streamKey)
			}, 10*time.Second, 50*time.Millisecond)

			chain := utilrand.GetRandomString(32)
			values := []string{utilrand.GetRandomString(32), utilrand.GetRandomString(32)}
			created, err := srv.doCreate(ctx, &corev1.Secret{
				Metadata: &metav1.Metadata{Name: utilrand.GetRandomStringCanonical(8)},
				Spec: &corev1.Secret_Spec{
					Data: &corev1.Secret_Spec_Data{Type: &corev1.Secret_Spec_Data_Value{Value: chain}},
				},
				Data: &corev1.Secret_Data{Type: &corev1.Secret_Data_Value{Value: values[0]}},
			}, ucorev1.API, ucorev1.Version, ucorev1.KindSecret)
			require.Nil(t, err)
			uid := created.GetMetadata().Uid
			assert.Equal(t, values[0], created.(*corev1.Secret).Data.GetValue())

			ev := stream.waitFor(eventTypeCreate, uid, newSecretMsg, 30*time.Second)
			require.NotNil(t, ev)
			items := getSecretWatchEventItems(t, ev)
			assert.Equal(t, values[0], items[0].Data.GetValue())
			assert.Equal(t, chain, items[0].Spec.Data.GetValue())

			created.(*corev1.Secret).Data = &corev1.Secret_Data{
				Type: &corev1.Secret_Data_Value{Value: values[1]},
			}
			updated, old, err := srv.doUpdate(ctx, created, ucorev1.API, ucorev1.Version, ucorev1.KindSecret)
			require.Nil(t, err)
			assert.Equal(t, values[1], updated.(*corev1.Secret).Data.GetValue())
			assert.Equal(t, values[0], old.(*corev1.Secret).Data.GetValue())

			ev = stream.waitFor(eventTypeUpdate, uid, newSecretMsg, 30*time.Second)
			require.NotNil(t, ev)
			items = getSecretWatchEventItems(t, ev)
			assert.Equal(t, values[1], items[0].Data.GetValue())
			assert.Equal(t, updated.GetMetadata().ResourceVersion, items[0].Metadata.ResourceVersion)
			assert.Nil(t, items[1].Data)
			assert.Equal(t, chain, items[1].Spec.Data.GetValue())
			assert.Equal(t, old.GetMetadata().ResourceVersion, items[1].Metadata.ResourceVersion)

			deleted, err := srv.doDelete(ctx, &rmetav1.DeleteOptions{Uid: uid},
				ucorev1.API, ucorev1.Version, ucorev1.KindSecret)
			require.Nil(t, err)
			assert.Equal(t, values[1], deleted.(*corev1.Secret).Data.GetValue())

			ev = stream.waitFor(eventTypeDelete, uid, newSecretMsg, 30*time.Second)
			require.NotNil(t, ev)
			items = getSecretWatchEventItems(t, ev)
			assert.Nil(t, items[0].Data)
			assert.Equal(t, chain, items[0].Spec.Data.GetValue())

			entries, err := srv.redisC.XRange(ctx, streamKey, "("+startID, "+").Result()
			require.Nil(t, err)
			var count int
			for _, entry := range entries {
				data, ok := entry.Values[rscStreamFieldData].(string)
				require.True(t, ok)
				for _, value := range values {
					assert.NotContains(t, data, value)
				}
				ev := &rmetav1.WatchEvent{}
				require.Nil(t, pbutils.Unmarshal([]byte(data), ev))
				if getEventItemUID(ev, newSecretMsg()) != uid {
					continue
				}
				count++
				for _, itm := range getSecretWatchEventItems(t, ev) {
					assert.Nil(t, itm.Data)
					assert.Equal(t, chain, itm.Spec.Data.GetValue())
				}
			}
			assert.Equal(t, 3, count)
		})
	}
}

func TestGetSecretWatchEvent(t *testing.T) {
	srv := newTestServer(t, nil)
	backend := newTstSecretMan(t)
	var getErr error
	srv.hasSecretManager = true
	srv.secretmanC = &testSecretManClient{
		get: func(ctx context.Context, req *csecretmanv1.GetSecretRequest) (*csecretmanv1.GetSecretResponse, error) {
			if getErr != nil {
				return nil, getErr
			}
			return backend.GetSecret(ctx, req)
		},
		set: backend.SetSecret, list: backend.ListSecret, delete: backend.DeleteSecret,
	}
	ctx := t.Context()
	created, err := srv.doCreate(ctx, &corev1.Secret{
		Metadata: &metav1.Metadata{Name: utilrand.GetRandomStringCanonical(8)},
		Data:     &corev1.Secret_Data{Type: &corev1.Secret_Data_Value{Value: "private"}},
	}, ucorev1.API, ucorev1.Version, ucorev1.KindSecret)
	require.Nil(t, err)
	stripped := withoutSecretData(created)
	assert.Nil(t, stripped.(*corev1.Secret).Data)
	assert.Equal(t, "private", created.(*corev1.Secret).Data.GetValue())
	assert.Same(t, stripped, withoutSecretData(stripped))
	user := newTestUser("user")
	assert.Same(t, user, withoutSecretData(user))
	missing := pbutils.Clone(stripped).(*corev1.Secret)
	missing.Metadata.Uid = vutils.UUIDv4()

	for _, typ := range []string{eventTypeCreate, eventTypeUpdate} {
		ev := newSecretWatchEvent(typ, stripped, stripped)
		ret, err := srv.getSecretWatchEvent(ctx, ev, ucorev1.API, ucorev1.Version, ucorev1.KindSecret)
		require.Nil(t, err)
		items := getSecretWatchEventItems(t, ret)
		assert.True(t, pbutils.IsEqual(created, items[0]))
		for _, itm := range items[1:] {
			assert.Nil(t, itm.Data)
		}
		for _, itm := range getSecretWatchEventItems(t, ev) {
			assert.Nil(t, itm.Data)
		}

		ret, err = srv.getSecretWatchEvent(ctx, newSecretWatchEvent(typ, missing, missing),
			ucorev1.API, ucorev1.Version, ucorev1.KindSecret)
		require.Nil(t, err)
		assert.Nil(t, ret)
	}

	ev := newSecretWatchEvent(eventTypeDelete, missing)
	ret, err := srv.getSecretWatchEvent(ctx, ev, ucorev1.API, ucorev1.Version, ucorev1.KindSecret)
	require.Nil(t, err)
	assert.Same(t, ev, ret)

	getErr = status.Error(codes.Unavailable, "unavailable")
	_, err = srv.getSecretWatchEvent(ctx, newSecretWatchEvent(eventTypeCreate, stripped),
		ucorev1.API, ucorev1.Version, ucorev1.KindSecret)
	assert.Equal(t, codes.Unavailable, status.Code(err))

	streamKey := getRscStreamKey(ucorev1.API, ucorev1.Version, ucorev1.KindSecret)
	stream := newFakeStream(ctx)
	errCh := make(chan error, 1)
	go func() {
		errCh <- srv.doHandleStreamRequest(&rmetav1.WatchOptions{SkipInitial: true}, stream,
			ucorev1.API, ucorev1.Version, ucorev1.KindSecret)
	}()
	require.Eventually(t, func() bool {
		return srv.eventHub.hasSubscribers(streamKey)
	}, 10*time.Second, 50*time.Millisecond)
	streamID := fmt.Sprintf("%d-0", time.Now().Add(time.Hour).UnixMilli())
	srv.eventHub.dispatch(streamKey, streamID, newSecretWatchEvent(eventTypeCreate, missing))
	srv.eventHub.dispatch(streamKey, streamID, newSecretWatchEvent(eventTypeCreate, stripped))
	select {
	case err := <-errCh:
		assert.Equal(t, codes.Unavailable, status.Code(err))
	case <-time.After(10 * time.Second):
		require.FailNow(t, "Timed out waiting for the Watch to fail")
	}
	assert.Empty(t, stream.getMsgs())
}
