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
	"testing"
	"time"

	"github.com/octelium/octelium/apis/cluster/csecretmanv1"
	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/apis/main/metav1"
	"github.com/octelium/octelium/apis/rsc/rmetav1"
	"github.com/octelium/octelium/cluster/common/vutils"
	"github.com/octelium/octelium/cluster/rscserver/rscserver/rerr"
	"github.com/octelium/octelium/pkg/apiutils/ucorev1"
	"github.com/octelium/octelium/pkg/apiutils/umetav1"
	"github.com/octelium/octelium/pkg/common/pbutils"
	"github.com/octelium/octelium/pkg/utils/utilrand"
	"github.com/patrickmn/go-cache"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
)

type tstSecretMan struct {
	csecretmanv1.MainServiceServer
	c   *cache.Cache
	lis net.Listener
}

func (s *tstSecretMan) GetSecret(ctx context.Context, req *csecretmanv1.GetSecretRequest) (*csecretmanv1.GetSecretResponse, error) {
	data, ok := s.c.Get(req.SecretRef.Uid)
	if !ok {
		return nil, rerr.NotFound("")
	}

	return &csecretmanv1.GetSecretResponse{
		Data: data.([]byte),
	}, nil
}

func (s *tstSecretMan) SetSecret(ctx context.Context, req *csecretmanv1.SetSecretRequest) (*csecretmanv1.SetSecretResponse, error) {
	s.c.Set(req.SecretRef.Uid, req.Data, cache.NoExpiration)
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
		c: cache.New(cache.NoExpiration, 3*time.Minute),
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
