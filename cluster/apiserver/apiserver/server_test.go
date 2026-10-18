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

package apiserver

import (
	"context"
	"net"
	"testing"

	"github.com/octelium/octelium/apis/cluster/cclusterv1"
	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/apis/main/userv1"
	"github.com/octelium/octelium/apis/rsc/rmetav1"
	"github.com/octelium/octelium/cluster/apiserver/apiserver/admin"
	"github.com/octelium/octelium/cluster/apiserver/apiserver/user"
	"github.com/octelium/octelium/cluster/common/tests"
	"github.com/octelium/octelium/cluster/common/tests/tstuser"
	"github.com/octelium/octelium/cluster/common/userctx"
	"github.com/octelium/octelium/pkg/common/pbutils"
	"github.com/stretchr/testify/assert"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/test/bufconn"
)

type userCtxStream struct {
	grpc.ServerStream
	ctx context.Context
}

func (s *userCtxStream) Context() context.Context {
	return s.ctx
}

func TestStopDisconnectsConnections(t *testing.T) {
	ctx := context.Background()

	tst, err := tests.Initialize(nil)
	assert.Nil(t, err)
	t.Cleanup(func() {
		tst.Destroy()
	})

	usrSrv := user.NewServer(tst.C.OcteliumC)
	adminSrv := admin.NewServer(&admin.Opts{
		OcteliumC:  tst.C.OcteliumC,
		IsEmbedded: true,
	})

	getActiveIndexes := func() []uint32 {
		cfg, err := tst.C.OcteliumC.CoreC().GetConfig(ctx, &rmetav1.GetOptions{Name: "sys:conn-info"})
		assert.Nil(t, err, "%+v", err)

		ret := &cclusterv1.ClusterConnInfo{}
		err = pbutils.StructToMessage(cfg.Data.GetAttrs(), ret)
		assert.Nil(t, err, "%+v", err)
		return append(ret.ActiveIndexesWG, ret.ActiveIndexesQUIC...)
	}

	var usrs []*tstuser.User
	userCtxs := make(map[string]*userctx.UserCtx)
	for range 3 {
		usrT, err := tstuser.NewUserWithType(tst.C.OcteliumC, adminSrv, usrSrv, nil,
			corev1.User_Spec_HUMAN, corev1.Session_Status_CLIENT)
		assert.Nil(t, err, "%+v", err)

		i, err := userctx.GetUserCtx(usrT.Ctx())
		assert.Nil(t, err, "%+v", err)

		usrs = append(usrs, usrT)
		userCtxs[usrT.Session.Metadata.Uid] = i
	}

	s := newGRPCServer(grpc.ChainStreamInterceptor(
		func(srv any, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
			md, _ := metadata.FromIncomingContext(ss.Context())
			return handler(srv, &userCtxStream{
				ServerStream: ss,
				ctx: context.WithValue(ss.Context(), "octelium-user-ctx",
					userCtxs[md.Get("x-test-session-uid")[0]]),
			})
		}))
	userv1.RegisterMainServiceServer(s, usrSrv)

	lis := bufconn.Listen(1024 * 1024)
	go s.Serve(lis)

	conn, err := grpc.NewClient("passthrough:///bufconn",
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
			return lis.DialContext(ctx)
		}),
		grpc.WithTransportCredentials(insecure.NewCredentials()))
	assert.Nil(t, err, "%+v", err)
	t.Cleanup(func() {
		conn.Close()
	})

	for _, usrT := range usrs {
		stream, err := userv1.NewMainServiceClient(conn).Connect(
			metadata.AppendToOutgoingContext(ctx, "x-test-session-uid", usrT.Session.Metadata.Uid))
		assert.Nil(t, err, "%+v", err)

		err = stream.Send(&userv1.ConnectRequest{
			Type: &userv1.ConnectRequest_Initialize_{
				Initialize: &userv1.ConnectRequest_Initialize{},
			},
		})
		assert.Nil(t, err, "%+v", err)

		resp, err := stream.Recv()
		assert.Nil(t, err, "%+v", err)
		assert.NotNil(t, resp.GetState())
	}

	assert.Equal(t, len(usrs), len(getActiveIndexes()))

	for _, usrT := range usrs {
		usrT.Resync()
		assert.True(t, usrT.Session.Status.IsConnected)
		assert.NotNil(t, usrT.Session.Status.Connection)
	}

	s.Stop()

	for _, usrT := range usrs {
		usrT.Resync()
		assert.False(t, usrT.Session.Status.IsConnected)
		assert.Nil(t, usrT.Session.Status.Connection)
		assert.Equal(t, 1, len(usrT.Session.Status.LastConnections))
	}

	assert.Equal(t, 0, len(getActiveIndexes()))
}
