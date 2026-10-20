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

package svccontroller

import (
	"context"
	"errors"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/apis/main/metav1"
	"github.com/octelium/octelium/apis/rsc/rcorev1"
	"github.com/octelium/octelium/apis/rsc/rmetav1"
	"github.com/octelium/octelium/cluster/apiserver/apiserver/admin"
	"github.com/octelium/octelium/cluster/common/tests"
	"github.com/octelium/octelium/pkg/apiutils/umetav1"
	"github.com/octelium/octelium/pkg/common/pbutils"
	"github.com/octelium/octelium/pkg/utils/utilrand"
	"github.com/stretchr/testify/assert"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	fakek8s "k8s.io/client-go/kubernetes/fake"
)

func sessionHasUpstreamForSvc(sess *corev1.Session, svc *corev1.Service) bool {
	if sess.Status == nil || sess.Status.Connection == nil {
		return false
	}
	for _, u := range sess.Status.Connection.Upstreams {
		if u.ServiceRef != nil && u.ServiceRef.Uid == svc.Metadata.Uid {
			return true
		}
	}
	return false
}

func TestHandleSessionUpstreamLifecycle(t *testing.T) {

	ctx := context.Background()

	tst, err := tests.Initialize(nil)
	assert.Nil(t, err, "%+v", err)
	t.Cleanup(func() {
		tst.Destroy()
	})
	fakeC := tst.C

	os.Setenv("OCTELIUM_REGION_NAME", "default")
	defer os.Unsetenv("OCTELIUM_REGION_NAME")

	adminSrv := admin.NewServer(&admin.Opts{
		OcteliumC:  fakeC.OcteliumC,
		IsEmbedded: true,
	})

	netw, err := adminSrv.CreateNamespace(ctx, tests.GenNamespace())
	assert.Nil(t, err, "%+v", err)

	hostUsr, err := adminSrv.CreateUser(ctx, tests.GenUser(nil))
	assert.Nil(t, err, "%+v", err)

	c := NewController(fakeC.OcteliumC, fakeC.K8sC)

	svc, err := adminSrv.CreateService(ctx, &corev1.Service{
		Metadata: &metav1.Metadata{
			Name: fmt.Sprintf("%s.%s", utilrand.GetRandomStringCanonical(8), netw.Metadata.Name),
		},
		Spec: &corev1.Service_Spec{
			Mode: corev1.Service_Spec_HTTP,
			Config: &corev1.Service_Spec_Config{
				Upstream: &corev1.Service_Spec_Config_Upstream{
					User: hostUsr.Metadata.Name,
					Type: &corev1.Service_Spec_Config_Upstream_Url{
						Url: "https://example.com",
					},
				},
			},
		},
	})
	assert.Nil(t, err, "%+v", err)

	svcV, err := fakeC.OcteliumC.CoreC().GetService(ctx, &rmetav1.GetOptions{Uid: svc.Metadata.Uid})
	assert.Nil(t, err, "%+v", err)

	sess, err := fakeC.OcteliumC.CoreC().CreateSession(ctx, &corev1.Session{
		Metadata: &metav1.Metadata{
			Name: utilrand.GetRandomStringCanonical(8),
		},
		Spec: &corev1.Session_Spec{
			State:     corev1.Session_Spec_ACTIVE,
			ExpiresAt: pbutils.Timestamp(time.Now().Add(time.Hour)),
		},
		Status: &corev1.Session_Status{
			UserRef: umetav1.GetObjectReference(hostUsr),
			Type:    corev1.Session_Status_CLIENT,
			Connection: &corev1.Session_Status_Connection{
				ServiceOptions: &corev1.Session_Status_Connection_ServiceOptions{
					ServeAll: true,
				},
			},
		},
	})
	assert.Nil(t, err, "%+v", err)

	err = c.handleUpdateSessionUpstream(ctx, svcV)
	assert.Nil(t, err, "%+v", err)

	{
		res, err := fakeC.OcteliumC.CoreC().GetSession(ctx, &rmetav1.GetOptions{Uid: sess.Metadata.Uid})
		assert.Nil(t, err, "%+v", err)
		assert.True(t, sessionHasUpstreamForSvc(res, svc))
	}

	err = c.handleDeleteSessionUpstream(ctx, svcV)
	assert.Nil(t, err, "%+v", err)

	{
		res, err := fakeC.OcteliumC.CoreC().GetSession(ctx, &rmetav1.GetOptions{Uid: sess.Metadata.Uid})
		assert.Nil(t, err, "%+v", err)
		assert.False(t, sessionHasUpstreamForSvc(res, svc))
	}
}

func TestHandleSessionUpstreamNoUserListener(t *testing.T) {

	ctx := context.Background()

	tst, err := tests.Initialize(nil)
	assert.Nil(t, err, "%+v", err)
	t.Cleanup(func() {
		tst.Destroy()
	})
	fakeC := tst.C

	c := NewController(fakeC.OcteliumC, fakeC.K8sC)

	svc := tests.GenService("default")

	assert.Nil(t, c.handleUpdateSessionUpstream(ctx, svc))
	assert.Nil(t, c.handleDeleteSessionUpstream(ctx, svc))
}

type fakeSessionCoreC struct {
	rcorev1.ResourceServiceClient
	listSession   func(*rmetav1.ListOptions) (*corev1.SessionList, error)
	getSession    func(*rmetav1.GetOptions) (*corev1.Session, error)
	updateSession func(*corev1.Session) (*corev1.Session, error)
}

func (c *fakeSessionCoreC) ListSession(ctx context.Context,
	in *rmetav1.ListOptions, opts ...grpc.CallOption) (*corev1.SessionList, error) {
	return c.listSession(in)
}

func (c *fakeSessionCoreC) GetSession(ctx context.Context,
	in *rmetav1.GetOptions, opts ...grpc.CallOption) (*corev1.Session, error) {
	return c.getSession(in)
}

func (c *fakeSessionCoreC) UpdateSession(ctx context.Context,
	in *corev1.Session, opts ...grpc.CallOption) (*corev1.Session, error) {
	return c.updateSession(in)
}

func TestSessionUpstreamListErrors(t *testing.T) {
	ctx := context.Background()
	t.Setenv("OCTELIUM_REGION_NAME", "default")
	errTst := errors.New("could not list host Sessions")
	svc := newTstService()
	svc.Spec.Config.Upstream.User = "host"
	svc.Metadata.SpecLabels = map[string]string{"host-user-host": "host-uid"}
	coreC := &fakeSessionCoreC{
		ResourceServiceClient: &fakeCoreC{
			getService: func(ctx context.Context, in *rmetav1.GetOptions) (*corev1.Service, error) { return svc, nil },
		},
		listSession: func(in *rmetav1.ListOptions) (*corev1.SessionList, error) { return nil, errTst },
	}
	c := NewController(&fakeOcteliumC{coreC: coreC}, fakek8s.NewSimpleClientset())
	assert.ErrorIs(t, c.handleUpdateSessionUpstream(ctx, svc), errTst)
	assert.ErrorIs(t, c.handleDeleteSessionUpstream(ctx, svc), errTst)
	assert.ErrorIs(t, c.OnAdd(ctx, svc), errTst)
	assert.ErrorIs(t, c.OnUpdate(ctx, svc, svc), errTst)
	assert.ErrorIs(t, c.OnDelete(ctx, svc), errTst)
}

func TestSessionUpstreamDeletedSessions(t *testing.T) {
	ctx := context.Background()
	svc := newTstService()
	svc.Spec.Config.Upstream.User = "host"
	svc.Metadata.SpecLabels = map[string]string{"host-user-host": "host-uid"}
	sess := &corev1.Session{
		Metadata: &metav1.Metadata{Uid: "session-uid"},
		Status: &corev1.Session_Status{
			Type:    corev1.Session_Status_CLIENT,
			UserRef: &metav1.ObjectReference{Uid: "host-uid"},
			Connection: &corev1.Session_Status_Connection{
				ServiceOptions: &corev1.Session_Status_Connection_ServiceOptions{ServeAll: true},
				Upstreams: []*corev1.Session_Status_Connection_Upstream{
					{ServiceRef: &metav1.ObjectReference{Uid: svc.Metadata.Uid}},
					{ServiceRef: &metav1.ObjectReference{Uid: "other-service"}},
				},
			},
		},
	}
	var updates int
	coreC := &fakeSessionCoreC{
		listSession: func(in *rmetav1.ListOptions) (*corev1.SessionList, error) {
			return &corev1.SessionList{Items: []*corev1.Session{proto.Clone(sess).(*corev1.Session)}}, nil
		},
		getSession: func(in *rmetav1.GetOptions) (*corev1.Session, error) {
			assert.Equal(t, sess.Metadata.Uid, in.Uid)
			return nil, status.Error(codes.NotFound, "not found")
		},
		updateSession: func(in *corev1.Session) (*corev1.Session, error) {
			updates++
			return nil, status.Error(codes.NotFound, "not found")
		},
	}
	c := NewController(&fakeOcteliumC{coreC: coreC}, nil)
	assert.Nil(t, c.handleUpdateSessionUpstream(ctx, svc))
	assert.Equal(t, 1, updates)
	assert.Nil(t, c.handleDeleteSessionUpstream(ctx, svc))
	assert.Equal(t, 1, updates)

	errTst := errors.New("could not get host Session")
	coreC.getSession = func(in *rmetav1.GetOptions) (*corev1.Session, error) { return nil, errTst }
	assert.ErrorIs(t, c.handleDeleteSessionUpstream(ctx, svc), errTst)

	coreC.getSession = func(in *rmetav1.GetOptions) (*corev1.Session, error) {
		return proto.Clone(sess).(*corev1.Session), nil
	}
	updates = 0
	coreC.updateSession = func(in *corev1.Session) (*corev1.Session, error) {
		updates++
		assert.Len(t, in.Status.Connection.Upstreams, 1)
		assert.Equal(t, "other-service", in.Status.Connection.Upstreams[0].ServiceRef.Uid)
		if updates == 1 {
			return nil, status.Error(codes.OutOfRange, "resource changed")
		}
		return in, nil
	}
	assert.Nil(t, c.handleDeleteSessionUpstream(ctx, svc))
	assert.Equal(t, 2, updates)
	assert.Len(t, sess.Status.Connection.Upstreams, 2)
}
