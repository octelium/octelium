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
	"sync/atomic"
	"testing"
	"time"

	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/apis/main/metav1"
	"github.com/octelium/octelium/apis/rsc/rcorev1"
	"github.com/octelium/octelium/apis/rsc/rmetav1"
	"github.com/octelium/octelium/cluster/apiserver/apiserver/admin"
	"github.com/octelium/octelium/cluster/common/tests"
	"github.com/octelium/octelium/cluster/common/watchers"
	"github.com/octelium/octelium/pkg/apiutils/umetav1"
	"github.com/octelium/octelium/pkg/common/pbutils"
	"github.com/octelium/octelium/pkg/grpcerr"
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

func newTstUpstreamSession() (*corev1.Service, *corev1.Session) {
	svc := newTstService()
	svc.Spec.Config.Upstream.User = "host"
	svc.Spec.Config.Upstream.Type = &corev1.Service_Spec_Config_Upstream_Url{
		Url: "http://localhost:8080",
	}
	svc.Metadata.SpecLabels = map[string]string{"host-user-host": "host-uid"}

	return svc, &corev1.Session{
		Metadata: &metav1.Metadata{
			Name:            "session",
			Uid:             "session-uid",
			ResourceVersion: "1",
		},
		Spec: &corev1.Session_Spec{
			State:     corev1.Session_Spec_ACTIVE,
			ExpiresAt: pbutils.Timestamp(time.Now().Add(time.Hour)),
		},
		Status: &corev1.Session_Status{
			Type:        corev1.Session_Status_CLIENT,
			UserRef:     &metav1.ObjectReference{Name: "host", Uid: "host-uid"},
			IsConnected: true,
			Connection: &corev1.Session_Status_Connection{
				Type:       corev1.Session_Status_Connection_WIREGUARD,
				StartedAt:  pbutils.Now(),
				LastSeenAt: pbutils.Now(),
				ServiceOptions: &corev1.Session_Status_Connection_ServiceOptions{
					ServeAll:  true,
					PortStart: 20000,
				},
				Upstreams: []*corev1.Session_Status_Connection_Upstream{
					{
						ServiceRef: &metav1.ObjectReference{Uid: "other-service"},
						Port:       20000,
						Backend: &corev1.Session_Status_Connection_Upstream_Backend{
							Host: "other", Port: 9000,
						},
					},
				},
			},
		},
	}
}

func TestSessionUpstreamWriteErrors(t *testing.T) {
	for _, remove := range []bool{false, true} {
		for _, code := range []codes.Code{
			codes.Unavailable, codes.Internal, codes.Canceled,
			codes.DeadlineExceeded, codes.PermissionDenied, codes.Unknown,
		} {
			t.Run(fmt.Sprintf("Remove%t/%s", remove, code), func(t *testing.T) {
				ctx := context.Background()
				svc, sess := newTstUpstreamSession()
				sess.Status.Connection.Upstreams = append(sess.Status.Connection.Upstreams,
					&corev1.Session_Status_Connection_Upstream{
						ServiceRef: &metav1.ObjectReference{Uid: svc.Metadata.Uid}, Port: 20001,
					})
				errTst := status.Error(code, "could not update Session")
				var updates int
				coreC := &fakeSessionCoreC{
					listSession: func(in *rmetav1.ListOptions) (*corev1.SessionList, error) {
						return &corev1.SessionList{Items: []*corev1.Session{proto.Clone(sess).(*corev1.Session)}}, nil
					},
					getSession: func(in *rmetav1.GetOptions) (*corev1.Session, error) {
						return proto.Clone(sess).(*corev1.Session), nil
					},
					updateSession: func(in *corev1.Session) (*corev1.Session, error) {
						updates++
						return nil, errTst
					},
				}
				c := NewController(&fakeOcteliumC{coreC: coreC}, nil)
				if remove {
					assert.ErrorIs(t, c.handleDeleteSessionUpstream(ctx, svc), errTst)
				} else {
					assert.ErrorIs(t, c.handleUpdateSessionUpstream(ctx, svc), errTst)
				}
				assert.Equal(t, 1, updates)
				assert.Len(t, sess.Status.Connection.Upstreams, 2)
			})
		}
	}
}

func TestSessionUpstreamConflict(t *testing.T) {
	for _, remove := range []bool{false, true} {
		for _, existing := range []bool{false, true} {
			t.Run(fmt.Sprintf("Remove%t/Existing%t", remove, existing), func(t *testing.T) {
				ctx := context.Background()
				svc, sess := newTstUpstreamSession()
				if remove || existing {
					sess.Status.Connection.Upstreams = append(sess.Status.Connection.Upstreams,
						&corev1.Session_Status_Connection_Upstream{
							ServiceRef: &metav1.ObjectReference{Uid: svc.Metadata.Uid}, Port: 25000,
							Backend: &corev1.Session_Status_Connection_Upstream_Backend{
								Host: "old", Port: 80,
							},
						})
				}
				current := proto.Clone(sess).(*corev1.Session)
				var updates, gets int
				coreC := &fakeSessionCoreC{
					listSession: func(in *rmetav1.ListOptions) (*corev1.SessionList, error) {
						return &corev1.SessionList{Items: []*corev1.Session{proto.Clone(sess).(*corev1.Session)}}, nil
					},
					getSession: func(in *rmetav1.GetOptions) (*corev1.Session, error) {
						gets++
						assert.Equal(t, sess.Metadata.Uid, in.Uid)
						return proto.Clone(current).(*corev1.Session), nil
					},
					updateSession: func(in *corev1.Session) (*corev1.Session, error) {
						updates++
						assert.Equal(t, current.Metadata.ResourceVersion, in.Metadata.ResourceVersion)
						if updates < 3 {
							current.Metadata.ResourceVersion = fmt.Sprintf("%d", updates+1)
							current.Spec.ExpiresAt = pbutils.Timestamp(time.Now().Add(2 * time.Hour))
							current.Status.Connection.LastSeenAt = pbutils.Now()
							current.Status.Connection.PublishedServices = []*corev1.Session_Status_Connection_PublishedService{
								{ServiceRef: &metav1.ObjectReference{Uid: "published"}, Port: 30000},
							}
							current.Status.Connection.Upstreams = append(current.Status.Connection.Upstreams,
								&corev1.Session_Status_Connection_Upstream{
									ServiceRef: &metav1.ObjectReference{Uid: fmt.Sprintf("concurrent-%d", updates)},
									Port:       int32(20000 + updates),
									Backend: &corev1.Session_Status_Connection_Upstream_Backend{
										Host: "concurrent", Port: 9000,
									},
								})
							return nil, status.Error(codes.OutOfRange, "resource changed")
						}
						assert.True(t, proto.Equal(current.Spec, in.Spec))
						expected := proto.Clone(current.Status.Connection).(*corev1.Session_Status_Connection)
						actual := proto.Clone(in.Status.Connection).(*corev1.Session_Status_Connection)
						expected.Upstreams = nil
						actual.Upstreams = nil
						assert.True(t, proto.Equal(expected, actual))
						current = proto.Clone(in).(*corev1.Session)
						return in, nil
					},
				}
				c := NewController(&fakeOcteliumC{coreC: coreC}, nil)
				if remove {
					assert.Nil(t, c.handleDeleteSessionUpstream(ctx, svc))
					assert.False(t, sessionHasUpstreamForSvc(current, svc))
					assert.Equal(t, 3, gets)
					assert.Len(t, current.Status.Connection.Upstreams, 3)
				} else {
					assert.Nil(t, c.handleUpdateSessionUpstream(ctx, svc))
					assert.Equal(t, 2, gets)
					assert.Len(t, current.Status.Connection.Upstreams, 4)
					var found int
					for _, u := range current.Status.Connection.Upstreams {
						if u.ServiceRef.Uid == svc.Metadata.Uid {
							found++
							assert.Equal(t, "localhost", u.Backend.Host)
							assert.Equal(t, int32(8080), u.Backend.Port)
							if existing {
								assert.Equal(t, int32(25000), u.Port)
							} else {
								assert.Equal(t, int32(20003), u.Port)
							}
						}
					}
					assert.Equal(t, 1, found)
				}
				assert.Equal(t, 3, updates)
				assert.True(t, proto.Equal(sess.Status.Connection.Upstreams[0], current.Status.Connection.Upstreams[0]))
			})
		}
	}
}

func TestSessionUpstreamConflictLimit(t *testing.T) {
	for _, remove := range []bool{false, true} {
		t.Run(fmt.Sprintf("Remove%t", remove), func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			svc, sess := newTstUpstreamSession()
			sess.Status.Connection.Upstreams = append(sess.Status.Connection.Upstreams,
				&corev1.Session_Status_Connection_Upstream{
					ServiceRef: &metav1.ObjectReference{Uid: svc.Metadata.Uid}, Port: 20001,
				})
			errTst := status.Error(codes.OutOfRange, "resource changed")
			var updates int
			coreC := &fakeSessionCoreC{
				listSession: func(in *rmetav1.ListOptions) (*corev1.SessionList, error) {
					return &corev1.SessionList{Items: []*corev1.Session{proto.Clone(sess).(*corev1.Session)}}, nil
				},
				getSession: func(in *rmetav1.GetOptions) (*corev1.Session, error) {
					return proto.Clone(sess).(*corev1.Session), nil
				},
				updateSession: func(in *corev1.Session) (*corev1.Session, error) {
					updates++
					if updates > 10 {
						cancel()
						return nil, context.Canceled
					}
					return nil, errTst
				},
			}
			c := NewController(&fakeOcteliumC{coreC: coreC}, nil)
			if remove {
				assert.ErrorIs(t, c.handleDeleteSessionUpstream(ctx, svc), errTst)
			} else {
				assert.ErrorIs(t, c.handleUpdateSessionUpstream(ctx, svc), errTst)
			}
			assert.Equal(t, 3, updates)
		})
	}
}

func TestSessionUpstreamConnectionChanged(t *testing.T) {
	for _, tc := range []struct {
		name string
		set  func(*corev1.Session)
	}{
		{"Disconnected", func(sess *corev1.Session) {
			sess.Status.IsConnected = false
			sess.Status.Connection = nil
		}},
		{"NoOptions", func(sess *corev1.Session) { sess.Status.Connection.ServiceOptions = nil }},
		{"NotServing", func(sess *corev1.Session) { sess.Status.Connection.ServiceOptions.ServeAll = false }},
		{"OtherService", func(sess *corev1.Session) {
			sess.Status.Connection.ServiceOptions = &corev1.Session_Status_Connection_ServiceOptions{
				RequestedServices: []*corev1.Session_Status_Connection_ServiceOptions_RequestedService{
					{ServiceRef: &metav1.ObjectReference{Uid: "unrequested-service"}},
				},
			}
		}},
		{"OtherType", func(sess *corev1.Session) { sess.Status.Type = corev1.Session_Status_CLIENTLESS }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			svc, sess := newTstUpstreamSession()
			current := proto.Clone(sess).(*corev1.Session)
			tc.set(current)
			var updates, gets int
			coreC := &fakeSessionCoreC{
				listSession: func(in *rmetav1.ListOptions) (*corev1.SessionList, error) {
					return &corev1.SessionList{Items: []*corev1.Session{proto.Clone(sess).(*corev1.Session)}}, nil
				},
				getSession: func(in *rmetav1.GetOptions) (*corev1.Session, error) {
					gets++
					return proto.Clone(current).(*corev1.Session), nil
				},
				updateSession: func(in *corev1.Session) (*corev1.Session, error) {
					updates++
					return nil, status.Error(codes.OutOfRange, "resource changed")
				},
			}
			c := NewController(&fakeOcteliumC{coreC: coreC}, nil)
			assert.Nil(t, c.handleUpdateSessionUpstream(context.Background(), svc))
			assert.Equal(t, 1, updates)
			assert.Equal(t, 1, gets)
			assert.False(t, sessionHasUpstreamForSvc(current, svc))
		})
	}
}

func TestSessionUpstreamReloadErrors(t *testing.T) {
	for _, code := range []codes.Code{codes.NotFound, codes.Unavailable, codes.Internal, codes.Canceled} {
		t.Run(code.String(), func(t *testing.T) {
			svc, sess := newTstUpstreamSession()
			errTst := status.Error(code, "could not get Session")
			var updates, gets int
			coreC := &fakeSessionCoreC{
				listSession: func(in *rmetav1.ListOptions) (*corev1.SessionList, error) {
					return &corev1.SessionList{Items: []*corev1.Session{proto.Clone(sess).(*corev1.Session)}}, nil
				},
				getSession: func(in *rmetav1.GetOptions) (*corev1.Session, error) {
					gets++
					assert.Equal(t, sess.Metadata.Uid, in.Uid)
					return nil, errTst
				},
				updateSession: func(in *corev1.Session) (*corev1.Session, error) {
					updates++
					return nil, status.Error(codes.OutOfRange, "resource changed")
				},
			}
			c := NewController(&fakeOcteliumC{coreC: coreC}, nil)
			err := c.handleUpdateSessionUpstream(context.Background(), svc)
			if code == codes.NotFound {
				assert.Nil(t, err)
			} else {
				assert.ErrorIs(t, err, errTst)
			}
			assert.Equal(t, 1, updates)
			assert.Equal(t, 1, gets)
		})
	}
}

func TestSessionUpstreamCancelled(t *testing.T) {
	for _, remove := range []bool{false, true} {
		for _, before := range []bool{false, true} {
			t.Run(fmt.Sprintf("Remove%t/Before%t", remove, before), func(t *testing.T) {
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				if before {
					cancel()
				}
				svc, sess := newTstUpstreamSession()
				sess.Status.Connection.Upstreams = append(sess.Status.Connection.Upstreams,
					&corev1.Session_Status_Connection_Upstream{
						ServiceRef: &metav1.ObjectReference{Uid: svc.Metadata.Uid}, Port: 20001,
					})
				var updates, gets int
				coreC := &fakeSessionCoreC{
					listSession: func(in *rmetav1.ListOptions) (*corev1.SessionList, error) {
						return &corev1.SessionList{Items: []*corev1.Session{proto.Clone(sess).(*corev1.Session)}}, nil
					},
					getSession: func(in *rmetav1.GetOptions) (*corev1.Session, error) {
						gets++
						return proto.Clone(sess).(*corev1.Session), nil
					},
					updateSession: func(in *corev1.Session) (*corev1.Session, error) {
						updates++
						cancel()
						return nil, status.Error(codes.OutOfRange, "resource changed")
					},
				}
				c := NewController(&fakeOcteliumC{coreC: coreC}, nil)
				if remove {
					assert.ErrorIs(t, c.handleDeleteSessionUpstream(ctx, svc), context.Canceled)
				} else {
					assert.ErrorIs(t, c.handleUpdateSessionUpstream(ctx, svc), context.Canceled)
				}
				if before {
					assert.Zero(t, updates)
					assert.Zero(t, gets)
				} else {
					assert.Equal(t, 1, updates)
					if remove {
						assert.Equal(t, 1, gets)
					} else {
						assert.Zero(t, gets)
					}
				}
			})
		}
	}
}

func TestSessionUpstreamControllerWriteErrors(t *testing.T) {
	ctx := context.Background()
	t.Setenv("OCTELIUM_REGION_NAME", "default")
	svc, sess := newTstUpstreamSession()
	sess.Status.Connection.Upstreams = append(sess.Status.Connection.Upstreams,
		&corev1.Session_Status_Connection_Upstream{
			ServiceRef: &metav1.ObjectReference{Uid: svc.Metadata.Uid}, Port: 20001,
		})
	errTst := status.Error(codes.Unavailable, "could not update Session")
	coreC := &fakeSessionCoreC{
		ResourceServiceClient: &fakeCoreC{
			getService: func(ctx context.Context, in *rmetav1.GetOptions) (*corev1.Service, error) {
				return proto.Clone(svc).(*corev1.Service), nil
			},
		},
		listSession: func(in *rmetav1.ListOptions) (*corev1.SessionList, error) {
			return &corev1.SessionList{Items: []*corev1.Session{proto.Clone(sess).(*corev1.Session)}}, nil
		},
		getSession: func(in *rmetav1.GetOptions) (*corev1.Session, error) {
			return proto.Clone(sess).(*corev1.Session), nil
		},
		updateSession: func(in *corev1.Session) (*corev1.Session, error) { return nil, errTst },
	}
	c := NewController(&fakeOcteliumC{coreC: coreC}, fakek8s.NewSimpleClientset())
	assert.ErrorIs(t, c.OnAdd(ctx, svc), errTst)
	assert.ErrorIs(t, c.OnUpdate(ctx, svc, svc), errTst)
	assert.ErrorIs(t, c.OnDelete(ctx, svc), errTst)
}

func TestSessionUpstreamPersistedConflict(t *testing.T) {
	ctx := context.Background()
	tst, err := tests.Initialize(nil)
	assert.Nil(t, err, "%+v", err)
	t.Cleanup(func() { tst.Destroy() })
	realC := tst.C.OcteliumC.CoreC()

	for _, remove := range []bool{false, true} {
		t.Run(fmt.Sprintf("Remove%t", remove), func(t *testing.T) {
			svc, sess := newTstUpstreamSession()
			svc.Metadata.Name = utilrand.GetRandomStringCanonical(8) + ".default"
			svc.Metadata.Uid = ""
			svc, err := realC.CreateService(ctx, svc)
			assert.Nil(t, err, "%+v", err)
			sess.Metadata = &metav1.Metadata{Name: utilrand.GetRandomStringCanonical(8)}
			if remove {
				sess.Status.Connection.Upstreams = append(sess.Status.Connection.Upstreams,
					&corev1.Session_Status_Connection_Upstream{
						ServiceRef: umetav1.GetObjectReference(svc), Port: 20001,
					})
			}
			sess, err = realC.CreateSession(ctx, sess)
			assert.Nil(t, err, "%+v", err)
			defer realC.DeleteSession(ctx, &rmetav1.DeleteOptions{Uid: sess.Metadata.Uid})

			var concurrent *corev1.Session
			var updates int
			coreC := &fakeSessionCoreC{
				ResourceServiceClient: realC,
				listSession: func(in *rmetav1.ListOptions) (*corev1.SessionList, error) {
					return realC.ListSession(ctx, in)
				},
				getSession: func(in *rmetav1.GetOptions) (*corev1.Session, error) {
					return realC.GetSession(ctx, in)
				},
				updateSession: func(in *corev1.Session) (*corev1.Session, error) {
					updates++
					if updates == 1 {
						current, err := realC.GetSession(ctx, &rmetav1.GetOptions{Uid: sess.Metadata.Uid})
						assert.Nil(t, err, "%+v", err)
						current.Spec.ExpiresAt = pbutils.Timestamp(time.Now().Add(2 * time.Hour))
						current.Status.Connection.LastSeenAt = pbutils.Now()
						current.Status.Connection.Upstreams = append(current.Status.Connection.Upstreams,
							&corev1.Session_Status_Connection_Upstream{
								ServiceRef: &metav1.ObjectReference{Uid: "concurrent-service"}, Port: 20002,
							})
						concurrent, err = realC.UpdateSession(ctx, current)
						assert.Nil(t, err, "%+v", err)
					}
					res, err := realC.UpdateSession(ctx, in)
					if updates == 1 {
						assert.True(t, grpcerr.IsResourceChanged(err), "%+v", err)
					}
					return res, err
				},
			}
			c := NewController(&fakeOcteliumC{coreC: coreC}, nil)
			if remove {
				assert.Nil(t, c.handleDeleteSessionUpstream(ctx, svc))
			} else {
				assert.Nil(t, c.handleUpdateSessionUpstream(ctx, svc))
			}
			assert.Equal(t, 2, updates)
			res, err := realC.GetSession(ctx, &rmetav1.GetOptions{Uid: sess.Metadata.Uid})
			assert.Nil(t, err, "%+v", err)
			assert.True(t, proto.Equal(concurrent.Spec, res.Spec))
			assert.True(t, proto.Equal(concurrent.Status.Connection.LastSeenAt, res.Status.Connection.LastSeenAt))
			assert.True(t, proto.Equal(concurrent.Status.Connection.Upstreams[0], res.Status.Connection.Upstreams[0]))
			assert.True(t, sessionHasUpstreamForSvc(res,
				&corev1.Service{Metadata: &metav1.Metadata{Uid: "concurrent-service"}}))
			assert.Equal(t, !remove, sessionHasUpstreamForSvc(res, svc))
			if !remove {
				for _, u := range res.Status.Connection.Upstreams {
					if u.ServiceRef.Uid == svc.Metadata.Uid {
						assert.Equal(t, "localhost", u.Backend.Host)
						assert.Equal(t, int32(8080), u.Backend.Port)
					}
				}
			}
		})
	}
}

func TestSessionUpstreamWatcherRetry(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	t.Setenv("OCTELIUM_REGION_NAME", "default")
	tst, err := tests.Initialize(nil)
	assert.Nil(t, err, "%+v", err)
	t.Cleanup(func() { tst.Destroy() })
	realC := tst.C.OcteliumC.CoreC()

	svc, sess := newTstUpstreamSession()
	svc.Metadata.Name = utilrand.GetRandomStringCanonical(8) + ".default"
	svc.Metadata.Uid = ""
	svc, err = realC.CreateService(ctx, svc)
	assert.Nil(t, err, "%+v", err)
	sess.Metadata = &metav1.Metadata{Name: utilrand.GetRandomStringCanonical(8)}
	sess, err = realC.CreateSession(ctx, sess)
	assert.Nil(t, err, "%+v", err)

	var updates atomic.Int32
	var fail atomic.Bool
	fail.Store(true)
	coreC := &fakeSessionCoreC{
		ResourceServiceClient: realC,
		listSession: func(in *rmetav1.ListOptions) (*corev1.SessionList, error) {
			return realC.ListSession(ctx, in)
		},
		getSession: func(in *rmetav1.GetOptions) (*corev1.Session, error) {
			return realC.GetSession(ctx, in)
		},
		updateSession: func(in *corev1.Session) (*corev1.Session, error) {
			updates.Add(1)
			if fail.Swap(false) {
				return nil, status.Error(codes.Unavailable, "could not update Session")
			}
			return realC.UpdateSession(ctx, in)
		},
	}
	octeliumC := &fakeOcteliumC{coreC: coreC}
	c := NewController(octeliumC, tst.C.K8sC)

	watcher, err := watchers.NewWatcher("core", "v1", "Service",
		func(ctx context.Context, item umetav1.ResourceObjectI) error {
			return c.OnAdd(ctx, item.(*corev1.Service))
		},
		func(ctx context.Context, new, old umetav1.ResourceObjectI) error {
			return c.OnUpdate(ctx, new.(*corev1.Service), old.(*corev1.Service))
		},
		func(ctx context.Context, item umetav1.ResourceObjectI) error {
			return c.OnDelete(ctx, item.(*corev1.Service))
		}, realC,
		func() (umetav1.ResourceObjectI, error) { return &corev1.Service{}, nil })
	assert.Nil(t, err, "%+v", err)
	defer watcher.Close()
	assert.Nil(t, watcher.Run(ctx))

	if !assert.Eventually(t, func() bool {
		res, err := realC.GetSession(ctx, &rmetav1.GetOptions{Uid: sess.Metadata.Uid})
		return err == nil && sessionHasUpstreamForSvc(res, svc)
	}, 10*time.Second, 10*time.Millisecond) {
		return
	}
	assert.Equal(t, int32(2), updates.Load())

	svc.Spec.Config.Upstream.Type = &corev1.Service_Spec_Config_Upstream_Url{
		Url: "http://updated:9090",
	}
	fail.Store(true)
	svc, err = realC.UpdateService(ctx, svc)
	assert.Nil(t, err, "%+v", err)
	if !assert.Eventually(t, func() bool {
		res, err := realC.GetSession(ctx, &rmetav1.GetOptions{Uid: sess.Metadata.Uid})
		if err != nil {
			return false
		}
		for _, u := range res.Status.Connection.Upstreams {
			if u.ServiceRef.Uid == svc.Metadata.Uid {
				return u.Backend != nil && u.Backend.Host == "updated" && u.Backend.Port == 9090
			}
		}
		return false
	}, 10*time.Second, 10*time.Millisecond) {
		return
	}
	assert.Equal(t, int32(4), updates.Load())

	fail.Store(true)
	_, err = realC.DeleteService(ctx, &rmetav1.DeleteOptions{Uid: svc.Metadata.Uid})
	assert.Nil(t, err, "%+v", err)
	assert.Eventually(t, func() bool {
		res, err := realC.GetSession(ctx, &rmetav1.GetOptions{Uid: sess.Metadata.Uid})
		return err == nil && !sessionHasUpstreamForSvc(res, svc)
	}, 10*time.Second, 10*time.Millisecond)
	assert.Equal(t, int32(6), updates.Load())

	res, err := realC.GetSession(ctx, &rmetav1.GetOptions{Uid: sess.Metadata.Uid})
	assert.Nil(t, err, "%+v", err)
	assert.Len(t, res.Status.Connection.Upstreams, 1)
	assert.True(t, proto.Equal(sess.Status.Connection.Upstreams[0], res.Status.Connection.Upstreams[0]))
}

func TestSessionUpstreamReconnectedSession(t *testing.T) {
	for _, typ := range []corev1.Session_Status_Connection_Type{
		corev1.Session_Status_Connection_WIREGUARD,
		corev1.Session_Status_Connection_QUICV0,
	} {
		t.Run(typ.String(), func(t *testing.T) {
			svc, sess := newTstUpstreamSession()
			current := proto.Clone(sess).(*corev1.Session)
			current.Metadata.ResourceVersion = "2"
			current.Status.Connection = &corev1.Session_Status_Connection{
				Type:            typ,
				StartedAt:       pbutils.Timestamp(time.Now().Add(time.Minute)),
				LastSeenAt:      pbutils.Timestamp(time.Now().Add(time.Minute)),
				X25519PublicKey: []byte("new public key"),
				Addresses:       []*metav1.DualStackNetwork{{V4: "10.0.0.2/32"}},
				ServiceOptions: &corev1.Session_Status_Connection_ServiceOptions{
					PortStart: 40000,
					RequestedServices: []*corev1.Session_Status_Connection_ServiceOptions_RequestedService{
						{ServiceRef: &metav1.ObjectReference{Uid: svc.Metadata.Uid}},
					},
				},
				Upstreams: []*corev1.Session_Status_Connection_Upstream{
					{ServiceRef: &metav1.ObjectReference{Uid: "new-service"}, Port: 40000},
				},
			}
			var updates int
			coreC := &fakeSessionCoreC{
				listSession: func(in *rmetav1.ListOptions) (*corev1.SessionList, error) {
					return &corev1.SessionList{Items: []*corev1.Session{proto.Clone(sess).(*corev1.Session)}}, nil
				},
				getSession: func(in *rmetav1.GetOptions) (*corev1.Session, error) {
					return proto.Clone(current).(*corev1.Session), nil
				},
				updateSession: func(in *corev1.Session) (*corev1.Session, error) {
					updates++
					if updates == 1 {
						return nil, status.Error(codes.OutOfRange, "resource changed")
					}
					assert.Equal(t, current.Metadata.ResourceVersion, in.Metadata.ResourceVersion)
					if !assert.Len(t, in.Status.Connection.Upstreams, 2) {
						return in, nil
					}
					assert.True(t, proto.Equal(current.Status.Connection.Upstreams[0], in.Status.Connection.Upstreams[0]))
					u := in.Status.Connection.Upstreams[1]
					assert.Equal(t, svc.Metadata.Uid, u.ServiceRef.Uid)
					assert.Equal(t, int32(40001), u.Port)
					assert.Equal(t, "localhost", u.Backend.Host)
					assert.Equal(t, int32(8080), u.Backend.Port)
					in.Status.Connection.Upstreams = in.Status.Connection.Upstreams[:1]
					assert.True(t, proto.Equal(current, in))
					return in, nil
				},
			}
			c := NewController(&fakeOcteliumC{coreC: coreC}, nil)
			assert.Nil(t, c.handleUpdateSessionUpstream(context.Background(), svc))
			assert.Equal(t, 2, updates)
		})
	}
}
