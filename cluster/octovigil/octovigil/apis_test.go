package octovigil

import (
	"context"
	"testing"
	"time"

	"github.com/octelium/octelium/apis/cluster/coctovigilv1"
	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/apis/main/metav1"
	"github.com/octelium/octelium/apis/rsc/rcorev1"
	"github.com/octelium/octelium/apis/rsc/rmetav1"
	"github.com/octelium/octelium/cluster/common/octeliumc"
	"github.com/octelium/octelium/cluster/common/vutils"
	"github.com/octelium/octelium/cluster/octovigil/octovigil/acache"
	"github.com/octelium/octelium/pkg/common/pbutils"
	"github.com/stretchr/testify/assert"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type downstreamCoreC struct {
	rcorev1.ResourceServiceClient
	session    *corev1.Session
	user       *corev1.User
	device     *corev1.Device
	groups     []*corev1.Group
	calls      []string
	errs       map[string]error
	getSession func()
}

func (c *downstreamCoreC) GetSession(ctx context.Context,
	in *rmetav1.GetOptions, opts ...grpc.CallOption) (*corev1.Session, error) {
	c.calls = append(c.calls, "session:"+in.Uid)
	if c.getSession != nil {
		c.getSession()
	}
	return c.session, c.errs["session"]
}

func (c *downstreamCoreC) GetUser(ctx context.Context,
	in *rmetav1.GetOptions, opts ...grpc.CallOption) (*corev1.User, error) {
	c.calls = append(c.calls, "user:"+in.Uid)
	return c.user, c.errs["user"]
}

func (c *downstreamCoreC) GetDevice(ctx context.Context,
	in *rmetav1.GetOptions, opts ...grpc.CallOption) (*corev1.Device, error) {
	c.calls = append(c.calls, "device:"+in.Uid)
	return c.device, c.errs["device"]
}

func (c *downstreamCoreC) GetGroup(ctx context.Context,
	in *rmetav1.GetOptions, opts ...grpc.CallOption) (*corev1.Group, error) {
	c.calls = append(c.calls, "group:"+in.Name)
	if err := c.errs["group"]; err != nil {
		return nil, err
	}
	for _, grp := range c.groups {
		if grp.Metadata.Name == in.Name {
			return grp, nil
		}
	}
	return nil, status.Error(codes.NotFound, "Group not found")
}

type downstreamOcteliumC struct {
	octeliumc.ClientInterface
	coreC *downstreamCoreC
}

func (c *downstreamOcteliumC) CoreC() rcorev1.ResourceServiceClient {
	return c.coreC
}

func newDownstreamService(t *testing.T) (*internalService, *downstreamCoreC) {
	t.Helper()

	cache, err := acache.NewCache()
	assert.Nil(t, err)
	t.Cleanup(func() {
		cache.Close()
	})

	coreC := &downstreamCoreC{
		session: &corev1.Session{
			Metadata: &metav1.Metadata{Uid: vutils.UUIDv4(), Name: "session"},
			Status: &corev1.Session_Status{
				UserRef:   &metav1.ObjectReference{Uid: "user"},
				DeviceRef: &metav1.ObjectReference{Uid: "device"},
			},
		},
		user: &corev1.User{
			Metadata: &metav1.Metadata{Uid: "user", Name: "user"},
			Spec:     &corev1.User_Spec{Groups: []string{"group1", "group2"}},
		},
		device: &corev1.Device{
			Metadata: &metav1.Metadata{Uid: "device", Name: "device"},
			Status: &corev1.Device_Status{
				ProbeAttempt: &corev1.Device_Status_ProbeAttempt{Uid: "attempt"},
				Posture: &corev1.Device_Status_Posture{
					ExpiresAt: timestamppb.New(time.Now().Add(-time.Hour)),
				},
			},
		},
		groups: []*corev1.Group{
			{Metadata: &metav1.Metadata{Uid: "group1", Name: "group1"}},
			{Metadata: &metav1.Metadata{Uid: "group2", Name: "group2"}},
		},
		errs: make(map[string]error),
	}

	return &internalService{s: &Server{
		cache:     cache,
		octeliumC: &downstreamOcteliumC{coreC: coreC},
	}}, coreC
}

func TestGetDownstreamFromSessionUID(t *testing.T) {
	for _, mode := range []string{"cold", "session", "dependencies", "partial groups", "warm"} {
		t.Run(mode, func(t *testing.T) {
			srv, coreC := newDownstreamService(t)
			cache := srv.s.cache
			sessUID := coreC.session.Metadata.Uid

			if mode != "cold" && mode != "dependencies" {
				assert.Nil(t, cache.SetSession(coreC.session))
			}
			if mode == "dependencies" || mode == "partial groups" || mode == "warm" {
				assert.Nil(t, cache.SetUser(coreC.user))
				assert.Nil(t, cache.SetDevice(coreC.device))
				assert.Nil(t, cache.SetGroup(coreC.groups[0]))
				if mode != "partial groups" {
					assert.Nil(t, cache.SetGroup(coreC.groups[1]))
				}
			}

			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			resp, err := srv.GetDownstreamFromSessionUID(ctx,
				&coctovigilv1.GetDownstreamFromSessionUIDRequest{SessionUID: sessUID})
			if !assert.Nil(t, err) || !assert.NotNil(t, resp) {
				return
			}

			assert.True(t, pbutils.IsEqual(coreC.session, resp.Session))
			assert.True(t, pbutils.IsEqual(coreC.user, resp.User))
			assert.Equal(t, coreC.groups, resp.Groups)
			if !assert.NotNil(t, resp.Device) {
				return
			}
			assert.Nil(t, resp.Device.Status.ProbeAttempt)
			assert.Nil(t, resp.Device.Status.Posture)
			assert.NotNil(t, coreC.device.Status.ProbeAttempt)
			assert.NotNil(t, coreC.device.Status.Posture)

			switch mode {
			case "cold":
				assert.Equal(t, []string{"session:" + sessUID, "user:user", "device:device", "group:group1", "group:group2"}, coreC.calls)
			case "session":
				assert.Equal(t, []string{"user:user", "device:device", "group:group1", "group:group2"}, coreC.calls)
			case "dependencies":
				assert.Equal(t, []string{"session:" + sessUID}, coreC.calls)
			case "partial groups":
				assert.Equal(t, []string{"group:group2"}, coreC.calls)
			case "warm":
				assert.Empty(t, coreC.calls)
			}

			_, err = cache.GetSession(sessUID)
			assert.Equal(t, mode != "cold" && mode != "dependencies", err == nil)
			_, err = cache.GetUser("user")
			assert.Equal(t, mode != "cold" && mode != "session", err == nil)
		})
	}
}

func TestGetDownstreamFromSessionUIDMissingGroup(t *testing.T) {
	srv, coreC := newDownstreamService(t)
	coreC.user.Spec.Groups = append(coreC.user.Spec.Groups, "group3")
	assert.Nil(t, srv.s.cache.SetSession(coreC.session))
	assert.Nil(t, srv.s.cache.SetUser(coreC.user))
	assert.Nil(t, srv.s.cache.SetDevice(coreC.device))
	assert.Nil(t, srv.s.cache.SetGroup(coreC.groups[0]))
	assert.Nil(t, srv.s.cache.SetGroup(coreC.groups[1]))

	resp, err := srv.GetDownstreamFromSessionUID(context.Background(),
		&coctovigilv1.GetDownstreamFromSessionUIDRequest{SessionUID: coreC.session.Metadata.Uid})
	if !assert.Nil(t, err) || !assert.NotNil(t, resp) {
		return
	}
	assert.Equal(t, coreC.groups, resp.Groups)
	assert.Equal(t, []string{"group:group3"}, coreC.calls)
}

func TestGetDownstreamFromSessionUIDErrors(t *testing.T) {
	for _, resource := range []string{"session", "user", "device", "group"} {
		for _, code := range []codes.Code{codes.NotFound, codes.Unavailable, codes.DeadlineExceeded} {
			t.Run(resource+"/"+code.String(), func(t *testing.T) {
				srv, coreC := newDownstreamService(t)
				coreC.errs[resource] = status.Error(code, "Lookup failed")

				resp, err := srv.GetDownstreamFromSessionUID(context.Background(),
					&coctovigilv1.GetDownstreamFromSessionUIDRequest{SessionUID: coreC.session.Metadata.Uid})
				if resource == "group" && code == codes.NotFound {
					assert.Nil(t, err)
					if assert.NotNil(t, resp) {
						assert.Empty(t, resp.Groups)
					}
					return
				}
				assert.Nil(t, resp)
				assert.Equal(t, code, status.Code(err))
				if resource == "session" && code == codes.NotFound {
					assert.Equal(t, "Session UID not Found", status.Convert(err).Message())
				}
			})
		}
	}

	for _, identifier := range []string{"", "session", "10.0.0.1", "fd00::1", "not-a-uid"} {
		t.Run("identifier "+identifier, func(t *testing.T) {
			srv, coreC := newDownstreamService(t)
			resp, err := srv.GetDownstreamFromSessionUID(context.Background(),
				&coctovigilv1.GetDownstreamFromSessionUIDRequest{SessionUID: identifier})
			assert.Nil(t, resp)
			assert.Equal(t, codes.NotFound, status.Code(err))
			assert.Empty(t, coreC.calls)
		})
	}
}

func TestGetDownstreamFromSessionUIDWatchUpdate(t *testing.T) {
	srv, coreC := newDownstreamService(t)
	sessUID := coreC.session.Metadata.Uid
	newSession := pbutils.Clone(coreC.session).(*corev1.Session)
	newSession.Status.IsConnected = true
	coreC.getSession = func() {
		assert.Nil(t, srv.s.cache.SetSession(newSession))
	}

	resp, err := srv.GetDownstreamFromSessionUID(context.Background(),
		&coctovigilv1.GetDownstreamFromSessionUIDRequest{SessionUID: sessUID})
	assert.Nil(t, err)
	assert.NotNil(t, resp)
	sess, err := srv.s.cache.GetSession(sessUID)
	assert.Nil(t, err)
	assert.True(t, pbutils.IsEqual(newSession, sess))
}
