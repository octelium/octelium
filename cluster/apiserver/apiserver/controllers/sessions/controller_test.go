package conncontroller

import (
	"fmt"
	"testing"

	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/apis/main/metav1"
	"github.com/octelium/octelium/apis/main/userv1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type tstCtl struct {
	messages []*userv1.ConnectResponse
	uids     []string
	err      error
}

func (c *tstCtl) SendMessage(msg *userv1.ConnectResponse, uid string) error {
	c.messages = append(c.messages, msg)
	c.uids = append(c.uids, uid)
	return c.err
}

func tstSession() *corev1.Session {
	return &corev1.Session{
		Metadata: &metav1.Metadata{Name: "session", Uid: "session-uid", UpdatedAt: timestamppb.Now()},
		Status: &corev1.Session_Status{Type: corev1.Session_Status_CLIENT, IsConnected: true,
			Connection: &corev1.Session_Status_Connection{Addresses: []*metav1.DualStackNetwork{{V4: "10.0.0.1/32", V6: "fd00::1/128"}}},
		},
	}
}

func tstUpstream(name string, port int32) *corev1.Session_Status_Connection_Upstream {
	return &corev1.Session_Status_Connection_Upstream{
		ServiceRef:   &metav1.ObjectReference{Name: name + ".default", Uid: name},
		NamespaceRef: &metav1.ObjectReference{Name: "default", Uid: "namespace-uid"},
		Port:         port, L4Type: corev1.Session_Status_Connection_Upstream_TCP,
		Backend: &corev1.Session_Status_Connection_Upstream_Backend{Host: "127.0.0.1", Port: port},
	}
}

func TestHostedServiceEvents(t *testing.T) {
	for _, sendErr := range []error{nil, fmt.Errorf("send failed")} {
		ctl := &tstCtl{err: sendErr}
		c := NewController(nil, ctl)
		old := tstSession()
		old.Status.Connection.Upstreams = []*corev1.Session_Status_Connection_Upstream{tstUpstream("removed", 8080), tstUpstream("updated", 8081)}
		newSess := proto.Clone(old).(*corev1.Session)
		newSess.Status.Connection.Upstreams = []*corev1.Session_Status_Connection_Upstream{tstUpstream("added", 8082), tstUpstream("updated", 8083)}
		require.Nil(t, c.OnUpdate(t.Context(), newSess, old))
		require.Len(t, ctl.messages, 3)
		assert.Equal(t, []string{"session-uid", "session-uid", "session-uid"}, ctl.uids)
		added := ctl.messages[0].GetAddService().GetService()
		require.NotNil(t, added)
		assert.Equal(t, "added.default", added.Name)
		assert.Equal(t, uint32(8082), added.Port)
		assert.Equal(t, "10.0.0.1", added.Address.Ipv4)
		assert.Equal(t, "fd00::1", added.Address.Ipv6)
		assert.Equal(t, uint32(8083), ctl.messages[1].GetUpdateService().GetService().Port)
		assert.Equal(t, "removed.default", ctl.messages[2].GetDeleteService().Name)
	}
}

func TestSessionNoEvents(t *testing.T) {
	for _, mutate := range []func(*corev1.Session){
		func(s *corev1.Session) {},
		func(s *corev1.Session) { s.Metadata.Description = "metadata" },
		func(s *corev1.Session) { s.Status.Connection = nil },
		func(s *corev1.Session) { s.Status.TotalAuthentications++ },
		func(s *corev1.Session) { s.Status.Connection.L3Mode = corev1.Session_Status_Connection_V4 },
		func(s *corev1.Session) { s.Status.Type = corev1.Session_Status_CLIENTLESS },
	} {
		ctl := &tstCtl{}
		c := NewController(nil, ctl)
		old := tstSession()
		newSess := proto.Clone(old).(*corev1.Session)
		mutate(newSess)
		require.Nil(t, c.OnAdd(t.Context(), newSess))
		require.Nil(t, c.OnUpdate(t.Context(), newSess, old))
		assert.Empty(t, ctl.messages)
	}
	ctl := &tstCtl{}
	c := NewController(nil, ctl)
	old, newSess := tstSession(), tstSession()
	old.Status.Connection = nil
	require.Nil(t, c.OnUpdate(t.Context(), newSess, old))
	assert.Empty(t, ctl.messages)
}

func TestSessionDisconnectEvents(t *testing.T) {
	ctl := &tstCtl{}
	c := NewController(nil, ctl)
	old := tstSession()
	newSess := proto.Clone(old).(*corev1.Session)
	newSess.Status.IsConnected = false
	require.Nil(t, c.OnUpdate(t.Context(), newSess, old))
	require.Len(t, ctl.messages, 1)
	assert.NotNil(t, ctl.messages[0].GetDisconnect())
	assert.True(t, proto.Equal(newSess.Metadata.UpdatedAt, ctl.messages[0].CreatedAt))
	ctl.err = fmt.Errorf("send failed")
	assert.Nil(t, c.OnUpdate(t.Context(), newSess, old))
	assert.ErrorIs(t, c.OnDelete(t.Context(), old), ctl.err)
	assert.Nil(t, ctl.messages[len(ctl.messages)-1].CreatedAt)
	old.Status.Connection = nil
	assert.Nil(t, c.OnDelete(t.Context(), old))
	assert.Nil(t, c.doDelete(t.Context(), old))
	old.Status.Type = corev1.Session_Status_CLIENTLESS
	assert.Nil(t, c.OnDelete(t.Context(), old))
}
