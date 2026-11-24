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

package acache

import (
	"context"
	"fmt"
	"reflect"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/apis/main/metav1"
	"github.com/octelium/octelium/cluster/apiserver/apiserver/admin"
	"github.com/octelium/octelium/cluster/apiserver/apiserver/user"
	"github.com/octelium/octelium/cluster/common/tests"
	"github.com/octelium/octelium/cluster/common/tests/tstuser"
	"github.com/octelium/octelium/pkg/apiutils/umetav1"
	"github.com/octelium/octelium/pkg/common/pbutils"
	"github.com/octelium/octelium/pkg/utils/utilrand"
	"github.com/stretchr/testify/assert"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/structpb"
)

func TestCache(t *testing.T) {

	ctx := context.Background()
	tst, err := tests.Initialize(nil)
	assert.Nil(t, err)
	t.Cleanup(func() {
		tst.Destroy()
	})

	adminSrv := admin.NewServer(&admin.Opts{
		OcteliumC:  tst.C.OcteliumC,
		IsEmbedded: true,
	})
	usrSrv := user.NewServer(tst.C.OcteliumC)

	grp, err := tst.C.OcteliumC.CoreC().CreateGroup(ctx, &corev1.Group{
		Metadata: &metav1.Metadata{
			Name: utilrand.GetRandomStringCanonical(8),
		},
		Spec: &corev1.Group_Spec{},
	})
	assert.Nil(t, err)

	usr, err := tstuser.NewUser(tst.C.OcteliumC, adminSrv, usrSrv, []string{grp.Metadata.Name})
	assert.Nil(t, err)

	c, err := NewCache()
	assert.Nil(t, err)
	defer c.Close()

	err = c.SetGroup(grp)
	assert.Nil(t, err)

	err = c.SetUser(usr.Usr)
	assert.Nil(t, err)

	usr.Connect()
	err = c.SetSession(usr.Session)
	assert.Nil(t, err)

	getAddrV4 := func(addr *metav1.DualStackNetwork) string {
		return umetav1.ToDualStackNetwork(addr).ToIP().Ipv4
	}
	getAddrV6 := func(addr *metav1.DualStackNetwork) string {
		return umetav1.ToDualStackNetwork(addr).ToIP().Ipv6
	}

	{
		di, err := c.GetDownstreamInfoBySessionIdentifier(getAddrV4(usr.Session.Status.Connection.Addresses[0]))
		assert.Nil(t, err)
		assert.True(t, pbutils.IsEqual(usr.Session, di.Session))
		assert.Equal(t, usr.Usr.Metadata.Uid, di.User.Metadata.Uid)
		assert.Equal(t, grp.Metadata.Uid, di.Groups[0].Metadata.Uid)
	}
	{
		di, err := c.GetDownstreamInfoBySessionIdentifier(getAddrV6(usr.Session.Status.Connection.Addresses[0]))
		assert.Nil(t, err)
		assert.True(t, pbutils.IsEqual(usr.Session, di.Session))
	}

	{
		webSess, err := usr.NewSessionWithType(corev1.Session_Status_CLIENTLESS)
		assert.Nil(t, err)
		c.SetSession(webSess)
		di, err := c.GetDownstreamInfoBySessionIdentifier(webSess.Metadata.Uid)
		assert.Nil(t, err)
		assert.True(t, pbutils.IsEqual(webSess, di.Session))
	}

}

func testResourceCache[T proto.Message](t *testing.T, original, updated T, keys []string,
	set func(T) error, get func(string) (T, error), del func(T) error) {
	t.Helper()
	for _, key := range keys {
		_, err := get(key)
		assert.ErrorIs(t, err, ErrNotFound)
	}
	assert.Nil(t, set(original))
	for _, key := range keys {
		value, err := get(key)
		assert.Nil(t, err)
		assert.True(t, proto.Equal(original, value))
	}
	assert.Nil(t, set(updated))
	for _, key := range keys {
		value, err := get(key)
		assert.Nil(t, err)
		assert.True(t, proto.Equal(updated, value))
	}
	assert.Nil(t, del(original))
	assert.Nil(t, del(updated))
	for _, key := range keys {
		_, err := get(key)
		assert.ErrorIs(t, err, ErrNotFound)
	}
	assert.Nil(t, set(updated))
	value, err := get(keys[0])
	assert.Nil(t, err)
	assert.True(t, proto.Equal(updated, value))
}

func TestResourceCacheLifecycle(t *testing.T) {
	c, err := NewCache()
	assert.Nil(t, err)
	t.Cleanup(func() { c.Close() })
	md := &metav1.Metadata{Uid: "uid", Name: "name"}
	updated := &metav1.Metadata{Uid: "uid", Name: "name", DisplayName: "updated"}
	t.Run("User", func(t *testing.T) {
		testResourceCache(t, &corev1.User{Metadata: md}, &corev1.User{Metadata: updated},
			[]string{"uid"}, c.SetUser, c.GetUser, c.DeleteUser)
	})
	t.Run("Device", func(t *testing.T) {
		testResourceCache(t, &corev1.Device{Metadata: md}, &corev1.Device{Metadata: updated},
			[]string{"uid"}, c.SetDevice, c.GetDevice, c.DeleteDevice)
	})
	t.Run("Service", func(t *testing.T) {
		testResourceCache(t, &corev1.Service{Metadata: md}, &corev1.Service{Metadata: updated},
			[]string{"uid"}, c.SetService, c.GetService, c.DeleteService)
	})
	t.Run("Group", func(t *testing.T) {
		testResourceCache(t, &corev1.Group{Metadata: md}, &corev1.Group{Metadata: updated},
			[]string{"uid", "name"}, c.SetGroup, c.GetGroup, c.DeleteGroup)
	})
	t.Run("Policy", func(t *testing.T) {
		testResourceCache(t, &corev1.Policy{Metadata: md}, &corev1.Policy{Metadata: updated},
			[]string{"uid", "name"}, c.SetPolicy, c.GetPolicy, c.DeletePolicy)
	})
	t.Run("Namespace", func(t *testing.T) {
		testResourceCache(t, &corev1.Namespace{Metadata: md}, &corev1.Namespace{Metadata: updated},
			[]string{"uid", "name"}, c.SetNamespace, c.GetNamespace, c.DeleteNamespace)
	})
	assert.True(t, c.IsErrNotFound(fmt.Errorf("lookup: %w", ErrNotFound)))
	assert.False(t, c.IsErrNotFound(nil))
	assert.False(t, c.IsErrNotFound(SessionNotFound))
}

func TestSessionCacheLifecycle(t *testing.T) {
	for _, mode := range []string{"IPv4", "IPv6", "DualStack"} {
		t.Run(mode, func(t *testing.T) {
			c, err := NewCache()
			assert.Nil(t, err)
			t.Cleanup(func() { c.Close() })
			sess := &corev1.Session{
				Metadata: &metav1.Metadata{Uid: "session-uid", Name: "session-name"},
				Status:   &corev1.Session_Status{},
			}
			assert.Nil(t, c.SetSession(sess))
			for _, key := range []string{"session-uid", "session-name"} {
				got, err := c.GetSession(key)
				assert.Nil(t, err)
				assert.True(t, proto.Equal(sess, got))
			}
			var keys []string
			connected := proto.Clone(sess).(*corev1.Session)
			connected.Status.Connection = &corev1.Session_Status_Connection{}
			for idx := range 2 {
				addr := &metav1.DualStackNetwork{}
				if mode != "IPv6" {
					addr.V4 = fmt.Sprintf("100.64.%d.2/32", idx)
					keys = append(keys, fmt.Sprintf("100.64.%d.2", idx))
				}
				if mode != "IPv4" {
					addr.V6 = fmt.Sprintf("fd00:%d::2/128", idx)
					keys = append(keys, fmt.Sprintf("fd00:%d::2", idx))
					if idx == 0 {
						keys[len(keys)-1] = "fd00::2"
					}
				}
				connected.Status.Connection.Addresses = append(connected.Status.Connection.Addresses, addr)
			}
			assert.Nil(t, c.SetSession(connected))
			for _, key := range keys {
				got, err := c.GetSession(key)
				assert.Nil(t, err)
				assert.True(t, proto.Equal(connected, got))
			}
			updated := proto.Clone(connected).(*corev1.Session)
			updated.Status.IsLocked = true
			assert.Nil(t, c.SetSession(updated))
			for _, key := range keys {
				got, err := c.GetSession(key)
				assert.Nil(t, err)
				assert.True(t, got.Status.IsLocked)
			}
			assert.Nil(t, c.SetSession(sess))
			for _, key := range keys {
				_, err := c.GetSession(key)
				assert.ErrorIs(t, err, ErrNotFound)
			}
			assert.Nil(t, c.SetSession(connected))
			assert.Nil(t, c.DeleteSession(sess))
			assert.Nil(t, c.DeleteSession(connected))
			for _, key := range append(keys, "session-uid", "session-name", "") {
				_, err := c.GetSession(key)
				assert.ErrorIs(t, err, ErrNotFound)
				info, err := c.GetDownstreamInfoBySessionIdentifier(key)
				assert.Nil(t, info)
				assert.ErrorIs(t, err, SessionNotFound)
			}
		})
	}
}

func TestDownstreamCacheDependencies(t *testing.T) {
	for _, mode := range []string{"Empty", "Missing", "PartialGroups", "Complete", "Deleted"} {
		t.Run(mode, func(t *testing.T) {
			c, err := NewCache()
			assert.Nil(t, err)
			t.Cleanup(func() { c.Close() })
			sess := &corev1.Session{Metadata: &metav1.Metadata{Uid: "session", Name: "session"}, Status: &corev1.Session_Status{}}
			user := &corev1.User{Metadata: &metav1.Metadata{Uid: "user"}, Spec: &corev1.User_Spec{Groups: []string{"first", "second", "missing"}}}
			device := &corev1.Device{Metadata: &metav1.Metadata{Uid: "device"}}
			first := &corev1.Group{Metadata: &metav1.Metadata{Uid: "first-uid", Name: "first"}}
			second := &corev1.Group{Metadata: &metav1.Metadata{Uid: "second-uid", Name: "second"}}
			if mode != "Empty" {
				sess.Status.UserRef = &metav1.ObjectReference{Uid: "user"}
				sess.Status.DeviceRef = &metav1.ObjectReference{Uid: "device"}
			}
			if mode == "PartialGroups" || mode == "Complete" || mode == "Deleted" {
				assert.Nil(t, c.SetUser(user))
				assert.Nil(t, c.SetDevice(device))
				assert.Nil(t, c.SetGroup(first))
			}
			if mode == "Complete" || mode == "Deleted" {
				assert.Nil(t, c.SetGroup(second))
			}
			if mode == "Deleted" {
				assert.Nil(t, c.DeleteUser(user))
				assert.Nil(t, c.DeleteDevice(device))
				assert.Nil(t, c.DeleteGroup(first))
				assert.Nil(t, c.DeleteGroup(second))
			}
			assert.Nil(t, c.SetSession(sess))
			info, err := c.GetDownstreamInfoBySessionIdentifier("session")
			if !assert.Nil(t, err) {
				return
			}
			assert.Same(t, sess, info.Session)
			if mode == "PartialGroups" || mode == "Complete" {
				assert.Same(t, user, info.User)
				assert.Same(t, device, info.Device)
				if mode == "Complete" {
					assert.Equal(t, []*corev1.Group{first, second}, info.Groups)
				} else {
					assert.Equal(t, []*corev1.Group{first}, info.Groups)
				}
			} else {
				assert.Nil(t, info.User)
				assert.Nil(t, info.Device)
				assert.Empty(t, info.Groups)
			}
		})
	}
}

func TestCacheConcurrentSessions(t *testing.T) {
	c, err := NewCache()
	assert.Nil(t, err)
	t.Cleanup(func() { c.Close() })
	var wg sync.WaitGroup
	for idx := range 32 {
		wg.Go(func() {
			sess := &corev1.Session{
				Metadata: &metav1.Metadata{Uid: fmt.Sprintf("uid-%d", idx), Name: fmt.Sprintf("name-%d", idx)},
				Status: &corev1.Session_Status{Connection: &corev1.Session_Status_Connection{
					Addresses: []*metav1.DualStackNetwork{{V4: fmt.Sprintf("100.64.0.%d/32", idx+1)}},
				}},
			}
			for range 64 {
				assert.Nil(t, c.SetSession(sess))
				for _, key := range []string{sess.Metadata.Uid, sess.Metadata.Name, fmt.Sprintf("100.64.0.%d", idx+1)} {
					got, err := c.GetSession(key)
					assert.Nil(t, err)
					assert.Same(t, sess, got)
				}
				assert.Nil(t, c.DeleteSession(sess))
			}
		})
	}
	wg.Wait()
	assert.Empty(t, c.sessions.m)
	assert.Empty(t, c.sessions.ipKeys)
}

func TestCacheConcurrentResources(t *testing.T) {
	c, err := NewCache()
	assert.Nil(t, err)
	t.Cleanup(func() { c.Close() })
	var wg sync.WaitGroup
	for idx := range 32 {
		wg.Go(func() {
			uid := fmt.Sprintf("uid-%d", idx%4)
			name := fmt.Sprintf("name-%d", idx%4)
			md := &metav1.Metadata{Uid: uid, Name: name, DisplayName: fmt.Sprintf("writer-%d", idx)}
			user := &corev1.User{Metadata: md, Spec: &corev1.User_Spec{IsDisabled: idx%2 == 0}}
			group := &corev1.Group{Metadata: md}
			policy := &corev1.Policy{Metadata: md, Spec: &corev1.Policy_Spec{IsDisabled: idx%2 == 0}}
			for range 32 {
				assert.Nil(t, c.SetUser(user))
				assert.Nil(t, c.SetGroup(group))
				assert.Nil(t, c.SetPolicy(policy))
				gotUser, err := c.GetUser(uid)
				if err == nil {
					assert.Equal(t, uid, gotUser.Metadata.Uid)
				} else {
					assert.ErrorIs(t, err, ErrNotFound)
				}
				gotGroup, err := c.GetGroup(name)
				if err == nil {
					assert.Equal(t, uid, gotGroup.Metadata.Uid)
				} else {
					assert.ErrorIs(t, err, ErrNotFound)
				}
				gotPolicy, err := c.GetPolicy(name)
				if err == nil {
					assert.Equal(t, uid, gotPolicy.Metadata.Uid)
				} else {
					assert.ErrorIs(t, err, ErrNotFound)
				}
				assert.Nil(t, c.DeleteUser(user))
				assert.Nil(t, c.DeleteGroup(group))
				assert.Nil(t, c.DeletePolicy(policy))
			}
		})
	}
	wg.Wait()
	for idx := range 4 {
		uid := fmt.Sprintf("uid-%d", idx)
		name := fmt.Sprintf("name-%d", idx)
		_, err := c.GetUser(uid)
		assert.ErrorIs(t, err, ErrNotFound)
		for _, key := range []string{uid, name} {
			_, err := c.GetGroup(key)
			assert.ErrorIs(t, err, ErrNotFound)
			_, err = c.GetPolicy(key)
			assert.ErrorIs(t, err, ErrNotFound)
		}
	}
}

func isSameMap(a, b map[string]any) bool {
	return reflect.ValueOf(a).UnsafePointer() == reflect.ValueOf(b).UnsafePointer()
}

type testResourceMapOpts[T proto.Message] struct {
	original T
	updated  T
	invalid  T
	set      func(T) error
	del      func(T) error
	getMap   func(T) (map[string]any, error)
	convert  func(T) proto.Message
	mutate   func(T)
}

func testResourceMap[T proto.Message](t *testing.T, c *Cache, o *testResourceMapOpts[T]) {
	t.Helper()

	getMap := func(val T) map[string]any {
		t.Helper()
		exp, err := pbutils.ConvertToMap(o.convert(val))
		assert.Nil(t, err)
		ret, err := o.getMap(val)
		assert.Nil(t, err)
		assert.Equal(t, exp, ret)
		return ret
	}

	first := getMap(o.original)
	assert.False(t, isSameMap(first, getMap(o.original)))
	assert.Equal(t, 0, c.maps.Len())

	assert.Nil(t, o.set(o.original))
	first = getMap(o.original)
	assert.True(t, isSameMap(first, getMap(o.original)))
	assert.Equal(t, 1, c.maps.Len())

	clone := proto.Clone(o.original).(T)
	assert.False(t, isSameMap(first, getMap(clone)))
	assert.Equal(t, 1, c.maps.Len())

	assert.Nil(t, o.set(o.updated))
	assert.Equal(t, 0, c.maps.Len())
	assert.False(t, isSameMap(first, getMap(o.original)))
	second := getMap(o.updated)
	assert.NotEqual(t, first, second)
	assert.True(t, isSameMap(second, getMap(o.updated)))
	assert.Equal(t, 1, c.maps.Len())

	o.mutate(o.updated)
	assert.Nil(t, o.set(o.updated))
	assert.Equal(t, 0, c.maps.Len())
	third := getMap(o.updated)
	assert.NotEqual(t, second, third)
	assert.True(t, isSameMap(third, getMap(o.updated)))

	assert.Nil(t, o.del(proto.Clone(o.updated).(T)))
	assert.Equal(t, 0, c.maps.Len())
	assert.False(t, isSameMap(third, getMap(o.updated)))
	assert.Equal(t, 0, c.maps.Len())

	assert.Nil(t, o.set(o.updated))
	third = getMap(o.updated)
	assert.Nil(t, o.del(o.updated))
	assert.Equal(t, 0, c.maps.Len())
	assert.False(t, isSameMap(third, getMap(o.updated)))

	var zero T
	getMap(zero)
	assert.Nil(t, o.set(o.original))
	getMap(zero)
	assert.Equal(t, 0, c.maps.Len())
	assert.Nil(t, o.del(o.original))

	_, expErr := pbutils.ConvertToMap(o.convert(o.invalid))
	assert.NotNil(t, expErr)
	assert.Nil(t, o.set(o.invalid))
	for range 2 {
		ret, err := o.getMap(o.invalid)
		assert.Nil(t, ret)
		assert.Equal(t, expErr.Error(), err.Error())
	}
	assert.Equal(t, 0, c.maps.Len())
	assert.Nil(t, o.del(o.invalid))
}

func TestResourceMaps(t *testing.T) {
	md := func(displayName string) *metav1.Metadata {
		return &metav1.Metadata{Uid: "uid", Name: "name", DisplayName: displayName}
	}
	identity := func(val proto.Message) proto.Message {
		return val
	}
	invalid := "invalid-\xff"

	t.Run("User", func(t *testing.T) {
		c, err := NewCache()
		assert.Nil(t, err)
		t.Cleanup(func() { c.Close() })
		testResourceMap(t, c, &testResourceMapOpts[*corev1.User]{
			original: &corev1.User{Metadata: md("original"), Spec: &corev1.User_Spec{Groups: []string{"group"}}},
			updated:  &corev1.User{Metadata: md("updated"), Status: &corev1.User_Status{IsLocked: true}},
			invalid:  &corev1.User{Metadata: md(invalid)},
			set:      c.SetUser,
			del:      c.DeleteUser,
			getMap:   c.GetUserMap,
			convert:  func(val *corev1.User) proto.Message { return identity(val) },
			mutate:   func(val *corev1.User) { val.Metadata.DisplayName = "mutated" },
		})
	})

	t.Run("Device", func(t *testing.T) {
		c, err := NewCache()
		assert.Nil(t, err)
		t.Cleanup(func() { c.Close() })
		testResourceMap(t, c, &testResourceMapOpts[*corev1.Device]{
			original: &corev1.Device{Metadata: md("original"), Spec: &corev1.Device_Spec{State: corev1.Device_Spec_ACTIVE}},
			updated:  &corev1.Device{Metadata: md("updated"), Status: &corev1.Device_Status{SerialNumber: "serial"}},
			invalid:  &corev1.Device{Metadata: md("invalid"), Status: &corev1.Device_Status{SerialNumber: invalid}},
			set:      c.SetDevice,
			del:      c.DeleteDevice,
			getMap:   c.GetDeviceMap,
			convert:  func(val *corev1.Device) proto.Message { return identity(val) },
			mutate:   func(val *corev1.Device) { val.Status.SerialNumber = "mutated" },
		})
	})

	t.Run("Service", func(t *testing.T) {
		c, err := NewCache()
		assert.Nil(t, err)
		t.Cleanup(func() { c.Close() })
		testResourceMap(t, c, &testResourceMapOpts[*corev1.Service]{
			original: &corev1.Service{Metadata: md("original"), Spec: &corev1.Service_Spec{Port: 8080}},
			updated:  &corev1.Service{Metadata: md("updated"), Spec: &corev1.Service_Spec{IsPublic: true}},
			invalid:  &corev1.Service{Metadata: md(invalid)},
			set:      c.SetService,
			del:      c.DeleteService,
			getMap:   c.GetServiceMap,
			convert:  func(val *corev1.Service) proto.Message { return identity(val) },
			mutate:   func(val *corev1.Service) { val.Spec.IsAnonymous = true },
		})
	})

	t.Run("Group", func(t *testing.T) {
		c, err := NewCache()
		assert.Nil(t, err)
		t.Cleanup(func() { c.Close() })
		testResourceMap(t, c, &testResourceMapOpts[*corev1.Group]{
			original: &corev1.Group{Metadata: md("original"), Spec: &corev1.Group_Spec{}},
			updated:  &corev1.Group{Metadata: md("updated"), Spec: &corev1.Group_Spec{Authorization: &corev1.Group_Spec_Authorization{Policies: []string{"policy"}}}},
			invalid:  &corev1.Group{Metadata: md(invalid)},
			set:      c.SetGroup,
			del:      c.DeleteGroup,
			getMap:   c.GetGroupMap,
			convert:  func(val *corev1.Group) proto.Message { return identity(val) },
			mutate: func(val *corev1.Group) {
				val.Spec.Authorization.Policies = append(val.Spec.Authorization.Policies, "mutated")
			},
		})
	})

	t.Run("Namespace", func(t *testing.T) {
		c, err := NewCache()
		assert.Nil(t, err)
		t.Cleanup(func() { c.Close() })
		testResourceMap(t, c, &testResourceMapOpts[*corev1.Namespace]{
			original: &corev1.Namespace{Metadata: md("original"), Spec: &corev1.Namespace_Spec{}},
			updated:  &corev1.Namespace{Metadata: md("updated"), Status: &corev1.Namespace_Status{}},
			invalid:  &corev1.Namespace{Metadata: md(invalid)},
			set:      c.SetNamespace,
			del:      c.DeleteNamespace,
			getMap:   c.GetNamespaceMap,
			convert:  func(val *corev1.Namespace) proto.Message { return identity(val) },
			mutate:   func(val *corev1.Namespace) { val.Metadata.Description = "mutated" },
		})
	})

	t.Run("Session", func(t *testing.T) {
		c, err := NewCache()
		assert.Nil(t, err)
		t.Cleanup(func() { c.Close() })
		testResourceMap(t, c, &testResourceMapOpts[*corev1.Session]{
			original: &corev1.Session{Metadata: md("original"), Status: &corev1.Session_Status{
				Connection: &corev1.Session_Status_Connection{
					Addresses: []*metav1.DualStackNetwork{{V4: "100.64.0.2/32", V6: "fd00::2/128"}},
				},
			}},
			updated: &corev1.Session{Metadata: md("updated"), Spec: &corev1.Session_Spec{State: corev1.Session_Spec_ACTIVE},
				Status: &corev1.Session_Status{Type: corev1.Session_Status_CLIENTLESS}},
			invalid: &corev1.Session{Metadata: md(invalid), Status: &corev1.Session_Status{}},
			set:     c.SetSession,
			del:     c.DeleteSession,
			getMap:  c.GetSessionMap,
			convert: func(val *corev1.Session) proto.Message { return identity(val) },
			mutate:  func(val *corev1.Session) { val.Status.IsLocked = true },
		})
	})

	t.Run("PolicyAttrs", func(t *testing.T) {
		c, err := NewCache()
		assert.Nil(t, err)
		t.Cleanup(func() { c.Close() })
		testResourceMap(t, c, &testResourceMapOpts[*corev1.Policy]{
			original: &corev1.Policy{Metadata: md("original"), Spec: &corev1.Policy_Spec{}},
			updated: &corev1.Policy{Metadata: md("updated"), Spec: &corev1.Policy_Spec{
				Attrs: &structpb.Struct{Fields: map[string]*structpb.Value{
					"key":  structpb.NewStringValue("value"),
					"list": structpb.NewListValue(&structpb.ListValue{Values: []*structpb.Value{structpb.NewNumberValue(1)}}),
				}},
			}},
			invalid: &corev1.Policy{Metadata: md("invalid"), Spec: &corev1.Policy_Spec{
				Attrs: &structpb.Struct{Fields: map[string]*structpb.Value{"key": structpb.NewStringValue(invalid)}},
			}},
			set:     c.SetPolicy,
			del:     c.DeletePolicy,
			getMap:  c.GetPolicyAttrsMap,
			convert: func(val *corev1.Policy) proto.Message { return val.GetSpec().GetAttrs() },
			mutate:  func(val *corev1.Policy) { val.Spec.Attrs.Fields["key"] = structpb.NewBoolValue(true) },
		})
	})
}

func TestResourceMapsCacheKeys(t *testing.T) {
	c, err := NewCache()
	assert.Nil(t, err)
	t.Cleanup(func() { c.Close() })

	grp := &corev1.Group{Metadata: &metav1.Metadata{Uid: "uid", Name: "name"}}
	renamed := &corev1.Group{Metadata: &metav1.Metadata{Uid: "uid", Name: "renamed"}}
	other := &corev1.Group{Metadata: &metav1.Metadata{Uid: "other", Name: "name"}}

	assert.Nil(t, c.SetGroup(grp))
	grpMap, err := c.GetGroupMap(grp)
	assert.Nil(t, err)
	assert.Equal(t, 1, c.maps.Len())

	assert.Nil(t, c.SetGroup(other))
	assert.Equal(t, 0, c.maps.Len())
	ret, err := c.GetGroupMap(grp)
	assert.Nil(t, err)
	assert.False(t, isSameMap(grpMap, ret))
	assert.Equal(t, grpMap, ret)
	assert.Equal(t, 1, c.maps.Len())

	assert.Nil(t, c.SetGroup(renamed))
	assert.Equal(t, 0, c.maps.Len())
	ret, err = c.GetGroupMap(grp)
	assert.Nil(t, err)
	assert.Equal(t, grpMap, ret)
	assert.Equal(t, 0, c.maps.Len())
	renamedMap, err := c.GetGroupMap(renamed)
	assert.Nil(t, err)
	otherMap, err := c.GetGroupMap(other)
	assert.Nil(t, err)
	assert.Equal(t, 2, c.maps.Len())

	assert.Nil(t, c.DeleteGroup(renamed))
	assert.Equal(t, 1, c.maps.Len())
	ret, err = c.GetGroupMap(other)
	assert.Nil(t, err)
	assert.True(t, isSameMap(otherMap, ret))
	ret, err = c.GetGroupMap(renamed)
	assert.Nil(t, err)
	assert.False(t, isSameMap(renamedMap, ret))
	assert.Equal(t, renamedMap, ret)

	assert.Nil(t, c.DeleteGroup(other))
	assert.Equal(t, 0, c.maps.Len())

	sess := &corev1.Session{Metadata: &metav1.Metadata{Uid: "session-uid", Name: "session-name"}, Status: &corev1.Session_Status{}}
	assert.Nil(t, c.SetSession(sess))
	sessMap, err := c.GetSessionMap(sess)
	assert.Nil(t, err)
	assert.Equal(t, 1, c.maps.Len())
	ret, err = c.GetSessionMap(sess)
	assert.Nil(t, err)
	assert.True(t, isSameMap(sessMap, ret))

	byName := &corev1.Session{Metadata: &metav1.Metadata{Uid: "", Name: "session-name"}, Status: &corev1.Session_Status{}}
	ret, err = c.GetSessionMap(byName)
	assert.Nil(t, err)
	exp, err := pbutils.ConvertToMap(byName)
	assert.Nil(t, err)
	assert.Equal(t, exp, ret)
	assert.Equal(t, 1, c.maps.Len())

	assert.Nil(t, c.DeleteSession(proto.Clone(sess).(*corev1.Session)))
	assert.Equal(t, 0, c.maps.Len())
}

func TestResourceMapsExpiration(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		c, err := NewCache()
		assert.Nil(t, err)
		defer c.Close()

		usr := &corev1.User{Metadata: &metav1.Metadata{Uid: "uid", Name: "name"}}
		assert.Nil(t, c.SetUser(usr))

		first, err := c.GetUserMap(usr)
		assert.Nil(t, err)

		time.Sleep(mapTTL - time.Second)
		ret, err := c.GetUserMap(usr)
		assert.Nil(t, err)
		assert.True(t, isSameMap(first, ret))

		time.Sleep(2 * time.Second)
		ret, err = c.GetUserMap(usr)
		assert.Nil(t, err)
		assert.False(t, isSameMap(first, ret))
		assert.Equal(t, first, ret)

		second, err := c.GetUserMap(usr)
		assert.Nil(t, err)
		assert.True(t, isSameMap(ret, second))
		assert.Equal(t, 1, c.maps.Len())

		time.Sleep(3 * mapTTL)
		synctest.Wait()
		assert.Equal(t, 0, c.maps.Len())
	})
}

func TestResourceMapsConcurrent(t *testing.T) {
	c, err := NewCache()
	assert.Nil(t, err)
	t.Cleanup(func() { c.Close() })

	requireMap := func(val proto.Message, ret map[string]any, err error) {
		exp, expErr := pbutils.ConvertToMap(val)
		assert.Nil(t, expErr)
		assert.Nil(t, err)
		assert.Equal(t, exp, ret)
	}

	var wg sync.WaitGroup
	for idx := range 16 {
		wg.Go(func() {
			for itr := range 64 {
				md := &metav1.Metadata{
					Uid:         fmt.Sprintf("uid-%d", idx%4),
					Name:        fmt.Sprintf("name-%d", idx%4),
					DisplayName: fmt.Sprintf("writer-%d-%d", idx, itr),
				}
				usr := &corev1.User{Metadata: md}
				grp := &corev1.Group{Metadata: md}
				sess := &corev1.Session{Metadata: md, Status: &corev1.Session_Status{}}
				policy := &corev1.Policy{Metadata: md, Spec: &corev1.Policy_Spec{
					Attrs: &structpb.Struct{Fields: map[string]*structpb.Value{"writer": structpb.NewStringValue(md.DisplayName)}},
				}}

				assert.Nil(t, c.SetUser(usr))
				assert.Nil(t, c.SetGroup(grp))
				assert.Nil(t, c.SetSession(sess))
				assert.Nil(t, c.SetPolicy(policy))

				for range 4 {
					ret, err := c.GetUserMap(usr)
					requireMap(usr, ret, err)
					ret, err = c.GetGroupMap(grp)
					requireMap(grp, ret, err)
					ret, err = c.GetSessionMap(sess)
					requireMap(sess, ret, err)
					ret, err = c.GetPolicyAttrsMap(policy)
					requireMap(policy.Spec.Attrs, ret, err)
				}

				if itr%2 == 0 {
					assert.Nil(t, c.DeleteUser(usr))
					assert.Nil(t, c.DeleteGroup(grp))
					assert.Nil(t, c.DeleteSession(sess))
					assert.Nil(t, c.DeletePolicy(policy))
				}
			}
		})
	}
	wg.Wait()
}
