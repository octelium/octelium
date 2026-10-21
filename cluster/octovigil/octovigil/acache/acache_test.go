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
	"sync"
	"testing"

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
