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
	"sync"
	"time"

	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/cluster/common/cache"
	"github.com/octelium/octelium/pkg/apiutils/umetav1"
	"github.com/octelium/octelium/pkg/common/pbutils"
	"github.com/pkg/errors"
	"google.golang.org/protobuf/proto"
)

var ErrNotFound = errors.New("Resource not found")
var SessionNotFound = errors.New("Session not found")

const mapTTL = 1 * time.Minute

type Cache struct {
	users      keyedStore[*corev1.User]
	devices    keyedStore[*corev1.Device]
	services   keyedStore[*corev1.Service]
	groups     keyedStore[*corev1.Group]
	policies   keyedStore[*corev1.Policy]
	namespaces keyedStore[*corev1.Namespace]
	sessions   sessionStore
	maps       *cache.Cache[proto.Message, map[string]any]
}

type keyedStore[T any] struct {
	sync.RWMutex
	m map[string]T
}

func newKeyedStore[T any]() keyedStore[T] {
	return keyedStore[T]{m: make(map[string]T)}
}

func (s *keyedStore[T]) get(key string) (T, bool) {
	s.RLock()
	v, ok := s.m[key]
	s.RUnlock()
	return v, ok
}

func (s *keyedStore[T]) set(keys []string, val T) []T {
	ret := []T{val}
	s.Lock()
	for _, k := range keys {
		if old, ok := s.m[k]; ok {
			ret = append(ret, old)
		}
		s.m[k] = val
	}
	s.Unlock()
	return ret
}

func (s *keyedStore[T]) del(keys []string, val T) []T {
	ret := []T{val}
	s.Lock()
	for _, k := range keys {
		if old, ok := s.m[k]; ok {
			ret = append(ret, old)
		}
		delete(s.m, k)
	}
	s.Unlock()
	return ret
}

type sessionStore struct {
	sync.RWMutex
	m      map[string]*corev1.Session
	ipKeys map[string][]string
}

func NewCache() (*Cache, error) {
	return &Cache{
		users:      newKeyedStore[*corev1.User](),
		devices:    newKeyedStore[*corev1.Device](),
		services:   newKeyedStore[*corev1.Service](),
		groups:     newKeyedStore[*corev1.Group](),
		policies:   newKeyedStore[*corev1.Policy](),
		namespaces: newKeyedStore[*corev1.Namespace](),
		sessions: sessionStore{
			m:      make(map[string]*corev1.Session),
			ipKeys: make(map[string][]string),
		},
		maps: cache.New(&cache.Opts[proto.Message, map[string]any]{
			DefaultTTL: mapTTL,
		}),
	}, nil
}

func (c *Cache) IsErrNotFound(err error) bool {
	return errors.Is(err, ErrNotFound)
}

func (c *Cache) Close() error {
	c.maps.Close()
	return nil
}

func (c *Cache) SetUser(usr *corev1.User) error {
	deleteMaps(c, c.users.set([]string{usr.Metadata.Uid}, usr))
	return nil
}

func (c *Cache) GetUser(uid string) (*corev1.User, error) {
	v, ok := c.users.get(uid)
	if !ok {
		return nil, ErrNotFound
	}
	return v, nil
}

func (c *Cache) DeleteUser(usr *corev1.User) error {
	deleteMaps(c, c.users.del([]string{usr.Metadata.Uid}, usr))
	return nil
}

func (c *Cache) SetDevice(device *corev1.Device) error {
	deleteMaps(c, c.devices.set([]string{device.Metadata.Uid}, device))
	return nil
}

func (c *Cache) GetDevice(uid string) (*corev1.Device, error) {
	v, ok := c.devices.get(uid)
	if !ok {
		return nil, ErrNotFound
	}
	return v, nil
}

func (c *Cache) DeleteDevice(device *corev1.Device) error {
	deleteMaps(c, c.devices.del([]string{device.Metadata.Uid}, device))
	return nil
}

func (c *Cache) SetService(svc *corev1.Service) error {
	deleteMaps(c, c.services.set([]string{svc.Metadata.Uid}, svc))
	return nil
}

func (c *Cache) GetService(identifier string) (*corev1.Service, error) {
	v, ok := c.services.get(identifier)
	if !ok {
		return nil, ErrNotFound
	}
	return v, nil
}

func (c *Cache) DeleteService(svc *corev1.Service) error {
	deleteMaps(c, c.services.del([]string{svc.Metadata.Uid}, svc))
	return nil
}

func (c *Cache) SetGroup(group *corev1.Group) error {
	deleteMaps(c, c.groups.set([]string{group.Metadata.Uid, group.Metadata.Name}, group))
	return nil
}

func (c *Cache) GetGroup(key string) (*corev1.Group, error) {
	v, ok := c.groups.get(key)
	if !ok {
		return nil, ErrNotFound
	}
	return v, nil
}

func (c *Cache) DeleteGroup(group *corev1.Group) error {
	deleteMaps(c, c.groups.del([]string{group.Metadata.Uid, group.Metadata.Name}, group))
	return nil
}

func (c *Cache) SetPolicy(p *corev1.Policy) error {
	deleteMaps(c, c.policies.set([]string{p.Metadata.Uid, p.Metadata.Name}, p))
	return nil
}

func (c *Cache) GetPolicy(key string) (*corev1.Policy, error) {
	v, ok := c.policies.get(key)
	if !ok {
		return nil, ErrNotFound
	}
	return v, nil
}

func (c *Cache) DeletePolicy(p *corev1.Policy) error {
	deleteMaps(c, c.policies.del([]string{p.Metadata.Uid, p.Metadata.Name}, p))
	return nil
}

func (c *Cache) SetNamespace(ns *corev1.Namespace) error {
	deleteMaps(c, c.namespaces.set([]string{ns.Metadata.Uid, ns.Metadata.Name}, ns))
	return nil
}

func (c *Cache) GetNamespace(key string) (*corev1.Namespace, error) {
	v, ok := c.namespaces.get(key)
	if !ok {
		return nil, ErrNotFound
	}
	return v, nil
}

func (c *Cache) DeleteNamespace(ns *corev1.Namespace) error {
	deleteMaps(c, c.namespaces.del([]string{ns.Metadata.Uid, ns.Metadata.Name}, ns))
	return nil
}

func (c *Cache) SetSession(sess *corev1.Session) error {
	c.sessions.Lock()
	defer c.sessions.Unlock()

	uid := sess.Metadata.Uid

	deleteMaps(c, []*corev1.Session{sess, c.sessions.m[uid]})

	if oldIPKeys, ok := c.sessions.ipKeys[uid]; ok {
		for _, key := range oldIPKeys {
			delete(c.sessions.m, key)
		}
	}

	var newIPKeys []string
	if sess.Status.Connection != nil {
		for _, addr := range sess.Status.Connection.Addresses {
			if addr.V4 != "" {
				ipKey := umetav1.ToDualStackNetwork(addr).ToIP().Ipv4
				c.sessions.m[ipKey] = sess
				newIPKeys = append(newIPKeys, ipKey)
			}
			if addr.V6 != "" {
				ipKey := umetav1.ToDualStackNetwork(addr).ToIP().Ipv6
				c.sessions.m[ipKey] = sess
				newIPKeys = append(newIPKeys, ipKey)
			}
		}
	}

	if len(newIPKeys) > 0 {
		c.sessions.ipKeys[uid] = newIPKeys
	} else {
		delete(c.sessions.ipKeys, uid)
	}

	c.sessions.m[uid] = sess
	c.sessions.m[sess.Metadata.Name] = sess

	return nil
}

func (c *Cache) GetSession(identifier string) (*corev1.Session, error) {
	if identifier == "" {
		return nil, ErrNotFound
	}
	c.sessions.RLock()
	v, ok := c.sessions.m[identifier]
	c.sessions.RUnlock()
	if !ok {
		return nil, ErrNotFound
	}
	return v, nil
}

func (c *Cache) DeleteSession(sess *corev1.Session) error {
	c.sessions.Lock()
	defer c.sessions.Unlock()

	uid := sess.Metadata.Uid

	deleteMaps(c, []*corev1.Session{sess, c.sessions.m[uid]})

	if oldIPKeys, ok := c.sessions.ipKeys[uid]; ok {
		for _, key := range oldIPKeys {
			delete(c.sessions.m, key)
		}
		delete(c.sessions.ipKeys, uid)
	}

	if sess.Status.Connection != nil {
		for _, addr := range sess.Status.Connection.Addresses {
			if addr.V4 != "" {
				delete(c.sessions.m, umetav1.ToDualStackNetwork(addr).ToIP().Ipv4)
			}
			if addr.V6 != "" {
				delete(c.sessions.m, umetav1.ToDualStackNetwork(addr).ToIP().Ipv6)
			}
		}
	}

	delete(c.sessions.m, uid)
	delete(c.sessions.m, sess.Metadata.Name)

	return nil
}

func (c *Cache) GetUserMap(usr *corev1.User) (map[string]any, error) {
	cur, _ := c.users.get(usr.GetMetadata().GetUid())
	return c.getMap(usr, usr, usr != nil && cur == usr)
}

func (c *Cache) GetDeviceMap(device *corev1.Device) (map[string]any, error) {
	cur, _ := c.devices.get(device.GetMetadata().GetUid())
	return c.getMap(device, device, device != nil && cur == device)
}

func (c *Cache) GetServiceMap(svc *corev1.Service) (map[string]any, error) {
	cur, _ := c.services.get(svc.GetMetadata().GetUid())
	return c.getMap(svc, svc, svc != nil && cur == svc)
}

func (c *Cache) GetGroupMap(group *corev1.Group) (map[string]any, error) {
	cur, _ := c.groups.get(group.GetMetadata().GetUid())
	return c.getMap(group, group, group != nil && cur == group)
}

func (c *Cache) GetNamespaceMap(ns *corev1.Namespace) (map[string]any, error) {
	cur, _ := c.namespaces.get(ns.GetMetadata().GetUid())
	return c.getMap(ns, ns, ns != nil && cur == ns)
}

func (c *Cache) GetSessionMap(sess *corev1.Session) (map[string]any, error) {
	cur, _ := c.GetSession(sess.GetMetadata().GetUid())
	return c.getMap(sess, sess, sess != nil && cur == sess)
}

func (c *Cache) GetPolicyAttrsMap(p *corev1.Policy) (map[string]any, error) {
	cur, _ := c.policies.get(p.GetMetadata().GetUid())
	return c.getMap(p, p.GetSpec().GetAttrs(), p != nil && cur == p)
}

func (c *Cache) getMap(key proto.Message, val proto.Message, isCached bool) (map[string]any, error) {
	if !isCached {
		return pbutils.ConvertToMap(val)
	}

	if ret, ok := c.maps.Get(key); ok {
		return ret, nil
	}

	ret, err := pbutils.ConvertToMap(val)
	if err != nil {
		return nil, err
	}

	c.maps.Set(key, ret)

	return ret, nil
}

func deleteMaps[T proto.Message](c *Cache, vals []T) {
	for _, val := range vals {
		c.maps.Delete(val)
	}
}

type DownstreamInfo struct {
	User    *corev1.User
	Device  *corev1.Device
	Session *corev1.Session
	Groups  []*corev1.Group
}

func (c *Cache) GetDownstreamInfoBySessionIdentifier(arg string) (*DownstreamInfo, error) {
	if arg == "" {
		return nil, SessionNotFound
	}

	sess, err := c.GetSession(arg)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			return nil, SessionNotFound
		}
		return nil, err
	}

	return c.GetDownstreamInfo(sess)
}

func (c *Cache) GetDownstreamInfo(sess *corev1.Session) (*DownstreamInfo, error) {
	var err error
	var usr *corev1.User
	if sess.Status.UserRef != nil {
		usr, err = c.GetUser(sess.Status.UserRef.Uid)
		if err != nil && !errors.Is(err, ErrNotFound) {
			return nil, err
		}
	}

	ret := &DownstreamInfo{
		Session: sess,
		User:    usr,
	}

	if sess.Status.DeviceRef != nil {
		ret.Device, err = c.GetDevice(sess.Status.DeviceRef.Uid)
		if err != nil && !errors.Is(err, ErrNotFound) {
			return nil, err
		}
	}

	if usr != nil {
		for _, g := range usr.Spec.Groups {
			grp, err := c.GetGroup(g)
			if err != nil && !errors.Is(err, ErrNotFound) {
				return nil, err
			}
			if grp != nil {
				ret.Groups = append(ret.Groups, grp)
			}
		}
	}

	return ret, nil
}
