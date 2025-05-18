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
	"fmt"

	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/pkg/apiutils/ucorev1"
	"github.com/octelium/octelium/pkg/apiutils/umetav1"
	"github.com/octelium/octelium/pkg/common/pbutils"
	"github.com/octelium/octelium/pkg/utils/utilrand"
	"github.com/pkg/errors"
	"go.etcd.io/bbolt"
	"go.uber.org/zap"
)

type Cache struct {
	db *bbolt.DB
}

func NewCache() (*Cache, error) {

	filename := fmt.Sprintf("/tmp/vigil-%s.db", utilrand.GetRandomStringLowercase(6))
	db, err := bbolt.Open(filename, 0600, nil)
	if err != nil {
		return nil, err
	}

	if err := db.Update(func(tx *bbolt.Tx) error {

		bucketNames := []string{
			"Service", "Session", "User",
			"Device", "Group",
			"Policy", "Namespace"}

		for _, bucketName := range bucketNames {
			_, err = tx.CreateBucketIfNotExists([]byte(bucketName))
			if err != nil {
				return err
			}
		}

		return nil
	}); err != nil {
		return nil, err
	}

	return &Cache{
		db: db,
	}, nil
}

var ErrNotFound = errors.New("Resource not found")
var SessionNotFound = errors.New("Session not found")

func (c *Cache) IsErrNotFound(err error) bool {
	return errors.Is(err, ErrNotFound)
}

func (c *Cache) setResource(key string, obj umetav1.ResourceObjectI, kind string) error {
	objBytes, err := pbutils.Marshal(obj)
	if err != nil {
		return err
	}

	zap.L().Debug("Setting resource",
		zap.String("kind", obj.GetKind()),
		zap.String("apiVersion", obj.GetApiVersion()),
		zap.String("uid", obj.GetMetadata().Uid),
		zap.String("key", key))

	if err := c.db.Update(func(tx *bbolt.Tx) error {

		b := tx.Bucket([]byte(kind))

		if key == "" {
			key = obj.GetMetadata().Uid
		}
		err := b.Put([]byte(key), objBytes)

		return err

	}); err != nil {
		return err
	}

	return nil
}

func (c *Cache) getResource(kind string, key string) (umetav1.ResourceObjectI, error) {
	if key == "" {
		return nil, ErrNotFound
	}

	rsc, err := func() (umetav1.ResourceObjectI, error) {
		switch kind {
		default:
			return ucorev1.NewObject(kind)

		}
	}()
	if err != nil {
		return nil, err
	}

	if err := c.db.View(func(tx *bbolt.Tx) error {
		b := tx.Bucket([]byte(kind))
		v := b.Get([]byte(key))
		if v == nil {
			return ErrNotFound
		}

		if err := pbutils.Unmarshal(v, rsc); err != nil {
			return err
		}

		return nil
	}); err != nil {
		return nil, err
	}
	return rsc, nil
}

func (c *Cache) deleteResource(kind string, key string) error {
	if err := c.db.Update(func(tx *bbolt.Tx) error {

		b := tx.Bucket([]byte(kind))

		err := b.Delete([]byte(key))

		return err

	}); err != nil {
		return err
	}
	return nil
}

func (c *Cache) SetUser(usr *corev1.User) error {
	return c.setResource("", usr, ucorev1.KindUser)
}

func (c *Cache) SetDevice(device *corev1.Device) error {
	return c.setResource("", device, ucorev1.KindDevice)
}

func (c *Cache) SetSession(sess *corev1.Session) error {
	return c.setSession(sess)
}

func (c *Cache) SetPolicy(p *corev1.Policy) error {
	if err := c.setResource("", p, ucorev1.KindPolicy); err != nil {
		return err
	}

	if err := c.setResource(p.Metadata.Name, p, ucorev1.KindPolicy); err != nil {
		return err
	}

	return nil
}

func (c *Cache) DeletePolicy(p *corev1.Policy) error {
	return c.deleteResource(ucorev1.KindPolicy, p.Metadata.Uid)
}

func (c *Cache) GetPolicy(uid string) (*corev1.Policy, error) {
	ret, err := c.getResource(ucorev1.KindPolicy, uid)
	if err != nil {
		return nil, err
	}
	return ret.(*corev1.Policy), nil
}

func (c *Cache) SetNamespace(p *corev1.Namespace) error {
	if err := c.setResource("", p, ucorev1.KindNamespace); err != nil {
		return err
	}

	if err := c.setResource(p.Metadata.Name, p, ucorev1.KindNamespace); err != nil {
		return err
	}

	return nil
}

func (c *Cache) DeleteNamespace(p *corev1.Namespace) error {
	return c.deleteResource(ucorev1.KindNamespace, p.Metadata.Uid)
}

func (c *Cache) GetNamespace(uid string) (*corev1.Namespace, error) {
	ret, err := c.getResource(ucorev1.KindNamespace, uid)
	if err != nil {
		return nil, err
	}
	return ret.(*corev1.Namespace), nil
}

func (c *Cache) SetGroup(group *corev1.Group) error {
	if err := c.setResource(group.Metadata.Uid, group, ucorev1.KindGroup); err != nil {
		return err
	}

	if err := c.setResource(group.Metadata.Name, group, ucorev1.KindGroup); err != nil {
		return err
	}

	return nil
}

func (c *Cache) DeleteGroup(group *corev1.Group) error {
	if err := c.deleteResource(ucorev1.KindGroup, group.Metadata.Uid); err != nil {
		return err
	}

	if err := c.deleteResource(ucorev1.KindGroup, group.Metadata.Name); err != nil {
		return err
	}

	return nil
}

func (c *Cache) GetGroup(key string) (*corev1.Group, error) {
	ret, err := c.getResource(ucorev1.KindGroup, key)
	if err != nil {
		return nil, err
	}
	return ret.(*corev1.Group), nil
}

func (c *Cache) GetUser(uid string) (*corev1.User, error) {
	ret, err := c.getResource(ucorev1.KindUser, uid)
	if err != nil {
		return nil, err
	}
	return ret.(*corev1.User), nil
}

func (c *Cache) GetDevice(uid string) (*corev1.Device, error) {
	ret, err := c.getResource(ucorev1.KindDevice, uid)
	if err != nil {
		return nil, err
	}
	return ret.(*corev1.Device), nil
}

func (c *Cache) GetSession(identifier string) (*corev1.Session, error) {
	ret, err := c.getResource(ucorev1.KindSession, identifier)
	if err != nil {
		return nil, err
	}
	return ret.(*corev1.Session), nil
}

func (c *Cache) DeleteUser(usr *corev1.User) error {
	return c.deleteResource(ucorev1.KindUser, usr.Metadata.Uid)
}

func (c *Cache) DeleteDevice(device *corev1.Device) error {
	return c.deleteResource(ucorev1.KindDevice, device.Metadata.Uid)
}

func (c *Cache) DeleteService(svc *corev1.Service) error {
	return c.deleteResource(ucorev1.KindService, svc.Metadata.Uid)
}

func (c *Cache) DeleteSession(sess *corev1.Session) error {

	if sess.Status.Connection != nil {
		for _, addr := range sess.Status.Connection.Addresses {
			if addr.V4 != "" {
				c.deleteResource(ucorev1.KindSession, umetav1.ToDualStackNetwork(addr).ToIP().Ipv4)
			}
			if addr.V6 != "" {
				c.deleteResource(ucorev1.KindSession, (umetav1.ToDualStackNetwork(addr).ToIP()).Ipv6)
			}
		}
	}

	if err := c.deleteResource(ucorev1.KindSession, sess.Metadata.Uid); err != nil {
		return err
	}

	if err := c.deleteResource(ucorev1.KindSession, sess.Metadata.Name); err != nil {
		return err
	}

	return nil
}

func (c *Cache) setSession(sess *corev1.Session) error {

	if sess.Status.Connection != nil {
		var keys []string
		for _, addr := range sess.Status.Connection.Addresses {
			if addr.V4 != "" {
				keys = append(keys, umetav1.ToDualStackNetwork(addr).ToIP().Ipv4)
			}
			if addr.V6 != "" {
				keys = append(keys, umetav1.ToDualStackNetwork(addr).ToIP().Ipv6)
			}
		}

		for _, key := range keys {
			if err := c.setResource(key, sess, ucorev1.KindSession); err != nil {
				zap.L().Error("Could not set Session resource in cache", zap.String("key", key), zap.Error(err))
			}
		}
	}

	if err := c.setResource(sess.Metadata.Uid, sess, ucorev1.KindSession); err != nil {
		zap.L().Error("Could not set Session resource in cache", zap.Error(err))
	}

	if err := c.setResource(sess.Metadata.Name, sess, ucorev1.KindSession); err != nil {
		zap.L().Error("Could not set Session resource in cache", zap.Error(err))
	}

	return nil
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

	usr, err := c.GetUser(sess.Status.UserRef.Uid)
	if err != nil && !errors.Is(err, ErrNotFound) {
		return nil, err
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

type DownstreamInfo struct {
	User    *corev1.User
	Device  *corev1.Device
	Session *corev1.Session
	Groups  []*corev1.Group
}

func (c *Cache) SetService(svc *corev1.Service) error {
	return c.setResource(svc.Metadata.Uid, svc, ucorev1.KindService)
}

func (c *Cache) GetService(identifier string) (*corev1.Service, error) {
	ret, err := c.getResource(ucorev1.KindService, identifier)
	if err != nil {
		return nil, err
	}
	return ret.(*corev1.Service), nil
}

func (c *Cache) Close() error {
	err := c.db.Close()
	return err
}
