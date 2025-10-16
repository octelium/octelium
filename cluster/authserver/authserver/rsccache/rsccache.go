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

package rsccache

import (
	"crypto/sha256"
	"fmt"

	"github.com/google/uuid"
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

	filename := fmt.Sprintf("/tmp/rsc-cache-%s.db", utilrand.GetRandomStringLowercase(6))
	db, err := bbolt.Open(filename, 0600, nil)
	if err != nil {
		return nil, err
	}

	if err := db.Update(func(tx *bbolt.Tx) error {

		bucketNames := []string{
			ucorev1.KindUser, ucorev1.KindAuthenticator, "count"}

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

func (c *Cache) setResource(key []byte, obj umetav1.ResourceObjectI, kind string) error {
	objBytes, err := pbutils.Marshal(obj)
	if err != nil {
		return err
	}
	if len(key) == 0 {
		uid, _ := uuid.Parse(obj.GetMetadata().Uid)
		key = uid[:]
	}

	zap.L().Debug("Setting resource",
		zap.String("kind", obj.GetKind()),
		zap.String("apiVersion", obj.GetApiVersion()),
		zap.String("uid", obj.GetMetadata().Uid),
		zap.Binary("key", key))

	return c.doSetResource([]byte(kind), key, objBytes)
}

func (c *Cache) doSetResource(bucket, key, val []byte) error {
	if err := c.db.Update(func(tx *bbolt.Tx) error {

		b := tx.Bucket(bucket)

		err := b.Put([]byte(key), val)

		return err

	}); err != nil {
		return err
	}

	return nil
}

func (c *Cache) getResource(kind string, key []byte) (umetav1.ResourceObjectI, error) {
	if len(key) == 0 {
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

func (c *Cache) deleteResource(kind string, key []byte) error {
	if err := c.db.Update(func(tx *bbolt.Tx) error {

		b := tx.Bucket([]byte(kind))

		err := b.Delete([]byte(key))

		return err

	}); err != nil {
		return err
	}
	return nil
}

/*
func (c *Cache) SetUser(usr *corev1.User) error {
	if usr.Spec.Email != "" {
		if err := c.setResource([]byte(strings.ToLower(usr.Spec.Email)), usr, ucorev1.KindUser); err != nil {
			return err
		}
	}

	return nil
}

func (c *Cache) GetUserByEmail(key string) (*corev1.User, error) {
	if key == "" || !govalidator.IsEmail(strings.ToLower(key)) {
		return nil, ErrNotFound
	}

	ret, err := c.getResource(ucorev1.KindUser, []byte(strings.ToLower(strings.TrimSpace(key))))
	if err != nil {
		return nil, err
	}
	return ret.(*corev1.User), nil
}

func (c *Cache) GetUserByUID(key string) (*corev1.User, error) {
	if key == "" {
		return nil, ErrNotFound
	}

	uid, err := uuid.Parse(key)
	if err != nil {
		return nil, err
	}

	ret, err := c.getResource(ucorev1.KindUser, uid[:])
	if err != nil {
		return nil, err
	}
	return ret.(*corev1.User), nil
}

func (c *Cache) DeleteUser(usr *corev1.User) error {
	if usr.Spec.Email != "" {
		if err := c.deleteResource(ucorev1.KindUser, []byte(usr.Spec.Email)); err != nil {
			return err
		}
	}

	return nil
}
*/

func (c *Cache) Close() error {
	err := c.db.Close()
	return err
}

func (c *Cache) SetAuthenticator(authn *corev1.Authenticator) error {
	if authn.Status.IsRegistered &&
		authn.Status.Type == corev1.Authenticator_Status_FIDO &&
		authn.Status.GetInfo() != nil &&
		authn.Status.GetInfo().GetFido() != nil &&
		len(authn.Status.GetInfo().GetFido().IdHash) > 0 {

		if err := c.setResource(
			authn.Status.GetInfo().GetFido().IdHash, authn, ucorev1.KindAuthenticator); err != nil {
			return err
		}
	}
	return nil
}

func (c *Cache) GetAuthenticatorByCredID(id []byte) (*corev1.Authenticator, error) {
	if len(id) == 0 {
		return nil, ErrNotFound
	}

	shaHash := sha256.Sum256(id)
	ret, err := c.getResource(ucorev1.KindAuthenticator, shaHash[:])
	if err != nil {
		return nil, err
	}
	return ret.(*corev1.Authenticator), nil
}

func (c *Cache) DeleteAuthenticator(authn *corev1.Authenticator) error {
	if authn.Status.Info == nil || authn.Status.Info.GetFido() == nil ||
		len(authn.Status.Info.GetFido().Id) == 0 {
		return nil
	}
	shaHash := sha256.Sum256(authn.Status.GetInfo().GetFido().Id)
	return c.deleteResource(ucorev1.KindUser, shaHash[:])
}

func (c *Cache) HasPasskey(usr *corev1.User) bool {
	return false
}
