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

package authncache

import (
	"crypto/sha256"
	"sync"

	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/pkg/common/pbutils"
	"github.com/pkg/errors"
)

type Cache struct {
	m    sync.RWMutex
	cMap map[[32]byte]*corev1.Authenticator
}

func NewCache() (*Cache, error) {
	return &Cache{
		cMap: make(map[[32]byte]*corev1.Authenticator),
	}, nil
}

var ErrNotFound = errors.New("Resource not found")
var SessionNotFound = errors.New("Session not found")

func (c *Cache) IsErrNotFound(err error) bool {
	return errors.Is(err, ErrNotFound)
}

func (c *Cache) Close() error {
	return nil
}

func (c *Cache) SetAuthenticator(authn *corev1.Authenticator) error {
	if authn.Status.IsRegistered &&
		authn.Status.Type == corev1.Authenticator_Status_FIDO &&
		authn.Status.GetInfo() != nil &&
		authn.Status.GetInfo().GetFido() != nil &&
		len(authn.Status.GetInfo().GetFido().IdHash) == 32 {
		c.m.Lock()
		c.cMap[[32]byte(authn.Status.GetInfo().GetFido().IdHash)] = pbutils.Clone(authn).(*corev1.Authenticator)
		c.m.Unlock()
	}

	return nil
}

func (c *Cache) GetAuthenticatorByCredID(id []byte) (*corev1.Authenticator, error) {
	if len(id) == 0 || len(id) > 20000 {
		return nil, ErrNotFound
	}

	shaHash := sha256.Sum256(id)
	c.m.RLock()
	defer c.m.RUnlock()
	ret, ok := c.cMap[shaHash]
	if !ok {
		return nil, ErrNotFound
	}

	return ret, nil
}

func (c *Cache) DeleteAuthenticator(authn *corev1.Authenticator) error {
	if authn.Status.Info != nil && authn.Status.Info.GetFido() != nil &&
		len(authn.Status.Info.GetFido().IdHash) == 32 {
		c.m.Lock()
		delete(c.cMap, [32]byte(authn.Status.Info.GetFido().IdHash))
		c.m.Unlock()
	}

	return nil
}
