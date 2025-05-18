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

package loadbalancer

import (
	"slices"
	"sync"

	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/pkg/apiutils/ucorev1"
)

type cache struct {
	sync.RWMutex
	sMap map[string][]*corev1.Session
}

func newCache() *cache {
	return &cache{
		sMap: make(map[string][]*corev1.Session),
	}
}

func (c *cache) getByUserName(name string, svc *corev1.Service) *corev1.Session {
	c.RLock()
	defer c.RUnlock()
	sessList, ok := c.sMap[name]
	if !ok {
		return nil
	}
	if len(sessList) < 1 {
		return nil
	}
	if idx := slices.IndexFunc(sessList, func(sess *corev1.Session) bool {
		return ucorev1.ToService(svc).IsServedBySession(ucorev1.ToSession(sess))
	}); idx >= 0 {
		return sessList[idx]
	}

	return nil
}

func (c *cache) setSession(sess *corev1.Session) {
	c.Lock()
	defer c.Unlock()
	sessList, ok := c.sMap[sess.Status.UserRef.Name]
	if !ok || len(sessList) == 0 {
		c.sMap[sess.Status.UserRef.Name] = []*corev1.Session{sess}
		return
	}
	if idx := slices.IndexFunc(sessList, func(s *corev1.Session) bool {
		return s.Metadata.Uid == sess.Metadata.Uid
	}); idx >= 0 {
		sessList[idx] = sess
	} else {
		sessList = append(sessList, sess)
	}
	c.sMap[sess.Status.UserRef.Name] = sessList
}

func (c *cache) deleteSession(sess *corev1.Session) {
	c.Lock()
	defer c.Unlock()
	sessList, ok := c.sMap[sess.Status.UserRef.Name]
	if !ok || len(sessList) == 0 {
		return
	}
	sessList = slices.DeleteFunc(sessList, func(s *corev1.Session) bool {
		return s.Metadata.Uid == sess.Metadata.Uid
	})
	if len(sessList) == 0 {
		delete(c.sMap, sess.Status.UserRef.Name)
	} else {
		c.sMap[sess.Status.UserRef.Name] = sessList
	}
}
