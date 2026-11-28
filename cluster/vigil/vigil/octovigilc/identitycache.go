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

package octovigilc

import (
	"bytes"
	"hash/maphash"
	"net/http"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/octelium/octelium/apis/cluster/coctovigilv1"
	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/pkg/apiutils/ucorev1"
	"github.com/pkg/errors"
)

const (
	identityCacheMaxEntries   = 1024
	identityCacheEvictSamples = 8
	identityCacheTTL          = 5 * time.Minute
)

var identityCacheSeed = maphash.MakeSeed()

type identityCache struct {
	mu sync.RWMutex
	m  map[uint64]*identity
}

type identity struct {
	fingerprint []byte
	session     *corev1.Session
	user        *corev1.User
	groups      []*corev1.Group
	device      *corev1.Device
	namespace   *corev1.Namespace
	expiresAt   time.Time
}

func (i *identity) getFingerprint() []byte {
	if i == nil {
		return nil
	}

	return i.fingerprint
}

func (c *identityCache) get(key uint64, now time.Time) *identity {
	c.mu.RLock()
	defer c.mu.RUnlock()

	ret := c.m[key]
	if ret == nil || !now.Before(ret.expiresAt) {
		return nil
	}

	return ret
}

func (c *identityCache) set(key uint64, i *identity, now time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.m == nil {
		c.m = make(map[uint64]*identity)
	}

	if _, ok := c.m[key]; !ok && len(c.m) >= identityCacheMaxEntries {
		c.evict(now)
	}

	c.m[key] = i
}

func (c *identityCache) evict(now time.Time) {
	var victim uint64
	i := 0
	for key, e := range c.m {
		if !now.Before(e.expiresAt) {
			delete(c.m, key)
			return
		}

		if i == 0 {
			victim = key
		}

		i++
		if i >= identityCacheEvictSamples {
			break
		}
	}

	delete(c.m, victim)
}

func (c *identityCache) len() int {
	c.mu.RLock()
	defer c.mu.RUnlock()

	return len(c.m)
}

func getIdentityCacheKey(req *coctovigilv1.DownstreamRequest) uint64 {
	var h maphash.Hash
	h.SetSeed(identityCacheSeed)
	h.WriteString(req.GetSource().GetAddress())
	h.WriteByte(0)
	h.WriteString(getAccessToken(ucorev1.GetRequestHTTP(req.GetRequest()).GetHeaders()))

	return h.Sum64()
}

func getAccessToken(hdr map[string]string) string {
	if len(hdr) == 0 {
		return ""
	}

	if authHdr := hdr["x-octelium-auth"]; authHdr != "" {
		return authHdr
	}

	if cookieVal := hdr["cookie"]; cookieVal != "" {
		request := http.Request{Header: http.Header{"Cookie": {cookieVal}}}
		if cookie, err := request.Cookie("octelium_auth"); err == nil && cookie.Value != "" {
			return cookie.Value
		}
	}

	if authHdr, ok := strings.CutPrefix(hdr["authorization"], "Bearer "); ok {
		return authHdr
	}

	return ""
}

func (c *Client) setIdentity(key uint64, cached *identity, resp *coctovigilv1.AuthenticateAndAuthorizeResponse) error {
	fingerprint := resp.IdentityFingerprint
	isOmitted := resp.IsIdentityOmitted
	resp.IdentityFingerprint = nil
	resp.IsIdentityOmitted = false

	reqCtx := resp.RequestContext

	if isOmitted {
		if cached == nil || reqCtx == nil || !bytes.Equal(fingerprint, cached.fingerprint) {
			return errors.Errorf("Octovigil omitted an identity that is not cached")
		}

		reqCtx.Session = cached.session
		reqCtx.User = cached.user
		reqCtx.Groups = slices.Clone(cached.groups)
		reqCtx.Device = cached.device
		reqCtx.Namespace = cached.namespace

		return nil
	}

	if len(fingerprint) == 0 || reqCtx.GetSession() == nil {
		return nil
	}

	now := time.Now()
	c.identities.set(key, &identity{
		fingerprint: fingerprint,
		session:     reqCtx.Session,
		user:        reqCtx.User,
		groups:      slices.Clone(reqCtx.Groups),
		device:      reqCtx.Device,
		namespace:   reqCtx.Namespace,
		expiresAt:   now.Add(identityCacheTTL),
	}, now)

	return nil
}
