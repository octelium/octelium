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

package middlewares

import (
	"time"

	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/cluster/common/cache"
	"github.com/octelium/octelium/pkg/apiutils/umetav1"
	"github.com/octelium/octelium/pkg/common/pbutils"
	"google.golang.org/protobuf/reflect/protoreflect"
)

const reqCtxMapTTL = 10 * time.Second

type reqCtxMapKey struct {
	kind            protoreflect.FullName
	uid             string
	resourceVersion string
}

type reqCtxMapCache = cache.Cache[reqCtxMapKey, map[string]any]

var reqCtxMaps = newReqCtxMapCache()

func newReqCtxMapCache() *reqCtxMapCache {
	return cache.New(&cache.Opts[reqCtxMapKey, map[string]any]{
		DefaultTTL:      reqCtxMapTTL,
		CleanupInterval: reqCtxMapTTL,
	})
}

func GetRequestContextMap(i *corev1.RequestContext) (map[string]any, error) {
	return getRequestContextMap(reqCtxMaps, i)
}

func getRequestContextMap(c *reqCtxMapCache, i *corev1.RequestContext) (map[string]any, error) {
	ret := make(map[string]any)

	if i.GetRequest() != nil {
		val, err := pbutils.ConvertToMap(i.Request)
		if err != nil {
			return nil, err
		}
		ret["request"] = val
	}

	if i.GetSession() != nil {
		val, err := getResourceMap(c, i.Session)
		if err != nil {
			return nil, err
		}
		ret["session"] = val
	}

	if i.GetUser() != nil {
		val, err := getResourceMap(c, i.User)
		if err != nil {
			return nil, err
		}
		ret["user"] = val
	}

	if len(i.GetGroups()) > 0 {
		groups := make([]any, 0, len(i.Groups))
		for _, grp := range i.Groups {
			val, err := getResourceMap(c, grp)
			if err != nil {
				return nil, err
			}
			groups = append(groups, val)
		}
		ret["groups"] = groups
	}

	if i.GetDevice() != nil {
		val, err := pbutils.ConvertToMap(i.Device)
		if err != nil {
			return nil, err
		}
		ret["device"] = val
	}

	if i.GetService() != nil {
		val, err := getResourceMap(c, i.Service)
		if err != nil {
			return nil, err
		}
		ret["service"] = val
	}

	if i.GetNamespace() != nil {
		val, err := getResourceMap(c, i.Namespace)
		if err != nil {
			return nil, err
		}
		ret["namespace"] = val
	}

	return ret, nil
}

func getResourceMap(c *reqCtxMapCache, obj umetav1.ResourceObjectI) (map[string]any, error) {
	md := obj.GetMetadata()
	if md.GetUid() == "" || md.GetResourceVersion() == "" {
		return pbutils.ConvertToMap(obj)
	}

	key := reqCtxMapKey{
		kind:            obj.ProtoReflect().Descriptor().FullName(),
		uid:             md.Uid,
		resourceVersion: md.ResourceVersion,
	}

	if ret, ok := c.Get(key); ok {
		return ret, nil
	}

	ret, err := pbutils.ConvertToMap(obj)
	if err != nil {
		return nil, err
	}

	c.Set(key, ret)

	return ret, nil
}
