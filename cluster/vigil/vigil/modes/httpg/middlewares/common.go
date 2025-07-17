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
	"context"
	"net"
	"net/http"
	"time"

	"github.com/octelium/octelium/apis/cluster/coctovigilv1"
	"github.com/octelium/octelium/apis/main/corev1"
)

type Constructor func(http.Handler) (http.Handler, error)

type Chain struct {
	constructors []Constructor
}

func New(constructors ...Constructor) Chain {
	return Chain{constructors: constructors}
}

func (c Chain) Then(h http.Handler) (http.Handler, error) {
	if h == nil {
		h = http.DefaultServeMux
	}

	for i := range c.constructors {
		handler, err := c.constructors[len(c.constructors)-1-i](h)
		if err != nil {
			return nil, err
		}
		h = handler
	}

	return h, nil
}

func (c Chain) ThenFunc(fn http.HandlerFunc) (http.Handler, error) {
	if fn == nil {
		return c.Then(nil)
	}
	return c.Then(fn)
}

func (c Chain) Append(constructors ...Constructor) Chain {
	newCons := make([]Constructor, 0, len(c.constructors)+len(constructors))
	newCons = append(newCons, c.constructors...)
	newCons = append(newCons, constructors...)

	return Chain{newCons}
}

func (c Chain) Extend(chain Chain) Chain {
	return c.Append(chain.constructors...)
}

type CtxKey string

const (
	CtxRequestContext CtxKey = "c-req-ctx"
)

type RequestContext struct {
	Service   *corev1.Service
	Conn      net.Conn
	CreatedAt time.Time

	IsAuthorized      bool
	IsAuthenticated   bool
	DownstreamInfo    *corev1.RequestContext
	DownstreamRequest *coctovigilv1.DownstreamRequest
	ServiceConfig     *corev1.Service_Spec_Config

	DecisionReason *corev1.AccessLog_Entry_Common_Reason
	AuthResponse   *coctovigilv1.AuthenticateAndAuthorizeResponse

	Body        []byte
	BodyJSONMap map[string]any

	ReqCtxMap map[string]any
}

func GetCtxRequestContext(ctx context.Context) *RequestContext {
	return ctx.Value(CtxRequestContext).(*RequestContext)
}
