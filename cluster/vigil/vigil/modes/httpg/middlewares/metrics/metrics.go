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

package metrics

import (
	"context"
	"net/http"

	"github.com/octelium/octelium/cluster/vigil/vigil/metricutils"
	"github.com/octelium/octelium/cluster/vigil/vigil/modes/httpg/httputils"
	"github.com/octelium/octelium/cluster/vigil/vigil/modes/httpg/middlewares"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
)

type middleware struct {
	next          http.Handler
	commonMetrics *metricutils.CommonMetrics
}

func New(ctx context.Context, next http.Handler, commonMetrics *metricutils.CommonMetrics) (http.Handler, error) {

	return &middleware{
		next:          next,
		commonMetrics: commonMetrics,
	}, nil
}

func (m *middleware) ServeHTTP(w http.ResponseWriter, req *http.Request) {

	reqCtx := middlewares.GetCtxRequestContext(req.Context())

	m.commonMetrics.AtRequestStart()

	m.next.ServeHTTP(w, req)

	state := func() string {
		switch {
		case reqCtx.IsAuthorized || httputils.IsAnonymousMode(req):
			return "ALLOWED"
		case reqCtx.IsAuthenticated:
			return "DENIED"
		default:
			return "DENIED_UNKNOWN"
		}
	}()

	attrs := []attribute.KeyValue{
		{
			Key:   "req.http.method",
			Value: attribute.StringValue(getMethod(req)),
		},
		{
			Key:   "state",
			Value: attribute.StringValue(state),
		},
	}

	m.commonMetrics.AtRequestEnd(reqCtx.CreatedAt, metric.WithAttributeSet(attribute.NewSet(attrs...)))
}

func getMethod(req *http.Request) string {
	switch req.Method {
	case "GET", "POST", "DELETE", "PUT", "OPTIONS", "CONNECT", "TRACE", "PATCH", "HEAD":
		return req.Method
	default:
		return "UNKNOWN"
	}
}
