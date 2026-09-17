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
	"context"
	"testing"

	"github.com/octelium/octelium/apis/cluster/coctovigilv1"
	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/pkg/apiutils/ucorev1"
	"github.com/octelium/octelium/pkg/common/pbutils"
	"github.com/stretchr/testify/assert"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/structpb"
)

type tstInternalC struct {
	coctovigilv1.InternalServiceClient
	sentBody []byte
}

func (c *tstInternalC) AuthenticateAndAuthorize(ctx context.Context,
	in *coctovigilv1.AuthenticateAndAuthorizeRequest,
	opts ...grpc.CallOption) (*coctovigilv1.AuthenticateAndAuthorizeResponse, error) {

	c.sentBody = ucorev1.GetRequestHTTP(in.Request.GetRequest()).GetBody()

	return &coctovigilv1.AuthenticateAndAuthorizeResponse{
		IsAuthorized: true,
		RequestContext: &corev1.RequestContext{
			Request: pbutils.Clone(in.Request.GetRequest()).(*corev1.RequestContext_Request),
		},
	}, nil
}

type tstRemoteC struct {
	internalC coctovigilv1.InternalServiceClient
}

func (c *tstRemoteC) InternalC() coctovigilv1.InternalServiceClient {
	return c.internalC
}

func TestRequestBodyIsNotSentToOctovigil(t *testing.T) {

	ctx := context.Background()

	body := []byte(`{"model": "gpt"}`)

	newReq := func(bodyMap *structpb.Struct) *AuthenticateAndAuthorizeRequest {
		return &AuthenticateAndAuthorizeRequest{
			Request: &coctovigilv1.DownstreamRequest{
				Request: &corev1.RequestContext_Request{
					Type: &corev1.RequestContext_Request_Http{
						Http: &corev1.RequestContext_Request_HTTP{
							Body:    body,
							BodyMap: bodyMap,
						},
					},
				},
			},
		}
	}

	{
		internalC := &tstInternalC{}
		c := &Client{remoteC: &tstRemoteC{internalC: internalC}}

		req := newReq(pbutils.MapToStructMust(map[string]any{"model": "gpt"}))

		resp, err := c.AuthenticateAndAuthorize(ctx, req)
		assert.Nil(t, err)

		assert.Nil(t, internalC.sentBody)
		assert.Equal(t, body,
			ucorev1.GetRequestHTTP(req.Request.GetRequest()).GetBody())
		assert.Equal(t, body,
			ucorev1.GetRequestHTTP(resp.GetRequestContext().GetRequest()).GetBody())
		assert.NotNil(t,
			ucorev1.GetRequestHTTP(resp.GetRequestContext().GetRequest()).GetBodyMap())
	}

	{
		internalC := &tstInternalC{}
		c := &Client{remoteC: &tstRemoteC{internalC: internalC}}

		req := newReq(nil)

		resp, err := c.AuthenticateAndAuthorize(ctx, req)
		assert.Nil(t, err)

		assert.Equal(t, body, internalC.sentBody)
		assert.Equal(t, body,
			ucorev1.GetRequestHTTP(req.Request.GetRequest()).GetBody())
		assert.Equal(t, body,
			ucorev1.GetRequestHTTP(resp.GetRequestContext().GetRequest()).GetBody())
	}
}
