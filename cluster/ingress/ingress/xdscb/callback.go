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

package xdscb

import (
	"context"

	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	discovery "github.com/envoyproxy/go-control-plane/envoy/service/discovery/v3"
)

type Callback struct {
}

func NewCallback() *Callback {
	return &Callback{}
}

func (c *Callback) OnStreamOpen(ctx context.Context, id int64, typ string) error {
	return nil
}
func (c *Callback) OnDeltaStreamOpen(ctx context.Context, id int64, typ string) error {
	return nil
}

func (c *Callback) OnStreamClosed(id int64, node *corev3.Node)      {}
func (c *Callback) OnDeltaStreamClosed(id int64, node *corev3.Node) {}

func (c *Callback) OnStreamRequest(id int64, req *discovery.DiscoveryRequest) error {
	return nil
}
func (c *Callback) OnStreamDeltaRequest(id int64, req *discovery.DeltaDiscoveryRequest) error {
	return nil
}
func (c *Callback) OnFetchRequest(ctx context.Context, req *discovery.DiscoveryRequest) error {
	return nil
}
func (c *Callback) OnStreamResponse(ctx context.Context, _ int64, _ *discovery.DiscoveryRequest, _ *discovery.DiscoveryResponse) {
}
func (c *Callback) OnStreamDeltaResponse(id int64, req *discovery.DeltaDiscoveryRequest, res *discovery.DeltaDiscoveryResponse) {
}

func (c *Callback) OnFetchResponse(*discovery.DiscoveryRequest, *discovery.DiscoveryResponse) {}
