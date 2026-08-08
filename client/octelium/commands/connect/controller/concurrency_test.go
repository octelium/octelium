// Copyright Octelium Labs, LLC. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package controller

import (
	"context"
	"fmt"
	"sync"
	"testing"

	"github.com/octelium/octelium/apis/client/cliconfigv1"
	"github.com/octelium/octelium/apis/main/metav1"
	"github.com/octelium/octelium/apis/main/userv1"
	"github.com/stretchr/testify/assert"
)

func newTestStateCtl(t *testing.T) *Controller {
	c := &Controller{
		isNetstack:    true,
		ipv4Supported: true,
		ipv6Supported: true,
		c: &cliconfigv1.Connection{
			Connection: &userv1.ConnectionState{
				Dns: &userv1.DNS{
					Servers: []string{"100.64.0.53"},
				},
				Addresses: []*metav1.DualStackNetwork{
					{V4: "100.64.0.2/32"},
				},
			},
			Info: &cliconfigv1.Connection_Info{
				Cluster: &cliconfigv1.Connection_Info_Cluster{
					Domain: "example.com",
				},
			},
			Preferences: &cliconfigv1.Connection_Preferences{
				DeviceName: "octelium0",
				IgnoreDNS:  true,
			},
		},
	}
	c.resolvConf.path = t.TempDir() + "/resolv.conf"

	return c
}

func newTestGateway(id string) *userv1.Gateway {
	return &userv1.Gateway{
		Id:       id,
		Hostname: "127.0.0.1",
		CIDRs:    []string{"10.0.0.0/8"},
		Quicv0:   &userv1.Gateway_QUICV0{Port: 1},
	}
}

func TestControllerStateEventsAreSerializedWithClose(t *testing.T) {
	ctx := context.Background()

	c := newTestStateCtl(t)

	var wg sync.WaitGroup

	for i := range 8 {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()

			gw := newTestGateway(fmt.Sprintf("gw-%d", i))

			for range 20 {
				c.AddGateway(ctx, gw)
				c.UpdateGateway(ctx, gw)
				c.SetDNS()
				c.GetClusterDNSServers()
				c.getCurrentDNS()
				c.UpdateDNS(&userv1.DNS{Servers: []string{"100.64.0.54"}})
				c.DeleteGateway(ctx, gw.Id)
			}
		}(i)
	}

	wg.Add(1)
	go func() {
		defer wg.Done()

		for range 20 {
			c.SetConnectionState(&userv1.ConnectionState{
				Dns: &userv1.DNS{Servers: []string{"100.64.0.55"}},
				Addresses: []*metav1.DualStackNetwork{
					{V4: "100.64.0.3/32"},
				},
			})
		}
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		assert.Nil(t, c.Close())
	}()

	wg.Wait()

	assert.Nil(t, c.Close())
}

func TestControllerStateEventsRejectedAfterClose(t *testing.T) {
	ctx := context.Background()

	c := newTestStateCtl(t)
	assert.Nil(t, c.Close())

	gw := newTestGateway("gw-1")

	assert.NotNil(t, c.AddGateway(ctx, gw))
	assert.NotNil(t, c.UpdateGateway(ctx, gw))
	assert.NotNil(t, c.DeleteGateway(ctx, gw.Id))
	assert.NotNil(t, c.SetDNS())
	assert.NotNil(t, c.UpdateDNS(&userv1.DNS{Servers: []string{"100.64.0.54"}}))
	assert.NotNil(t, c.Reconfigure())
	assert.NotNil(t, c.SetConnectionState(&userv1.ConnectionState{}))
	assert.NotNil(t, c.UpdatePrivateKey("invalid"))
	assert.NotNil(t, c.Start(ctx))
}

func TestControllerSetConnectionStateRejectsNil(t *testing.T) {
	c := newTestStateCtl(t)

	assert.NotNil(t, c.SetConnectionState(nil))
	assert.NotNil(t, c.c.Connection)
}

func TestControllerGetClusterDNSServersSnapshot(t *testing.T) {
	c := newTestStateCtl(t)

	assert.Nil(t, c.SetDNS())
	assert.Equal(t, []string{"100.64.0.53"}, c.GetClusterDNSServers())

	servers := c.GetClusterDNSServers()
	servers[0] = "mutated"
	assert.Equal(t, []string{"100.64.0.53"}, c.GetClusterDNSServers())

	assert.Nil(t, c.UpdateDNS(&userv1.DNS{Servers: []string{"100.64.0.54"}}))
	assert.Equal(t, []string{"100.64.0.54"}, c.GetClusterDNSServers())
}
