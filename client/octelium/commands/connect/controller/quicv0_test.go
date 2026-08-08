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
	"testing"
	"time"

	"github.com/octelium/octelium/apis/client/cliconfigv1"
	"github.com/octelium/octelium/apis/main/userv1"
	"github.com/stretchr/testify/assert"
)

func newTestQUICEngine(gws []*userv1.Gateway) *quicEngine {
	return newQUICEngine(&Controller{
		isQUIC:        true,
		ipv4Supported: true,
		ipv6Supported: true,
		c: &cliconfigv1.Connection{
			Connection: &userv1.ConnectionState{
				Gateways: gws,
			},
			Info: &cliconfigv1.Connection_Info{
				Cluster: &cliconfigv1.Connection_Info_Cluster{
					Domain: "example.com",
				},
			},
			Preferences: &cliconfigv1.Connection_Preferences{
				DeviceName: "octelium0",
			},
		},
	})
}

func TestQUICEngineCloseIsIdempotent(t *testing.T) {
	e := newTestQUICEngine(nil)

	assert.Nil(t, e.close())
	assert.Nil(t, e.close())
	assert.True(t, e.getIsClosed())
}

func TestQUICAddGWAfterClose(t *testing.T) {
	ctx := context.Background()

	gw := &userv1.Gateway{
		Id:       "gw-1",
		Hostname: "127.0.0.1",
		CIDRs:    []string{"10.0.0.0/8"},
		Quicv0:   &userv1.Gateway_QUICV0{Port: 1},
	}

	e := newTestQUICEngine([]*userv1.Gateway{gw})
	assert.Nil(t, e.close())

	assert.NotNil(t, e.addGW(ctx, gw))

	e.quicGWMap.RLock()
	defer e.quicGWMap.RUnlock()
	assert.Equal(t, 0, len(e.quicGWMap.gwMap))
}

func TestQUICAddGWWithoutQUICInfo(t *testing.T) {
	ctx := context.Background()

	gw := &userv1.Gateway{
		Id:        "gw-1",
		Hostname:  "127.0.0.1",
		CIDRs:     []string{"10.0.0.0/8"},
		Wireguard: &userv1.Gateway_WireGuard{Port: 5432},
	}

	e := newTestQUICEngine([]*userv1.Gateway{gw})

	assert.NotNil(t, e.addGW(ctx, gw))

	e.quicGWMap.RLock()
	defer e.quicGWMap.RUnlock()
	assert.Equal(t, 0, len(e.quicGWMap.gwMap))
}

func TestQUICReconnectLoopExitsAfterEngineClose(t *testing.T) {
	ctx := context.Background()

	gw := &userv1.Gateway{
		Id:       "gw-1",
		Hostname: "127.0.0.1",
		CIDRs:    []string{"10.0.0.0/8"},
		Quicv0:   &userv1.Gateway_QUICV0{Port: 1},
	}

	e := newTestQUICEngine([]*userv1.Gateway{gw})
	assert.Nil(t, e.close())

	doneCh := make(chan error, 1)
	go func() {
		doneCh <- e.doReconnectGW(ctx, gw.Id)
	}()

	select {
	case err := <-doneCh:
		assert.Nil(t, err)
	case <-time.After(20 * time.Second):
		t.Fatal("the reconnection loop did not exit")
	}
}

func TestQUICReconnectLoopWithUnknownGW(t *testing.T) {
	e := newTestQUICEngine(nil)

	assert.Nil(t, e.doReconnectGW(context.Background(), "unknown"))
}

func TestQUICGWCloseWithoutRun(t *testing.T) {
	gw := &userv1.Gateway{
		Id:       "gw-1",
		Hostname: "127.0.0.1",
		CIDRs:    []string{"10.0.0.0/8"},
		Quicv0:   &userv1.Gateway_QUICV0{Port: 1},
	}

	e := newTestQUICEngine([]*userv1.Gateway{gw})

	newGW, err := newQUIGW(e, gw)
	assert.Nil(t, err)

	newGW.close()
	newGW.close()

	assert.Equal(t, gw.Id, <-e.gwCloseCh)
}

func TestQUICGWCloseWithFullCloseCh(t *testing.T) {
	gw := &userv1.Gateway{
		Id:       "gw-1",
		Hostname: "127.0.0.1",
		CIDRs:    []string{"10.0.0.0/8"},
		Quicv0:   &userv1.Gateway_QUICV0{Port: 1},
	}

	e := newTestQUICEngine([]*userv1.Gateway{gw})

	for i := 0; i < cap(e.gwCloseCh); i++ {
		e.gwCloseCh <- "filler"
	}

	newGW, err := newQUIGW(e, gw)
	assert.Nil(t, err)

	doneCh := make(chan struct{})
	go func() {
		newGW.close()
		close(doneCh)
	}()

	select {
	case <-doneCh:
	case <-time.After(10 * time.Second):
		t.Fatal("closing the gw blocked on a full close channel")
	}
}
