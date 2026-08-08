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
	"os"
	"sync"
	"testing"

	"github.com/octelium/octelium/apis/client/cliconfigv1"
	"github.com/octelium/octelium/apis/main/metav1"
	"github.com/octelium/octelium/apis/main/userv1"
	"github.com/stretchr/testify/assert"
	bufferv2 "gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

func newTestNetstackCtl(t *testing.T) *Controller {
	c := &Controller{
		ipv4Supported: true,
		ipv6Supported: true,
		c: &cliconfigv1.Connection{
			Connection: &userv1.ConnectionState{
				Addresses: []*metav1.DualStackNetwork{
					{
						V4: "100.64.0.2/32",
						V6: "fd00::2/128",
					},
				},
			},
			Info: &cliconfigv1.Connection_Info{
				Cluster: &cliconfigv1.Connection_Info_Cluster{
					Domain: "example.com",
				},
			},
			Preferences: &cliconfigv1.Connection_Preferences{
				DeviceName: "octelium0",
				Mtu:        1280,
				IgnoreDNS:  true,
			},
		},
	}

	assert.Nil(t, c.createNetstackTUN())
	assert.True(t, c.isNetstack)
	assert.NotNil(t, c.nsTun)

	return c
}

func newTestPacketBuffer() *stack.PacketBuffer {
	pkt := make([]byte, 60)
	pkt[0] = 4 << 4

	return stack.NewPacketBuffer(stack.PacketBufferOptions{
		Payload: bufferv2.MakeWithData(pkt),
	})
}

func TestNetTunCloseIsIdempotent(t *testing.T) {
	c := newTestNetstackCtl(t)

	assert.Nil(t, c.nsTun.Close())
	assert.Nil(t, c.nsTun.Close())
	assert.Nil(t, c.nsTun.Close())
}

func TestNetTunReadAfterClose(t *testing.T) {
	c := newTestNetstackCtl(t)

	assert.Nil(t, c.nsTun.Close())

	buf := [][]byte{make([]byte, 65535)}
	sizes := []int{0}

	n, err := c.nsTun.Read(buf, sizes, 0)
	assert.Equal(t, 0, n)
	assert.ErrorIs(t, err, os.ErrClosed)
}

func TestNetTunReadUnblocksOnClose(t *testing.T) {
	c := newTestNetstackCtl(t)

	errCh := make(chan error, 1)
	go func() {
		buf := [][]byte{make([]byte, 65535)}
		sizes := []int{0}
		_, err := c.nsTun.Read(buf, sizes, 0)
		errCh <- err
	}()

	assert.Nil(t, c.nsTun.Close())
	assert.ErrorIs(t, <-errCh, os.ErrClosed)
}

func TestNetTunWritePacketAfterClose(t *testing.T) {
	c := newTestNetstackCtl(t)
	ep := (*endpoint)(c.nsTun)

	assert.Nil(t, c.nsTun.Close())

	pkt := newTestPacketBuffer()
	defer pkt.DecRef()

	assert.NotNil(t, ep.WritePacket(pkt))
}

func TestNetTunConcurrentWritePacketAndClose(t *testing.T) {
	c := newTestNetstackCtl(t)
	ep := (*endpoint)(c.nsTun)

	var wg sync.WaitGroup
	for range 32 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			pkt := newTestPacketBuffer()
			defer pkt.DecRef()
			ep.WritePacket(pkt)
		}()
	}

	wg.Add(1)
	go func() {
		defer wg.Done()
		assert.Nil(t, c.nsTun.Close())
	}()

	wg.Wait()
}

func TestCreateNetstackTUNWithInvalidAddresses(t *testing.T) {
	c := &Controller{
		ipv4Supported: true,
		ipv6Supported: true,
		c: &cliconfigv1.Connection{
			Connection: &userv1.ConnectionState{
				Addresses: []*metav1.DualStackNetwork{
					{
						V4: "100.64.0.2/32",
					},
					{
						V4: "100.64.0.2/32",
					},
				},
			},
			Preferences: &cliconfigv1.Connection_Preferences{
				DeviceName: "octelium0",
				Mtu:        1280,
			},
		},
	}

	assert.NotNil(t, c.createNetstackTUN())
	assert.False(t, c.isNetstack)
	assert.Nil(t, c.nsTun)
}

func TestControllerCloseWithNetstackTUN(t *testing.T) {
	c := newTestNetstackCtl(t)
	nsTun := c.nsTun

	assert.Nil(t, c.Close())
	assert.Nil(t, c.Close())

	buf := [][]byte{make([]byte, 65535)}
	sizes := []int{0}
	_, err := nsTun.Read(buf, sizes, 0)
	assert.ErrorIs(t, err, os.ErrClosed)
}
