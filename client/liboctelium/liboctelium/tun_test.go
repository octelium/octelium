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

package liboctelium

import (
	"os"
	"sync"
	"testing"
	"time"

	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
	"golang.zx2c4.com/wireguard/tun"
)

type fakeDev struct {
	name      string
	mtu       int
	readCh    chan []byte
	readErrCh chan error
	writeCh   chan []byte
	closedCh  chan struct{}
	closeOnce sync.Once
}

func newFakeDev(name string) *fakeDev {
	return &fakeDev{
		name:      name,
		mtu:       1400,
		readCh:    make(chan []byte, 16),
		readErrCh: make(chan error, 1),
		writeCh:   make(chan []byte, 16),
		closedCh:  make(chan struct{}),
	}
}

func (d *fakeDev) File() *os.File {
	return nil
}

func (d *fakeDev) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	select {
	case pkt := <-d.readCh:
		sizes[0] = copy(bufs[0][offset:], pkt)
		return 1, nil
	case err := <-d.readErrCh:
		return 0, err
	case <-d.closedCh:
		return 0, os.ErrClosed
	}
}

func (d *fakeDev) Write(bufs [][]byte, offset int) (int, error) {
	if d.isClosed() {
		return 0, os.ErrClosed
	}

	for _, buf := range bufs {
		d.writeCh <- append([]byte(nil), buf[offset:]...)
	}

	return len(bufs), nil
}

func (d *fakeDev) MTU() (int, error) {
	return d.mtu, nil
}

func (d *fakeDev) Name() (string, error) {
	return d.name, nil
}

func (d *fakeDev) Events() <-chan tun.Event {
	return nil
}

func (d *fakeDev) Close() error {
	d.closeOnce.Do(func() {
		close(d.closedCh)
	})
	return nil
}

func (d *fakeDev) BatchSize() int {
	return 1
}

func (d *fakeDev) isClosed() bool {
	select {
	case <-d.closedCh:
		return true
	default:
		return false
	}
}

func readPlatformTUN(t *testing.T, dev tun.Device) chan []byte {
	ret := make(chan []byte, 1)

	go func() {
		bufs := [][]byte{make([]byte, 1500)}
		sizes := []int{0}

		n, err := dev.Read(bufs, sizes, 16)
		if err != nil {
			close(ret)
			return
		}

		assert.Equal(t, 1, n)
		ret <- bufs[0][16 : 16+sizes[0]]
	}()

	return ret
}

func TestPlatformTUN(t *testing.T) {
	dev1 := newFakeDev("tun1")
	dev := newPlatformTUN(dev1, 1280)

	{
		mtu, err := dev.MTU()
		assert.Nil(t, err)
		assert.Equal(t, 1280, mtu)

		name, err := dev.Name()
		assert.Nil(t, err)
		assert.Equal(t, "tun1", name)

		assert.Equal(t, 1, dev.BatchSize())
		assert.Nil(t, dev.File())
	}

	{
		readCh := readPlatformTUN(t, dev)
		dev1.readCh <- []byte("pkt1")
		assert.Equal(t, []byte("pkt1"), <-readCh)
	}

	{
		n, err := dev.Write([][]byte{append(make([]byte, 16), []byte("out1")...)}, 16)
		assert.Nil(t, err)
		assert.Equal(t, 1, n)
		assert.Equal(t, []byte("out1"), <-dev1.writeCh)
	}

	{
		readErr := errors.Errorf("read error")
		readCh := readPlatformTUN(t, dev)
		dev1.readErrCh <- readErr

		_, ok := <-readCh
		assert.False(t, ok)
		assert.False(t, dev1.isClosed())
	}

	dev2 := newFakeDev("tun2")
	{
		readCh := readPlatformTUN(t, dev)

		time.Sleep(50 * time.Millisecond)
		dev.swap(dev2, 0)

		assert.True(t, dev1.isClosed())

		dev2.readCh <- []byte("pkt2")
		assert.Equal(t, []byte("pkt2"), <-readCh)

		mtu, err := dev.MTU()
		assert.Nil(t, err)
		assert.Equal(t, 1400, mtu)

		name, err := dev.Name()
		assert.Nil(t, err)
		assert.Equal(t, "tun2", name)
	}

	{
		n, err := dev.Write([][]byte{append(make([]byte, 16), []byte("out2")...)}, 16)
		assert.Nil(t, err)
		assert.Equal(t, 1, n)
		assert.Equal(t, []byte("out2"), <-dev2.writeCh)
		assert.Equal(t, 0, len(dev1.writeCh))
	}

	{
		readCh := readPlatformTUN(t, dev)

		time.Sleep(50 * time.Millisecond)
		assert.Nil(t, dev.Close())

		_, ok := <-readCh
		assert.False(t, ok)
		assert.True(t, dev2.isClosed())
		assert.True(t, dev.getIsClosed())

		_, ok = <-dev.Events()
		assert.False(t, ok)
	}

	{
		_, err := dev.Read([][]byte{make([]byte, 1500)}, []int{0}, 16)
		assert.ErrorIs(t, err, os.ErrClosed)

		_, err = dev.Write([][]byte{make([]byte, 32)}, 16)
		assert.ErrorIs(t, err, os.ErrClosed)

		assert.Nil(t, dev.Close())
	}

	{
		dev3 := newFakeDev("tun3")
		dev.swap(dev3, 1280)
		assert.True(t, dev3.isClosed())

		name, err := dev.Name()
		assert.Nil(t, err)
		assert.Equal(t, "tun2", name)
	}
}

func TestPlatformTUNConcurrentSwap(t *testing.T) {
	dev := newPlatformTUN(newFakeDev("tun0"), 1280)

	var wg sync.WaitGroup

	wg.Add(1)
	go func() {
		defer wg.Done()

		bufs := [][]byte{make([]byte, 1500)}
		sizes := []int{0}
		for {
			if _, err := dev.Read(bufs, sizes, 0); err != nil {
				assert.ErrorIs(t, err, os.ErrClosed)
				return
			}
		}
	}()

	for i := range 50 {
		dev.swap(newFakeDev("tun"), 1280+i)
	}

	assert.Nil(t, dev.Close())
	wg.Wait()
}
