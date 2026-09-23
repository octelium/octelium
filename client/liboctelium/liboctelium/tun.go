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

	"golang.zx2c4.com/wireguard/tun"
)

type platformTUN struct {
	mu       sync.RWMutex
	dev      tun.Device
	gen      uint64
	mtu      int
	isClosed bool

	events    chan tun.Event
	closeOnce sync.Once
}

func newPlatformTUN(dev tun.Device, mtu int) *platformTUN {
	return &platformTUN{
		dev:    dev,
		mtu:    mtu,
		events: make(chan tun.Event),
	}
}

func (t *platformTUN) current() (tun.Device, uint64, bool) {
	t.mu.RLock()
	defer t.mu.RUnlock()

	return t.dev, t.gen, t.isClosed
}

func (t *platformTUN) hasChanged(gen uint64) bool {
	t.mu.RLock()
	defer t.mu.RUnlock()

	return t.isClosed || t.gen != gen
}

func (t *platformTUN) swap(dev tun.Device, mtu int) {
	t.mu.Lock()
	if t.isClosed {
		t.mu.Unlock()
		dev.Close()
		return
	}

	old := t.dev
	t.dev = dev
	t.mtu = mtu
	t.gen++
	t.mu.Unlock()

	old.Close()
}

func (t *platformTUN) File() *os.File {
	dev, _, _ := t.current()
	return dev.File()
}

func (t *platformTUN) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	for {
		dev, gen, isClosed := t.current()
		if isClosed {
			return 0, os.ErrClosed
		}

		n, err := dev.Read(bufs, sizes, offset)
		if err == nil || !t.hasChanged(gen) {
			return n, err
		}
	}
}

func (t *platformTUN) Write(bufs [][]byte, offset int) (int, error) {
	for {
		dev, gen, isClosed := t.current()
		if isClosed {
			return 0, os.ErrClosed
		}

		n, err := dev.Write(bufs, offset)
		if err == nil || n > 0 || !t.hasChanged(gen) {
			return n, err
		}
	}
}

func (t *platformTUN) MTU() (int, error) {
	t.mu.RLock()
	mtu := t.mtu
	dev := t.dev
	t.mu.RUnlock()

	if mtu > 0 {
		return mtu, nil
	}

	return dev.MTU()
}

func (t *platformTUN) Name() (string, error) {
	dev, _, _ := t.current()
	return dev.Name()
}

func (t *platformTUN) Events() <-chan tun.Event {
	return t.events
}

func (t *platformTUN) BatchSize() int {
	dev, _, _ := t.current()
	return dev.BatchSize()
}

func (t *platformTUN) Close() error {
	var err error

	t.closeOnce.Do(func() {
		t.mu.Lock()
		t.isClosed = true
		dev := t.dev
		t.mu.Unlock()

		close(t.events)
		err = dev.Close()
	})

	return err
}

func (t *platformTUN) getIsClosed() bool {
	_, _, isClosed := t.current()
	return isClosed
}
