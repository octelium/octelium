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

package db

import (
	"context"
	"sync"

	"github.com/octelium/octelium/apis/client/cliconfigv1"
	"github.com/octelium/octelium/apis/main/authv1"
	"github.com/octelium/octelium/pkg/common/pbutils"
)

type memDB struct {
	sync.RWMutex
	state *cliconfigv1.State
}

func newMemDB() (*memDB, error) {
	return &memDB{
		state: &cliconfigv1.State{
			DomainMap: make(map[string]*cliconfigv1.State_Domain),
		},
	}, nil
}

func (d *memDB) get(ctx context.Context, domain string) (*cliconfigv1.State_Domain, error) {
	d.RLock()
	defer d.RUnlock()
	ret, ok := d.state.DomainMap[domain]
	if !ok {
		return nil, ErrNotFound
	}
	return ret, nil
}
func (d *memDB) set(ctx context.Context, domain string, sessToken *authv1.SessionToken) error {
	d.Lock()
	d.state.DomainMap[domain] = &cliconfigv1.State_Domain{
		SessionToken:      sessToken,
		SessionTokenSetAt: pbutils.Now(),
	}
	d.Unlock()
	return nil
}
func (d *memDB) delete(ctx context.Context, domain string) error {
	d.Lock()
	delete(d.state.DomainMap, domain)
	d.Unlock()

	return nil
}

func (d *memDB) close(ctx context.Context) error {
	return nil
}
func (d *memDB) migrate(ctx context.Context) error {
	return nil
}
