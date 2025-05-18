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
	"fmt"
	"os"
	"path"

	"github.com/gofrs/flock"
	"github.com/octelium/octelium/apis/client/cliconfigv1"
	"github.com/octelium/octelium/apis/main/authv1"
	"github.com/octelium/octelium/client/common/cliutils/vhome"
	"github.com/octelium/octelium/pkg/common/pbutils"
	"github.com/pkg/errors"
)

var ErrNotFound = errors.New("OcteliumDB: Not Found")

type fsDB struct {
	flock  *flock.Flock
	dbPath string
}

func newFSDB(dbPath string) (*fsDB, error) {
	ret := &fsDB{}

	if dbPath != "" {
		if err := createHomeDirIfNotExists((dbPath)); err != nil {
			return nil, err
		}
		dbPath = path.Join(dbPath, "octelium.db")
	} else {
		vHome, err := vhome.GetOcteliumHome()
		if err != nil {
			return nil, err
		}
		if err := createHomeDirIfNotExists(vHome); err != nil {
			return nil, err
		}
		dbPath = path.Join(vHome, "octelium.db")
	}

	ret.dbPath = dbPath
	ret.flock = flock.New(fmt.Sprintf("%s.lock", dbPath))

	return ret, nil
}

func (d *fsDB) writeState(state *cliconfigv1.State) error {

	stateBytes, err := pbutils.Marshal(state)
	if err != nil {
		return err
	}

	if err := d.flock.Lock(); err != nil {
		return err
	}
	defer d.flock.Unlock()

	return os.WriteFile(d.dbPath, stateBytes, 0600)
}

func (d *fsDB) readState() (*cliconfigv1.State, error) {

	if err := d.flock.Lock(); err != nil {
		return nil, err
	}
	defer d.flock.Unlock()

	ret := &cliconfigv1.State{}

	stateBytes, err := os.ReadFile(d.dbPath)
	if err != nil {
		if os.IsNotExist(err) {
			ret.DomainMap = make(map[string]*cliconfigv1.State_Domain)
			return ret, nil
		}
		return nil, err
	}

	if err := pbutils.Unmarshal(stateBytes, ret); err != nil {
		return nil, err
	}

	if ret.DomainMap == nil {
		ret.DomainMap = make(map[string]*cliconfigv1.State_Domain)
	}

	return ret, nil

}

func (d *fsDB) migrate(_ context.Context) error {

	_, err := os.Stat(d.dbPath)
	if err == nil {
		return nil
	}
	if os.IsNotExist(err) {
		return d.writeState(&cliconfigv1.State{
			DomainMap: make(map[string]*cliconfigv1.State_Domain),
		})
	}

	return err

}

func (d *fsDB) close(_ context.Context) error {
	return nil

}

func (d *fsDB) getDomain(domain string) (*cliconfigv1.State_Domain, error) {
	state, err := d.readState()
	if err != nil {
		if os.IsNotExist(err) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	if state.DomainMap == nil {
		return nil, ErrNotFound
	}

	ret, ok := state.DomainMap[domain]
	if !ok {
		return nil, ErrNotFound
	}

	return ret, nil
}

func (d *fsDB) get(_ context.Context, clusterDomain string) (*cliconfigv1.State_Domain, error) {
	return d.getDomain(clusterDomain)
}

func (d *fsDB) set(_ context.Context, clusterDomain string, resp *authv1.SessionToken) error {

	state, err := d.readState()
	if err != nil {
		return err
	}

	state.DomainMap[clusterDomain] = &cliconfigv1.State_Domain{
		SessionToken:      resp,
		SessionTokenSetAt: pbutils.Now(),
	}

	return d.writeState(state)
}

func (d *fsDB) delete(_ context.Context, clusterDomain string) error {
	state, err := d.readState()
	if err != nil {
		return err
	}

	delete(state.DomainMap, clusterDomain)

	return d.writeState(state)
}
