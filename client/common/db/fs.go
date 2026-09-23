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
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"sync"
	"time"

	"github.com/gofrs/flock"
	"github.com/octelium/octelium/apis/client/cliconfigv1"
	"github.com/octelium/octelium/apis/client/daemonv1"
	"github.com/octelium/octelium/apis/main/authv1"
	"github.com/octelium/octelium/client/common/cliutils/vhome"
	"github.com/octelium/octelium/pkg/common/pbutils"
	"github.com/pkg/errors"
)

var ErrNotFound = errors.New("OcteliumDB: Not Found")

const (
	lockTimeout       = 10 * time.Second
	lockRetryInterval = 1000 * time.Millisecond
)

const encryptionKeyLen = 32

var encryptedStatePrefix = []byte("octelium-db-v1:")

type fsDB struct {
	mu     sync.Mutex
	flock  *flock.Flock
	dbPath string
	owner  *Owner
	aead   cipher.AEAD
}

func newFSDB(o *Opts) (*fsDB, error) {
	ret := &fsDB{
		owner: o.Owner,
	}

	if len(o.EncryptionKey) > 0 {
		aead, err := newAEAD(o.EncryptionKey)
		if err != nil {
			return nil, err
		}
		ret.aead = aead
	}

	dbDir := o.Path
	if dbDir == "" {
		vHome, err := vhome.GetOcteliumHome()
		if err != nil {
			return nil, err
		}
		dbDir = vHome
	}

	if err := ret.owner.createHomeDirIfNotExists(dbDir); err != nil {
		return nil, err
	}

	ret.dbPath = path.Join(dbDir, "octelium.db")

	lockPath := fmt.Sprintf("%s.lock", ret.dbPath)
	if err := ret.createLockFile(lockPath); err != nil {
		return nil, err
	}

	ret.flock = flock.New(lockPath)

	return ret, nil
}

func newAEAD(key []byte) (cipher.AEAD, error) {
	if len(key) != encryptionKeyLen {
		return nil, errors.Errorf("OcteliumDB: The encryption key must be %d bytes", encryptionKeyLen)
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	return cipher.NewGCM(block)
}

func (d *fsDB) seal(plaintext []byte) ([]byte, error) {
	nonce := make([]byte, d.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}

	ret := make([]byte, 0, len(encryptedStatePrefix)+len(nonce)+len(plaintext)+d.aead.Overhead())
	ret = append(ret, encryptedStatePrefix...)
	ret = append(ret, nonce...)

	return d.aead.Seal(ret, nonce, plaintext, encryptedStatePrefix), nil
}

func (d *fsDB) open(ciphertext []byte) ([]byte, error) {
	if !bytes.HasPrefix(ciphertext, encryptedStatePrefix) ||
		len(ciphertext) < len(encryptedStatePrefix)+d.aead.NonceSize() {
		return nil, errors.Errorf("OcteliumDB: The state is not encrypted")
	}

	ciphertext = ciphertext[len(encryptedStatePrefix):]
	nonce := ciphertext[:d.aead.NonceSize()]

	ret, err := d.aead.Open(nil, nonce, ciphertext[d.aead.NonceSize():], encryptedStatePrefix)
	if err != nil {
		return nil, errors.Errorf("OcteliumDB: Could not decrypt the state")
	}

	return ret, nil
}

func (d *fsDB) createLockFile(lockPath string) error {
	if d.owner == nil {
		return nil
	}

	f, err := os.OpenFile(lockPath, os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	f.Close()

	return d.owner.setOwner(lockPath)
}

func (d *fsDB) lock() (func(), error) {

	d.mu.Lock()

	ctx, cancel := context.WithTimeout(context.Background(), lockTimeout)
	defer cancel()

	locked, err := d.flock.TryLockContext(ctx, lockRetryInterval)
	if err != nil {
		d.mu.Unlock()
		return nil, err
	}
	if !locked {
		d.mu.Unlock()
		return nil, errors.Errorf("OcteliumDB: Could not acquire the file lock at %s", d.flock.Path())
	}

	return func() {
		d.flock.Unlock()
		d.mu.Unlock()
	}, nil
}

func (d *fsDB) writeState(state *cliconfigv1.State) error {

	unlock, err := d.lock()
	if err != nil {
		return err
	}
	defer unlock()

	return d.writeStateLocked(state)
}

func (d *fsDB) writeStateLocked(state *cliconfigv1.State) error {

	stateBytes, err := pbutils.Marshal(state)
	if err != nil {
		return err
	}

	if d.aead != nil {
		stateBytes, err = d.seal(stateBytes)
		if err != nil {
			return err
		}

		if err := writeFileAtomic(d.dbPath, stateBytes); err != nil {
			return err
		}

		return d.owner.setOwner(d.dbPath)
	}

	if err := os.WriteFile(d.dbPath, stateBytes, 0600); err != nil {
		return err
	}

	return d.owner.setOwner(d.dbPath)
}

func writeFileAtomic(filePath string, content []byte) error {
	dir := filepath.Dir(filePath)

	f, err := os.CreateTemp(dir, fmt.Sprintf("%s.tmp-*", filepath.Base(filePath)))
	if err != nil {
		return err
	}

	tmpPath := f.Name()
	isRenamed := false
	defer func() {
		if !isRenamed {
			os.Remove(tmpPath)
		}
	}()

	if _, err := f.Write(content); err != nil {
		f.Close()
		return err
	}

	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}

	if err := f.Close(); err != nil {
		return err
	}

	if err := os.Rename(tmpPath, filePath); err != nil {
		return err
	}
	isRenamed = true

	if dirFile, err := os.Open(dir); err == nil {
		dirFile.Sync()
		dirFile.Close()
	}

	return nil
}

func (d *fsDB) readState() (*cliconfigv1.State, error) {

	unlock, err := d.lock()
	if err != nil {
		return nil, err
	}
	defer unlock()

	return d.readStateLocked()
}

func (d *fsDB) readStateLocked() (*cliconfigv1.State, error) {

	ret := &cliconfigv1.State{}

	stateBytes, err := os.ReadFile(d.dbPath)
	if err != nil {
		if os.IsNotExist(err) {
			ret.DomainMap = make(map[string]*cliconfigv1.State_Domain)
			return ret, nil
		}
		return nil, err
	}

	if d.aead != nil && len(stateBytes) > 0 {
		stateBytes, err = d.open(stateBytes)
		if err != nil {
			return nil, err
		}
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

	unlock, err := d.lock()
	if err != nil {
		return err
	}
	defer unlock()

	_, err = os.Stat(d.dbPath)
	if err == nil {
		return nil
	}
	if os.IsNotExist(err) {
		return d.writeStateLocked(&cliconfigv1.State{
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

func (d *fsDB) list(_ context.Context) (map[string]*cliconfigv1.State_Domain, error) {
	state, err := d.readState()
	if err != nil {
		if os.IsNotExist(err) {
			return make(map[string]*cliconfigv1.State_Domain), nil
		}
		return nil, err
	}

	return state.DomainMap, nil
}

func (d *fsDB) set(_ context.Context, clusterDomain string, resp *authv1.SessionToken) error {

	unlock, err := d.lock()
	if err != nil {
		return err
	}
	defer unlock()

	state, err := d.readStateLocked()
	if err != nil {
		return err
	}

	domain := state.DomainMap[clusterDomain]
	if domain == nil {
		domain = &cliconfigv1.State_Domain{}
		state.DomainMap[clusterDomain] = domain
	}
	domain.SessionToken = resp
	domain.SessionTokenSetAt = pbutils.Now()

	return d.writeStateLocked(state)
}

func (d *fsDB) setConnectionCleanup(_ context.Context, clusterDomain string,
	cleanup *cliconfigv1.ConnectionCleanup) error {

	unlock, err := d.lock()
	if err != nil {
		return err
	}
	defer unlock()

	state, err := d.readStateLocked()
	if err != nil {
		return err
	}

	domain := state.DomainMap[clusterDomain]
	if domain == nil {
		domain = &cliconfigv1.State_Domain{}
		state.DomainMap[clusterDomain] = domain
	}
	domain.ConnectionCleanup = cleanup

	return d.writeStateLocked(state)
}

func (d *fsDB) deleteConnectionCleanup(_ context.Context, clusterDomain string) error {
	unlock, err := d.lock()
	if err != nil {
		return err
	}
	defer unlock()

	state, err := d.readStateLocked()
	if err != nil {
		return err
	}

	domain := state.DomainMap[clusterDomain]
	if domain == nil {
		return nil
	}
	domain.ConnectionCleanup = nil
	if domain.SessionToken == nil && domain.SessionTokenSetAt == nil && domain.Settings == nil {
		delete(state.DomainMap, clusterDomain)
	}

	return d.writeStateLocked(state)
}

func (d *fsDB) setSettings(_ context.Context, clusterDomain string, settings *daemonv1.DomainSettings) error {

	unlock, err := d.lock()
	if err != nil {
		return err
	}
	defer unlock()

	state, err := d.readStateLocked()
	if err != nil {
		return err
	}

	domain := state.DomainMap[clusterDomain]
	if domain == nil {
		domain = &cliconfigv1.State_Domain{}
		state.DomainMap[clusterDomain] = domain
	}
	domain.Settings = settings

	return d.writeStateLocked(state)
}

func (d *fsDB) deleteSessionToken(_ context.Context, clusterDomain string) error {

	unlock, err := d.lock()
	if err != nil {
		return err
	}
	defer unlock()

	state, err := d.readStateLocked()
	if err != nil {
		return err
	}

	domain := state.DomainMap[clusterDomain]
	if domain == nil {
		return nil
	}
	domain.SessionToken = nil
	domain.SessionTokenSetAt = nil

	return d.writeStateLocked(state)
}

func (d *fsDB) delete(_ context.Context, clusterDomain string) error {

	unlock, err := d.lock()
	if err != nil {
		return err
	}
	defer unlock()

	state, err := d.readStateLocked()
	if err != nil {
		return err
	}

	domain := state.DomainMap[clusterDomain]
	if domain == nil {
		return nil
	}
	cleanup := domain.ConnectionCleanup
	if cleanup == nil {
		delete(state.DomainMap, clusterDomain)
	} else {
		state.DomainMap[clusterDomain] = &cliconfigv1.State_Domain{
			ConnectionCleanup: cleanup,
		}
	}

	return d.writeStateLocked(state)
}
