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
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/octelium/octelium/client/common/cliutils"
	"github.com/octelium/octelium/client/common/db"
	"github.com/pkg/errors"
	"go.uber.org/zap"
)

type cleanupStore struct {
	dbC          *db.DB
	userDB       *db.DB
	isPrivileged bool
}

type cleanupStoreOpts struct {
	dir          string
	isPrivileged bool
	isContainer  bool
}

func getCleanupStore(dbC *db.DB) *cleanupStore {
	return newCleanupStore(dbC, &cleanupStoreOpts{
		dir:          getCleanupStoreDir(),
		isPrivileged: isPrivilegedProcess(),
		isContainer:  cliutils.IsContainerRuntime(),
	})
}

func newCleanupStore(dbC *db.DB, o *cleanupStoreOpts) *cleanupStore {
	if dbC == nil || !o.isPrivileged || dbC.Path() == "" || isOwnedDBPath(dbC.Path()) {
		return &cleanupStore{
			dbC: dbC,
		}
	}

	if o.isContainer {
		return &cleanupStore{
			dbC:          dbC,
			isPrivileged: true,
		}
	}

	ret := &cleanupStore{
		userDB:       dbC,
		isPrivileged: true,
	}

	storeDB, err := openCleanupStoreDB(o.dir, dbC.Path())
	if err != nil {
		zap.L().Warn("Could not open the privileged connection cleanup state",
			zap.String("dir", o.dir), zap.Error(err))
		return ret
	}

	zap.L().Debug("Using the privileged connection cleanup state",
		zap.String("dbPath", dbC.Path()), zap.String("path", storeDB.Path()))

	ret.dbC = storeDB

	return ret
}

func (s *cleanupStore) reconcile(domain string) {
	reconcileConnectionCleanup(s.dbC, domain, s.isPrivileged)
	reconcileConnectionCleanup(s.userDB, domain, true)
}

func (s *cleanupStore) listDomains() []string {
	var ret []string

	for _, dbC := range []*db.DB{s.dbC, s.userDB} {
		if dbC == nil {
			continue
		}

		domainMap, err := dbC.List()
		if err != nil {
			zap.L().Warn("Could not list the connection cleanup states", zap.Error(err))
			continue
		}

		for domain, itm := range domainMap {
			if itm.GetConnectionCleanup() != nil && !slices.Contains(ret, domain) {
				ret = append(ret, domain)
			}
		}
	}

	slices.Sort(ret)

	return ret
}

func openCleanupStoreDB(storeDir, dbPath string) (*db.DB, error) {
	if storeDir == "" {
		return nil, errors.Errorf("Could not find the connection cleanup state directory")
	}

	dir := filepath.Join(storeDir, getCleanupStoreKey(dbPath))
	if err := prepareCleanupStoreDir(storeDir, dir); err != nil {
		return nil, err
	}

	return db.OpenWithOpts(&db.Opts{
		Path: dir,
	})
}

func prepareCleanupStoreDir(storeDir, dir string) error {
	if err := os.MkdirAll(filepath.Dir(storeDir), 0o755); err != nil {
		return err
	}

	for _, dirPath := range []string{storeDir, dir} {
		if err := os.Mkdir(dirPath, 0o700); err != nil && !os.IsExist(err) {
			return err
		}

		if !isOwnedPath(dirPath, os.ModeDir) {
			return errors.Errorf("%s is not a directory that is exclusively owned by the current user", dirPath)
		}
	}

	return nil
}

func getCleanupStoreKey(dbPath string) string {
	if absPath, err := filepath.Abs(dbPath); err == nil {
		dbPath = absPath
	} else {
		dbPath = filepath.Clean(dbPath)
	}

	if cliutils.IsWindows() {
		dbPath = strings.ToLower(dbPath)
	}

	hash := sha256.Sum256([]byte(dbPath))

	return hex.EncodeToString(hash[:16])
}
