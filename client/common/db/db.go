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
	"os"
	"path/filepath"
	"strings"

	"github.com/octelium/octelium/apis/client/cliconfigv1"
	"github.com/octelium/octelium/apis/client/daemonv1"
	"github.com/octelium/octelium/apis/main/authv1"
	"github.com/pkg/errors"
)

type DB struct {
	db db
}

func OpenDefault() (*DB, error) {
	return Open("")
}

type Opts struct {
	Path  string
	Owner *Owner
}

type Owner struct {
	UID int
	GID int
}

type db interface {
	get(ctx context.Context, domain string) (*cliconfigv1.State_Domain, error)
	list(ctx context.Context) (map[string]*cliconfigv1.State_Domain, error)
	set(ctx context.Context, domain string, sessToken *authv1.SessionToken) error
	setSettings(ctx context.Context, domain string, settings *daemonv1.DomainSettings) error
	deleteSessionToken(ctx context.Context, domain string) error
	delete(ctx context.Context, domain string) error
	close(ctx context.Context) error
	migrate(ctx context.Context) error
}

func Open(overridePath string) (*DB, error) {
	return OpenWithOpts(&Opts{
		Path: overridePath,
	})
}

func OpenWithOpts(o *Opts) (*DB, error) {
	if o == nil {
		o = &Opts{}
	}

	ret := &DB{}
	var err error

	switch strings.ToLower(o.Path) {
	case "mem", "memory":
		ret.db, err = newMemDB()
		if err != nil {
			return nil, err
		}
	default:
		ret.db, err = newFSDB(o)
		if err != nil {
			return nil, err
		}

	}

	return ret, nil
}

func (d *DB) Migrate() error {
	return d.db.migrate(context.Background())
}

func (d *DB) Close() error {
	return d.db.close(context.Background())
}

func (d *DB) SetSessionToken(clusterDomain string, resp *authv1.SessionToken) error {
	return d.db.set(context.Background(), clusterDomain, resp)
}

func (d *DB) GetSessionToken(clusterDomain string) (*authv1.SessionToken, error) {

	if accessToken := os.Getenv("OCTELIUM_ACCESS_TOKEN"); accessToken != "" {
		return &authv1.SessionToken{
			AccessToken: accessToken,
		}, nil
	}

	ret, err := d.db.get(context.Background(), clusterDomain)
	if err != nil {
		return nil, err
	}
	if ret.GetSessionToken() == nil {
		return nil, ErrNotFound
	}
	return ret.SessionToken, nil
}

func (d *DB) Get(clusterDomain string) (*cliconfigv1.State_Domain, error) {
	return d.db.get(context.Background(), clusterDomain)
}

func (d *DB) List() (map[string]*cliconfigv1.State_Domain, error) {
	return d.db.list(context.Background())
}

func (d *DB) SetDomainSettings(clusterDomain string, settings *daemonv1.DomainSettings) error {
	return d.db.setSettings(context.Background(), clusterDomain, settings)
}

func (d *DB) DeleteSessionToken(clusterDomain string) error {
	return d.db.deleteSessionToken(context.Background(), clusterDomain)
}

func (d *DB) Delete(clusterDomain string) error {
	return d.db.delete(context.Background(), clusterDomain)
}

func (d *DB) ErrorIsNotFound(err error) bool {

	return errors.Is(err, ErrNotFound)
}

func (o *Owner) createHomeDirIfNotExists(dirPath string) error {
	_, err := os.Stat(dirPath)
	if err == nil {
		return nil
	}
	if !os.IsNotExist(err) {
		return err
	}

	missingDirs, err := getMissingDirs(dirPath)
	if err != nil {
		return err
	}

	if parent := filepath.Dir(dirPath); parent != dirPath {
		if err := os.MkdirAll(parent, 0755); err != nil {
			return err
		}
	}

	if err := os.Mkdir(dirPath, 0700); err != nil && !os.IsExist(err) {
		return err
	}

	for _, dir := range missingDirs {
		if err := o.setOwner(dir); err != nil {
			return err
		}
	}

	return nil
}

func getMissingDirs(dirPath string) ([]string, error) {
	var ret []string

	for dir := dirPath; ; {
		_, err := os.Stat(dir)
		if err == nil {
			break
		}
		if !os.IsNotExist(err) {
			return nil, err
		}

		ret = append(ret, dir)

		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}

	return ret, nil
}

func (o *Owner) setOwner(filePath string) error {
	if o == nil {
		return nil
	}

	if err := os.Chown(filePath, o.UID, o.GID); err != nil {
		return errors.Errorf("OcteliumDB: Could not set the owner of %s: %+v", filePath, err)
	}

	return nil
}
