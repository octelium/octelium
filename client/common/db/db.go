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
	"strings"

	"github.com/octelium/octelium/apis/client/cliconfigv1"
	"github.com/octelium/octelium/apis/main/authv1"
	"github.com/pkg/errors"
)

type DB struct {
	db db
}

func OpenDefault() (*DB, error) {
	return Open("")
}

type db interface {
	get(ctx context.Context, domain string) (*cliconfigv1.State_Domain, error)
	set(ctx context.Context, domain string, sessToken *authv1.SessionToken) error
	delete(ctx context.Context, domain string) error
	close(ctx context.Context) error
	migrate(ctx context.Context) error
}

func Open(overridePath string) (*DB, error) {

	ret := &DB{}
	var err error

	switch strings.ToLower(overridePath) {
	case "mem", "memory":
		ret.db, err = newMemDB()
		if err != nil {
			return nil, err
		}
	default:
		ret.db, err = newFSDB(overridePath)
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
	return ret.SessionToken, nil
}

func (d *DB) Get(clusterDomain string) (*cliconfigv1.State_Domain, error) {
	return d.db.get(context.Background(), clusterDomain)
}

func (d *DB) Delete(clusterDomain string) error {
	return d.db.delete(context.Background(), clusterDomain)
}

func (d *DB) ErrorIsNotFound(err error) bool {

	return errors.Is(err, ErrNotFound)
}

func createHomeDirIfNotExists(dirPath string) error {
	_, err := os.Stat(dirPath)
	if err == nil {
		return nil
	}
	if !os.IsNotExist(err) {
		return err
	}

	return os.MkdirAll(dirPath, 0700)
}
