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

package cliutils

import "github.com/octelium/octelium/client/common/db"

var dbC *db.DB

func openDBDefault() error {
	var err error
	dbC, err = db.OpenDefault()
	if err != nil {
		return err
	}
	return nil
}

func OpenDB(path string) error {
	var err error
	dbC, err = db.Open(path)
	if err != nil {
		return err
	}
	return nil
}

func GetDB() *db.DB {
	return dbC
}

func CloseDB() error {
	return dbC.Close()
}
