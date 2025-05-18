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

//go:build !windows
// +build !windows


package essh

import (
	"bufio"

	"os"
	"strings"

	"github.com/pkg/errors"
)

type passwdEntry struct {
	Pass  string
	Uid   string
	Gid   string
	Gecos string
	Home  string
	Shell string
}

func getShellFromPasswdFile(usr string) (string, error) {
	fileMap, err := parsePasswdFile()
	if err != nil {
		return "", err
	}
	ret, ok := fileMap[usr]
	if !ok {
		return "", errors.Errorf("Could not find passwd entry for user: %s", usr)
	}
	return ret.Shell, nil
}

func parsePasswdFile() (map[string]passwdEntry, error) {

	file, err := os.Open("/etc/passwd")
	if err != nil {
		return nil, err
	}

	defer file.Close()
	lines := bufio.NewReader(file)
	entries := make(map[string]passwdEntry)
	for {
		line, _, err := lines.ReadLine()
		if err != nil {
			break
		}
		name, entry, err := parseLine(string(line))
		if err != nil {
			return nil, err
		}
		entries[name] = entry
	}
	return entries, nil
}

func parseLine(line string) (string, passwdEntry, error) {
	fs := strings.Split(line, ":")
	if len(fs) != 7 {
		return "", passwdEntry{}, errors.Errorf("Invalid number of fields")
	}
	return fs[0], passwdEntry{fs[1], fs[2], fs[3], fs[4], fs[5], fs[6]}, nil
}
