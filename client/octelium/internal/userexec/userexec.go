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

package userexec

import (
	"fmt"
	"os"
)

const cmdArg = "__internal"

var cmds = make(map[string]func(args []string) error)

func Register(name string, fn func(args []string) error) {
	cmds[name] = fn
}

func Init() {
	if len(os.Args) < 3 || os.Args[1] != cmdArg {
		return
	}

	fn, ok := cmds[os.Args[2]]
	if !ok {
		fmt.Fprintf(os.Stderr, "Unknown internal command: %s\n", os.Args[2])
		os.Exit(2)
	}

	if err := fn(os.Args[3:]); err != nil {
		fmt.Fprintf(os.Stderr, "%s\n", err)
		os.Exit(1)
	}

	os.Exit(0)
}
