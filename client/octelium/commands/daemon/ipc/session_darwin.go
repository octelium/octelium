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

package ipc

import (
	"context"
	"os"
	"strconv"
	"syscall"

	"github.com/pkg/errors"
)

var consolePath = "/dev/console"

func HasLoginSession(_ context.Context, pr *Principal) (bool, error) {
	info, err := os.Stat(consolePath)
	if err != nil {
		return false, err
	}

	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return false, errors.Errorf("Could not get the owner of %s", consolePath)
	}

	return strconv.FormatUint(uint64(st.Uid), 10) == pr.ID, nil
}
