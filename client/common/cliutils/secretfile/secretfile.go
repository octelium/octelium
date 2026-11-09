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

package secretfile

import (
	"io"
	"os"
	"strings"

	"github.com/pkg/errors"
)

const maxSize = 64 * 1024

func Read(filePath string) (string, error) {
	if filePath == "" {
		return "", errors.Errorf("The secret file path is not set")
	}

	f, err := os.Open(filePath)
	if err != nil {
		return "", errors.Errorf("Could not open the secret file: %+v", err)
	}
	defer f.Close()

	b, err := io.ReadAll(io.LimitReader(f, maxSize+1))
	if err != nil {
		return "", errors.Errorf("Could not read the secret file: %+v", err)
	}

	if len(b) > maxSize {
		return "", errors.Errorf("The secret file %s is too large", filePath)
	}

	ret := strings.TrimSpace(string(b))
	if ret == "" {
		return "", errors.Errorf("The secret file %s is empty", filePath)
	}

	return ret, nil
}
