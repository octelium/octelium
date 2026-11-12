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

package netutils

import (
	"io"

	"github.com/pkg/errors"
)

func CopyAndCloseWrite(dst io.Writer, src io.Reader, closeFn func()) (int64, error) {
	n, err := io.Copy(dst, src)
	if err == nil {
		err = closeWrite(dst)
	}

	if err != nil {
		closeFn()
	}

	return n, err
}

func closeWrite(w io.Writer) error {
	if cw, ok := w.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}

	return errors.Errorf("%T does not support CloseWrite", w)
}
