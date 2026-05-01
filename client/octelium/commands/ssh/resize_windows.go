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

package ssh

import (
	"context"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/term"
)

func watchResize(ctx context.Context, fd int, sess *ssh.Session) {
	var prevW, prevH int
	for {
		select {
		case <-ctx.Done():
			return
		case <-time.After(500 * time.Millisecond):
			w, h, err := term.GetSize(fd)
			if err != nil {
				continue
			}
			if w != prevW || h != prevH {
				sess.WindowChange(h, w)
				prevW, prevH = w, h
			}
		}
	}
}
