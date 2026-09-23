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

package liboctelium

import (
	"os"

	"github.com/pkg/errors"
	"golang.org/x/sys/unix"
	"golang.zx2c4.com/wireguard/tun"
)

const utunControlName = "com.apple.net.utun_control"

const maxUTUNFD = 1024

func dupFD(fd int) (int, error) {
	return unix.FcntlInt(uintptr(fd), unix.F_DUPFD_CLOEXEC, 0)
}

func closeFD(fd int) error {
	return unix.Close(fd)
}

func newTUNFromFD(fd int) (tun.Device, error) {
	tunFD, err := dupFD(fd)
	if err != nil {
		return nil, err
	}

	if err := unix.SetNonblock(tunFD, true); err != nil {
		unix.Close(tunFD)
		return nil, err
	}

	return tun.CreateTUNFromFile(os.NewFile(uintptr(tunFD), "/dev/tun"), 0)
}

func findTUNFD() (int, error) {
	ctlInfo := &unix.CtlInfo{}
	copy(ctlInfo.Name[:], utunControlName)

	for fd := 0; fd < maxUTUNFD; fd++ {
		sa, err := unix.Getpeername(fd)
		if err != nil {
			continue
		}

		addr, ok := sa.(*unix.SockaddrCtl)
		if !ok {
			continue
		}

		if ctlInfo.Id == 0 {
			if err := unix.IoctlCtlInfo(fd, ctlInfo); err != nil {
				continue
			}
		}

		if addr.ID == ctlInfo.Id {
			return fd, nil
		}
	}

	return -1, errors.Errorf("Could not find the utun file descriptor")
}
