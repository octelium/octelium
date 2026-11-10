//go:build unix

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
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/pkg/errors"
	"go.uber.org/zap"
	"golang.org/x/sys/unix"
)

func (o *Owner) createDirs(dirPath string) error {
	if trimmed := strings.TrimRight(dirPath, "/"); trimmed != "" {
		dirPath = trimmed
	}

	missingDirs, err := getMissingDirs(dirPath)
	if err != nil {
		return err
	}

	if len(missingDirs) == 0 {
		return nil
	}

	dir, err := os.Open(filepath.Dir(missingDirs[len(missingDirs)-1]))
	if err != nil {
		return err
	}

	for i := len(missingDirs) - 1; i >= 0; i-- {
		mode := uint32(0755)
		if i == 0 {
			mode = 0700
		}

		child, err := o.mkdirAt(dir, missingDirs[i], mode)
		dir.Close()
		if err != nil {
			return err
		}
		dir = child
	}

	return dir.Close()
}

func (o *Owner) mkdirAt(dir *os.File, dirPath string, mode uint32) (*os.File, error) {
	if err := unix.Mkdirat(int(dir.Fd()), filepath.Base(dirPath), mode); err != nil {
		if !errors.Is(err, unix.EEXIST) {
			return nil, &os.PathError{Op: "mkdir", Path: dirPath, Err: err}
		}

		return openAt(dir, dirPath, unix.O_RDONLY|unix.O_DIRECTORY, 0)
	}

	ret, err := openAt(dir, dirPath, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}

	o.setOwner(dir, ret)

	return ret, nil
}

func (o *Owner) createFile(filePath string) {
	if o == nil {
		return
	}

	dir, err := os.Open(filepath.Dir(filePath))
	if err != nil {
		return
	}
	defer dir.Close()

	f, err := openAt(dir, filePath, unix.O_RDONLY|unix.O_CREAT|unix.O_EXCL, 0600)
	if err != nil {
		return
	}
	defer f.Close()

	o.setOwner(dir, f)
}

func (o *Owner) setOwner(dir, f *os.File) {
	dirInfo, err := dir.Stat()
	if err != nil {
		return
	}

	if st, ok := dirInfo.Sys().(*syscall.Stat_t); !ok || int64(st.Uid) != int64(o.UID) {
		return
	}

	if err := f.Chown(o.UID, o.GID); err != nil {
		zap.L().Warn("OcteliumDB: Could not set the owner", zap.String("path", f.Name()), zap.Error(err))
	}
}

func openAt(dir *os.File, filePath string, flags int, mode uint32) (*os.File, error) {
	for {
		fd, err := unix.Openat(int(dir.Fd()), filepath.Base(filePath), flags|unix.O_CLOEXEC, mode)
		if err == nil {
			return os.NewFile(uintptr(fd), filePath), nil
		}

		if !errors.Is(err, unix.EINTR) {
			return nil, &os.PathError{Op: "open", Path: filePath, Err: err}
		}
	}
}
