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
	"bytes"
	"maps"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/pkg/errors"
	"golang.org/x/sys/unix"
)

type fileAttrs struct {
	uid    uint32
	gid    uint32
	mode   os.FileMode
	xattrs map[string][]byte
}

func (a *fileAttrs) isEqual(b *fileAttrs) bool {
	return a.uid == b.uid && a.gid == b.gid && a.mode == b.mode &&
		maps.EqualFunc(a.xattrs, b.xattrs, bytes.Equal)
}

func replaceFile(filePath string, content []byte) error {
	realPath, err := filepath.EvalSymlinks(filePath)
	if err != nil {
		if !os.IsNotExist(err) {
			return err
		}
		if _, err := os.Lstat(filePath); err == nil {
			return errors.Errorf("OcteliumDB: Could not resolve the symlink %s", filePath)
		}
		realPath = filePath
	}

	target, err := getFileAttrs(realPath)
	if err != nil && !os.IsNotExist(err) {
		return err
	}

	return doWriteFileAtomic(realPath, content, func(f *os.File) error {
		if target == nil {
			return nil
		}

		return setFileAttrs(f, target)
	})
}

func setFileAttrs(f *os.File, target *fileAttrs) error {
	cur, err := getOpenFileAttrs(f)
	if err != nil {
		return err
	}

	if cur.uid != target.uid || cur.gid != target.gid {
		if err := f.Chown(int(target.uid), int(target.gid)); err != nil {
			return err
		}
	}

	if err := f.Chmod(target.mode); err != nil {
		return err
	}

	cur, err = getOpenFileAttrs(f)
	if err != nil {
		return err
	}

	if !cur.isEqual(target) {
		return errors.Errorf("OcteliumDB: Could not preserve the attributes of %s", f.Name())
	}

	return nil
}

func getFileAttrs(filePath string) (*fileAttrs, error) {
	fi, err := os.Lstat(filePath)
	if err != nil {
		return nil, err
	}

	ret, err := getFileInfoAttrs(fi)
	if err != nil {
		return nil, err
	}

	ret.xattrs, err = getXattrs(
		func(dest []byte) (int, error) {
			return unix.Listxattr(filePath, dest)
		},
		func(attr string, dest []byte) (int, error) {
			return unix.Getxattr(filePath, attr, dest)
		})
	if err != nil {
		return nil, err
	}

	return ret, nil
}

func getOpenFileAttrs(f *os.File) (*fileAttrs, error) {
	fi, err := f.Stat()
	if err != nil {
		return nil, err
	}

	ret, err := getFileInfoAttrs(fi)
	if err != nil {
		return nil, err
	}

	fd := int(f.Fd())

	ret.xattrs, err = getXattrs(
		func(dest []byte) (int, error) {
			return unix.Flistxattr(fd, dest)
		},
		func(attr string, dest []byte) (int, error) {
			return unix.Fgetxattr(fd, attr, dest)
		})
	if err != nil {
		return nil, err
	}

	return ret, nil
}

func getFileInfoAttrs(fi os.FileInfo) (*fileAttrs, error) {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok || !fi.Mode().IsRegular() || st.Nlink != 1 {
		return nil, errors.Errorf("OcteliumDB: %s is not a regular file with a single link", fi.Name())
	}

	return &fileAttrs{
		uid:  st.Uid,
		gid:  st.Gid,
		mode: fi.Mode() & (os.ModePerm | os.ModeSetuid | os.ModeSetgid | os.ModeSticky),
	}, nil
}

func getXattrs(listFn func(dest []byte) (int, error),
	getFn func(attr string, dest []byte) (int, error)) (map[string][]byte, error) {

	sz, err := listFn(nil)
	if err != nil {
		if errors.Is(err, unix.ENOTSUP) {
			return nil, nil
		}
		return nil, err
	}

	names := make([]byte, sz)
	sz, err = listFn(names)
	if err != nil {
		return nil, err
	}

	ret := make(map[string][]byte)

	for _, attr := range strings.Split(string(names[:sz]), "\x00") {
		if attr == "" {
			continue
		}

		sz, err := getFn(attr, nil)
		if err != nil {
			return nil, err
		}

		val := make([]byte, sz)
		sz, err = getFn(attr, val)
		if err != nil {
			return nil, err
		}

		ret[attr] = val[:sz]
	}

	return ret, nil
}
