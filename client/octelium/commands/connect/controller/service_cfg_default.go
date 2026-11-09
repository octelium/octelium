//go:build !windows
// +build !windows

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

package controller

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/octelium/octelium/client/octelium/internal/userexec"
	"github.com/pkg/errors"
	"go.uber.org/zap"
)

const sshConfigCmdTimeout = 10 * time.Second

const sshConfigCmdMaxOutput = 4096

func setFileOwner(filePath string, src os.FileInfo) error {
	if os.Geteuid() != 0 {
		return nil
	}

	st, ok := src.Sys().(*syscall.Stat_t)
	if !ok {
		return nil
	}

	if int(st.Uid) == os.Geteuid() && int(st.Gid) == os.Getegid() {
		return nil
	}

	return os.Chown(filePath, int(st.Uid), int(st.Gid))
}

func doSSHConfigOp(op *sshConfigOp) error {
	cred, err := getSSHConfigCredential(filepath.Dir(op.FilePath))
	if err != nil {
		if op.Remove && os.IsNotExist(err) {
			return nil
		}
		return err
	}

	if cred == nil {
		return op.run()
	}

	return runSSHConfigCmdAs(cred, op)
}

func getSSHConfigCredential(sshDir string) (*syscall.Credential, error) {
	if os.Geteuid() != 0 {
		return nil, nil
	}

	for _, filePath := range []string{filepath.Dir(sshDir), sshDir} {
		fi, err := os.Stat(filePath)
		if err != nil {
			return nil, err
		}

		st, ok := fi.Sys().(*syscall.Stat_t)
		if !ok {
			return nil, errors.Errorf("Could not get the owner of %s", filePath)
		}

		if int(st.Uid) != os.Geteuid() {
			return getSSHConfigUserCredential(st.Uid, st.Gid), nil
		}

		if fi.Mode().Perm()&0o022 != 0 {
			return nil, errors.Errorf("Refusing to manage the SSH config since %s is writable by other users", filePath)
		}
	}

	return nil, nil
}

func getSSHConfigUserCredential(uid, gid uint32) *syscall.Credential {
	if usr, err := user.LookupId(strconv.FormatUint(uint64(uid), 10)); err == nil {
		if val, err := strconv.ParseUint(usr.Gid, 10, 32); err == nil {
			gid = uint32(val)
		}
	}

	return &syscall.Credential{
		Uid: uid,
		Gid: gid,
	}
}

func runSSHConfigCmdAs(cred *syscall.Credential, op *sshConfigOp) error {
	req, err := json.Marshal(op)
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), sshConfigCmdTimeout)
	defer cancel()

	cmd, err := userexec.Command(ctx, cred, sshConfigCmdName)
	if err != nil {
		return err
	}

	output := &sshConfigCmdOutput{}
	cmd.Stdin = bytes.NewReader(req)
	cmd.Stdout = output
	cmd.Stderr = output

	zap.L().Debug("Running the SSH config command as the owner of the SSH directory",
		zap.String("filePath", op.FilePath), zap.Uint32("uid", cred.Uid), zap.Uint32("gid", cred.Gid))

	if err := cmd.Run(); err != nil {
		return errors.Errorf("Could not run the SSH config command as the uid %d: %s. %+v",
			cred.Uid, strings.TrimSpace(output.buf.String()), err)
	}

	return nil
}

type sshConfigCmdOutput struct {
	buf bytes.Buffer
}

func (o *sshConfigCmdOutput) Write(p []byte) (int, error) {
	if n := sshConfigCmdMaxOutput - o.buf.Len(); n > 0 {
		o.buf.Write(p[:min(len(p), n)])
	}

	return len(p), nil
}
