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
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strconv"
	"sync"
	"syscall"

	"github.com/creack/pty"
	"github.com/moby/term"
	"github.com/octelium/octelium/pkg/utils/utilrand"
	"github.com/pkg/errors"
	"go.uber.org/zap"
	"golang.org/x/crypto/ssh"
)

type terminal struct {
	id  string
	cmd *exec.Cmd

	pty *os.File
	tty *os.File

	closeCh chan struct{}

	dctx *dctx

	ch ssh.Channel

	mu sync.Mutex

	isClosed bool
	sessCtx  *sessCtx

	noPty bool
}

func newTerminal(dctx *dctx, sessCtx *sessCtx) (*terminal, error) {

	ret := &terminal{
		id:      fmt.Sprintf("%s-%s", dctx.id, utilrand.GetRandomStringLowercase(4)),
		dctx:    dctx,
		ch:      sessCtx.ch,
		sessCtx: sessCtx,
		closeCh: make(chan struct{}, 10),
		noPty:   sessCtx.ptyParams == nil,
	}

	zap.L().Debug("Creating a new terminal",
		zap.String("id", ret.id), zap.Any("ptyReq", sessCtx.ptyParams))

	var err error

	if !ret.noPty {

		zap.S().Debugf("Opening pty")

		ret.pty, ret.tty, err = pty.Open()
		if err != nil {
			return nil, err
		}
	}

	/*
		 termState, err := term.SetRawTerminal(ret.pty.Fd())
		 if err != nil {
			 return nil, err
		 }

		 if err := term.DisableEcho(ret.pty.Fd(), termState); err != nil {
			 return nil, err
		 }
	*/

	if !ret.noPty && sessCtx.ptyParams != nil {
		zap.L().Debug("Setting init win size",
			zap.Uint32("width", sessCtx.ptyParams.W),
			zap.Uint32("height", sessCtx.ptyParams.H),
		)
		if err := ret.setWinSize(uint16(sessCtx.ptyParams.W), uint16(sessCtx.ptyParams.H)); err != nil {
			return nil, err
		}
	}

	shellPath, err := getShellPath(dctx.usr.Username)
	if err != nil {
		return nil, err
	}

	env := dctx.getEnv(sessCtx.env)

	setEnv(&env, "SHELL", shellPath)

	cmd := &exec.Cmd{
		Path: shellPath,
		Dir:  dctx.usr.HomeDir,
		Env:  env,
	}

	if ret.noPty {

		cmd.Stdout = sessCtx.ch
		cmd.Stderr = sessCtx.ch.Stderr()

		cmd.SysProcAttr = &syscall.SysProcAttr{
			Setsid: true,
		}

	} else {
		cmd.Stdin = ret.tty
		cmd.Stdout = ret.tty
		cmd.Stderr = ret.tty

		cmd.SysProcAttr = &syscall.SysProcAttr{
			Setsid:  true,
			Setctty: true,
		}
	}

	if !dctx.sameUser {
		uid, err := strconv.ParseUint(dctx.usr.Uid, 10, 32)
		if err != nil {
			return nil, err
		}
		gid, err := strconv.ParseUint(dctx.usr.Gid, 10, 32)
		if err != nil {
			return nil, err
		}

		zap.L().Debug("uid-gid", zap.Uint64("uid", uid), zap.Uint64("gid", gid))

		cmd.SysProcAttr.Credential = &syscall.Credential{Uid: uint32(uid), Gid: uint32(gid)}
	}

	ret.cmd = cmd

	zap.L().Debug("terminal successfully created", zap.String("id", ret.id))

	return ret, nil
}

func (t *terminal) setWinSize(w, h uint16) error {
	if err := term.SetWinsize(t.pty.Fd(), &term.Winsize{
		Width:  w,
		Height: h,
	}); err != nil {
		return errors.Errorf("Could not size terminal win Size: %s: %+v", t.id, err)
	}
	return nil
}

func (t *terminal) run(ctx context.Context) error {
	zap.S().Debugf("Running terminal: %s", t.id)
	var once sync.Once
	var err error

	closeFn := func() {
		zap.S().Debugf("closing terminal closeCh")
		t.closeCh <- struct{}{}
	}

	var stdinPipe io.WriteCloser
	if t.noPty {
		stdinPipe, err = t.cmd.StdinPipe()
		if err != nil {
			return err
		}
	}

	if err := t.cmd.Start(); err != nil {
		return err
	}

	if t.noPty {

		go func() {
			io.Copy(stdinPipe, t.ch)
			once.Do(closeFn)
			stdinPipe.Close()
		}()

	} else {
		go func() {
			io.Copy(t.ch, t.pty)
			once.Do(closeFn)
		}()

		go func() {
			io.Copy(t.pty, t.ch)
			once.Do(closeFn)
		}()

		t.tty.Close()
		t.tty = nil
	}

	go func(ctx context.Context) {
		err := t.waitAndClose(ctx)
		if err != nil {
			zap.S().Debugf("terminal wait err: %+v", err)
		}
	}(ctx)

	zap.S().Debugf("terminal: %s is now running", t.id)

	return nil
}

func (t *terminal) waitAndClose(ctx context.Context) error {

	waitCh := make(chan error)
	go func() {
		err := t.cmd.Wait()
		if err != nil {
			zap.S().Debugf("cmd wait err: %+v", err)
		}
		waitCh <- err
	}()

	statusCode := 0
	select {
	case <-ctx.Done():
		statusCode = 130
	case err := <-waitCh:
		if exiterr, ok := err.(*exec.ExitError); ok {
			zap.S().Debugf("exit code....", zap.Int("code", exiterr.ExitCode()))
			statusCode = exiterr.ExitCode()
		}
	case <-t.closeCh:
		if err := t.cmd.Process.Kill(); err != nil {
			zap.S().Debugf("cmd kill err: %+v", err)
		}
	}

	if err := t.sessCtx.sendSessionExitStatus(statusCode); err != nil && !errors.Is(err, io.EOF) {
		zap.L().Warn("Could not send exit-status req", zap.Error(err))
	}

	return t.close()
}

func (t *terminal) close() error {
	if t == nil {
		return nil
	}

	zap.S().Debugf("Starting closing terminal: %s", t.id)

	t.mu.Lock()

	if t.isClosed {
		zap.L().Debug("terminal is already closed. Nothing to be done.")
		t.mu.Unlock()
		return nil
	}
	t.isClosed = true
	t.mu.Unlock()

	if !t.noPty {

		if t.tty != nil {
			t.tty.Close()
			// t.tty = nil
		}

		if t.pty != nil {
			t.tty.Close()
			// t.pty = nil
		}
	}

	t.ch.Close()

	zap.S().Debugf("Terminal is now closed: %s", t.id)

	return nil
}

func getShellPath(usr string) (string, error) {

	ret, err := getShellFromPasswdFile(usr)
	if err == nil {
		zap.L().Debug("Found shell path from passwd file", zap.String("shell", ret))
		return ret, nil
	}

	zap.L().Debug("Could not get shell from passwd file. Will try to get an installed shell", zap.Error(err))

	shells := []string{"bash", "zsh", "sh"}

	for _, sh := range shells {
		path, err := exec.LookPath(sh)
		if err == nil {
			zap.L().Debug("Found shell", zap.String("shell", sh), zap.String("path", path))

			return path, nil
		}
	}

	return "", errors.Errorf("Could not find shell path")
}
