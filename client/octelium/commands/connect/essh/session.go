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

package essh

import (
	"context"
	"encoding/binary"
	"io"
	"os"
	"os/exec"
	"slices"
	"sync"
	"syscall"

	"github.com/pkg/errors"
	"github.com/pkg/sftp"
	"go.uber.org/zap"
	"golang.org/x/crypto/ssh"
)

type ptyReqParams struct {
	Env   string
	W     uint32
	H     uint32
	Wpx   uint32
	Hpx   uint32
	Modes string
}

func (c *dctx) doHandleSessionReqs(ctx context.Context, reqs <-chan *ssh.Request, ch ssh.Channel) {
	var closer sync.Once
	ctx, cancelFn := context.WithCancel(ctx)

	sessCtx := &sessCtx{
		ch: ch,
	}
	closeFunc := func() {
		zap.L().Debug("Closing sess req channel")
		cancelFn()
		ch.Close()
		if sessCtx.term != nil {
			if err := sessCtx.term.close(); err != nil {
				zap.L().Debug("Error closing terminal", zap.Error(err))
			}
		}
		sessCtx.wg.Wait()
	}

	defer closer.Do(closeFunc)

	for {
		select {
		case <-ctx.Done():
			zap.L().Debug("ctx done. Exiting doHandleSessionReqs")
			return
		case req := <-reqs:
			if req == nil {
				zap.L().Debug("Nil req. Exiting doHandleSessionReqs")
				return
			}
			zap.L().Debug("Downstream Req", zap.String("type", req.Type))
			if err := c.handleSessionReq(ctx, sessCtx, req); err != nil {
				zap.L().Debug("could not handle sess req", zap.Error(err))
			}
		}
	}
}

type sessCtx struct {
	ch        ssh.Channel
	term      *terminal
	cmd       *exec.Cmd
	ptyParams *ptyReqParams
	env       []*envVar
	started   bool
	wg        sync.WaitGroup
}

func (c *dctx) handleSessionReq(ctx context.Context, sessCtx *sessCtx, req *ssh.Request) error {
	if req == nil {
		return errors.Errorf("nil SSH request")
	}

	zap.L().Debug("New sess req", zap.String("type", req.Type))

	switch req.Type {
	case "pty-req":
		if sessCtx.started {
			replyFailure(req)
			return errors.Errorf("pty request after session start")
		}

		ptyParams, err := parsePTYReq(req)
		if err != nil {
			replyFailure(req)
			return err
		}
		if ptyParams.W == 0 || ptyParams.H == 0 || ptyParams.W > 65535 || ptyParams.H > 65535 {
			replyFailure(req)
			return errors.Errorf("invalid terminal dimensions")
		}

		sessCtx.ptyParams = ptyParams

		if ptyParams.Env != "" {
			sessCtx.env = setOrAppendEnv(sessCtx.env, "TERM", ptyParams.Env)
		}

		return replySuccess(req)

	case "shell":
		if sessCtx.started {
			replyFailure(req)
			return errors.Errorf("session already started")
		}
		sessCtx.started = true

		term, err := newTerminal(c, sessCtx)
		if err != nil {
			zap.L().Debug("Could not start a new terminal", zap.Error(err))
			replyFailure(req)
			return err
		}

		sessCtx.term = term

		if err := term.run(ctx, req); err != nil {
			replyFailure(req)
			return err
		}

		return nil

	case "exec":
		if sessCtx.started {
			replyFailure(req)
			return errors.Errorf("session already started")
		}
		sessCtx.started = true

		if err := c.handleSessionReqExec(ctx, sessCtx, req); err != nil {
			zap.L().Debug("Could not handle exec req", zap.Error(err))
			replyFailure(req)
			return err
		}

		return nil

	case "subsystem":
		if sessCtx.started {
			replyFailure(req)
			return errors.Errorf("session already started")
		}

		var payload struct{ Value string }
		if err := ssh.Unmarshal(req.Payload, &payload); err != nil {
			replyFailure(req)
			return err
		}

		zap.L().Debug("Subsystem request", zap.String("subsystem", payload.Value))

		switch payload.Value {
		case "sftp":
			sessCtx.started = true

			if err := c.handleSubsystemSFTP(ctx, sessCtx, req); err != nil {
				zap.L().Debug("Could not handle sftp subsystem", zap.Error(err))
				replyFailure(req)
				return err
			}
			return nil

		default:
			zap.L().Debug("Unsupported subsystem", zap.String("subsystem", payload.Value))
			replyFailure(req)
			return errors.Errorf("unsupported subsystem: %s", payload.Value)
		}

	case "env":
		if sessCtx.started {
			replyFailure(req)
			return errors.Errorf("env request after session start")
		}

		key, val, err := parseEnv(req.Payload)
		if err != nil {
			replyFailure(req)
			return err
		}

		zap.L().Debug("Adding env var", zap.String("key", key))
		sessCtx.env = setOrAppendEnv(sessCtx.env, key, val)

		return replySuccess(req)

	case "window-change":
		w, h, err := parseDims(req.Payload)
		if err != nil {
			replyFailure(req)
			return err
		}

		if w == 0 || h == 0 || w > 65535 || h > 65535 {
			replyFailure(req)
			return errors.Errorf("invalid terminal dimensions")
		}

		if sessCtx.term != nil {
			zap.L().Debug("Changing win size to", zap.Uint32("w", w), zap.Uint32("h", h))
			if err := sessCtx.term.setWinSize(uint16(w), uint16(h)); err != nil {
				replyFailure(req)
				return err
			}
		} else if sessCtx.ptyParams != nil {
			sessCtx.ptyParams.W = w
			sessCtx.ptyParams.H = h
		}

		return replySuccess(req)

	case "keepalive@openssh.com":
		return replySuccess(req)

	case "signal":
		if !sessCtx.started || sessCtx.cmd == nil {
			replyFailure(req)
			return errors.Errorf("signal request before session start")
		}

		var payload struct{ Signal string }
		if err := ssh.Unmarshal(req.Payload, &payload); err != nil {
			replyFailure(req)
			return err
		}

		sig, err := getSSHSignal(payload.Signal)
		if err != nil {
			replyFailure(req)
			return err
		}
		if err := signalProcessGroup(sessCtx.cmd, sig); err != nil {
			replyFailure(req)
			return err
		}

		return replySuccess(req)

	default:
		zap.L().Debug("Unsupported session req type", zap.String("type", req.Type))
		replyFailure(req)
		return errors.Errorf("unsupported session request type: %s", req.Type)
	}
}

func replySuccess(req *ssh.Request) error {
	if req != nil && req.WantReply {
		return req.Reply(true, nil)
	}
	return nil
}

func replyFailure(req *ssh.Request) {
	if req != nil && req.WantReply {
		_ = req.Reply(false, nil)
	}
}

func setOrAppendEnv(env []*envVar, key, val string) []*envVar {
	for _, e := range env {
		if e.key == key {
			e.val = val
			return env
		}
	}

	return append(env, &envVar{
		key: key,
		val: val,
	})
}

func (c *dctx) handleSessionReqExec(ctx context.Context, sessCtx *sessCtx, req *ssh.Request) error {
	var err error

	ch := sessCtx.ch

	var payload = struct{ Value string }{}
	if err := ssh.Unmarshal(req.Payload, &payload); err != nil {
		return err
	}

	cmdStr := payload.Value

	zap.L().Debug("Handling exec req")

	usr := c.usr

	shellPath, err := getShellPath(usr.Username)
	if err != nil {
		return err
	}

	cmd := exec.Command(shellPath, "-c", cmdStr)

	cmd.SysProcAttr = &syscall.SysProcAttr{
		Setpgid: true,
	}

	if !c.sameUser {
		credential, err := getSysProcCredential(usr)
		if err != nil {
			return err
		}

		cmd.SysProcAttr.Credential = credential
	}
	cmd.WaitDelay = processWaitDelay

	if usr.HomeDir != "" {
		cmd.Dir = usr.HomeDir
	}

	cmd.Stdout = ch
	cmd.Stderr = ch.Stderr()

	cmd.Env = c.getEnv(sessCtx.env)

	inPipe, err := cmd.StdinPipe()
	if err != nil {
		return err
	}

	if err := cmd.Start(); err != nil {
		inPipe.Close()
		return err
	}
	sessCtx.cmd = cmd
	if err := replySuccess(req); err != nil {
		killProcessGroup(cmd)
		_ = cmd.Wait()
		inPipe.Close()
		return err
	}

	go func() {
		io.Copy(inPipe, ch)
		inPipe.Close()
	}()

	sessCtx.wg.Add(1)
	go func(ctx context.Context) {
		defer sessCtx.wg.Done()

		waitCh := make(chan error, 1)
		go func() {
			err := cmd.Wait()
			if err != nil {
				zap.L().Debug("cmd wait err", zap.Error(err))
			}
			waitCh <- err
		}()

		forced := false
		var waitErr error
		select {
		case <-ctx.Done():
			forced = true
			zap.L().Debug("ctx done. Exiting exec...")
			killProcessGroup(cmd)
			waitErr = <-waitCh

		case waitErr = <-waitCh:
			zap.L().Debug("cmd wait done...", zap.Error(waitErr))
		}
		if err := sessCtx.sendSessionExit(waitErr, forced); err != nil && !errors.Is(err, io.EOF) {
			zap.L().Debug("Could not send session exit", zap.Error(err))
		}

		ch.Close()

	}(ctx)

	return nil

}

func (c *sessCtx) sendSessionExitStatus(statusCode int) error {
	zap.L().Debug("Sending exit-status request", zap.Int("code", statusCode))

	req := struct{ Status uint32 }{uint32(statusCode)}
	_, err := c.ch.SendRequest("exit-status", false,
		ssh.Marshal(&req))

	zap.L().Debug("Sending exit-status request done", zap.Error(err))

	if err := c.ch.CloseWrite(); err != nil {
		zap.L().Debug("closwWrite err", zap.Error(err))
	}

	return err
}

func (c *sessCtx) sendSessionExitSignal(sig ssh.Signal, coreDumped bool) error {
	zap.L().Debug("Sending exit-signal request", zap.String("signal", string(sig)))

	req := struct {
		Signal     string
		CoreDumped bool
		Error      string
		Lang       string
	}{
		Signal:     string(sig),
		CoreDumped: coreDumped,
	}
	_, err := c.ch.SendRequest("exit-signal", false, ssh.Marshal(&req))
	if closeErr := c.ch.CloseWrite(); err == nil {
		err = closeErr
	}

	return err
}

func (c *sessCtx) sendSessionExit(waitErr error, forced bool) error {
	if forced {
		return c.sendSessionExitStatus(130)
	}
	if waitErr == nil {
		return c.sendSessionExitStatus(0)
	}

	exitErr, ok := waitErr.(*exec.ExitError)
	if !ok {
		return c.sendSessionExitStatus(255)
	}
	waitStatus, ok := exitErr.Sys().(syscall.WaitStatus)
	if !ok || !waitStatus.Signaled() {
		return c.sendSessionExitStatus(exitErr.ExitCode())
	}

	sig, err := getSSHSignalName(waitStatus.Signal())
	if err != nil {
		return c.sendSessionExitStatus(255)
	}
	return c.sendSessionExitSignal(sig, waitStatus.CoreDump())
}

func (c *dctx) handleSessionRequests(ctx context.Context, newChannel ssh.NewChannel) {

	zap.L().Debug("Accepting a new channel")

	sesschan, reqs, err := newChannel.Accept()
	if err != nil {
		zap.L().Debug("Could not accept a new SSH channel", zap.Error(err))
		return
	}

	c.doHandleSessionReqs(ctx, reqs, sesschan)
	zap.L().Debug("Handling session requests ended", zap.String("dctxID", c.id))
}

func (c *dctx) handleSubsystemSFTP(ctx context.Context, sessCtx *sessCtx, req *ssh.Request) error {
	ch := sessCtx.ch

	if os.Getenv("OCTELIUM_ESSH_SFTP_DISABLE") == "true" {
		return errors.Errorf("eSSH SFTP is disabled")
	}

	root := "/"
	if c.usr != nil && c.usr.HomeDir != "" {
		root = c.usr.HomeDir
	}

	serverOpts := []sftp.ServerOption{
		sftp.WithServerWorkingDirectory(root),
	}

	if !c.sameUser {
		if os.Getenv("OCTELIUM_ESSH_SFTP_USER") != "true" {
			return errors.Errorf(
				`Cannot run SFTP while running as root and having --essh-user unless when setting "OCTELIUM_ESSH_SFTP_USER" env var to "true"`)
		}
	}

	srv, err := sftp.NewServer(ch, serverOpts...)
	if err != nil {
		ch.Close()
		return errors.Errorf("Could not create sftp server: %+v", err)
	}
	if err := replySuccess(req); err != nil {
		srv.Close()
		return err
	}

	sessCtx.wg.Add(1)
	go func() {
		defer sessCtx.wg.Done()
		defer ch.Close()

		errCh := make(chan error, 1)
		go func() {
			errCh <- srv.Serve()
		}()

		select {
		case <-ctx.Done():
			srv.Close()
			<-errCh
		case err := <-errCh:
			if err != nil && !errors.Is(err, io.EOF) {
				zap.L().Debug("sftp server exited...", zap.Error(err))
			}
		}
	}()

	return nil
}

func parsePTYReq(req *ssh.Request) (*ptyReqParams, error) {
	var r ptyReqParams
	if err := ssh.Unmarshal(req.Payload, &r); err != nil {
		return nil, err
	}

	return &r, nil
}

func parseDims(b []byte) (uint32, uint32, error) {
	if len(b) < 8 {
		return 0, 0, errors.Errorf("Could not parse dims")
	}

	w := binary.BigEndian.Uint32(b)
	h := binary.BigEndian.Uint32(b[4:])
	return w, h, nil
}

func parseEnv(payload []byte) (string, string, error) {
	var kv struct{ Key, Value string }
	if err := ssh.Unmarshal(payload, &kv); err != nil {
		return "", "", err
	}
	key := kv.Key
	val := kv.Value
	if !isValidEnvKey(key) {
		return "", "", errors.Errorf("Invalid env var key: %s", key)
	}

	if !slices.Contains(allowedEnvVars, key) {
		if os.Getenv("OCTELIUM_ESSH_ALLOW_ANY_ENV") != "true" {
			return "", "", errors.Errorf("Denied adding the env var key: %s", key)
		}
	}

	return key, val, nil
}

func isValidEnvKey(key string) bool {
	if key == "" {
		return false
	}
	for idx, ch := range key {
		if ch == '_' || ch >= 'a' && ch <= 'z' || ch >= 'A' && ch <= 'Z' {
			continue
		}
		if idx > 0 && ch >= '0' && ch <= '9' {
			continue
		}
		return false
	}
	return true
}

var allowedEnvVars = []string{
	"TERM",
	"TERM_PROGRAM",
	"TERM_PROGRAM_VERSION",
	"COLORTERM",
	"COLORFGBG",
	"DISPLAY",

	"LANG",
	"LC_ALL",
	"LC_CTYPE",
	"LC_MESSAGES",
	"LC_COLLATE",
	"LC_MONETARY",
	"LC_NUMERIC",
	"LC_TIME",
	"LC_ADDRESS",
	"LC_MEASUREMENT",
	"LC_NAME",
	"LC_PAPER",
	"LC_TELEPHONE",

	"TZ",

	"EDITOR",
	"VISUAL",
	"PAGER",
	"MANPAGER",

	"GIT_AUTHOR_NAME",
	"GIT_AUTHOR_EMAIL",
	"GIT_COMMITTER_NAME",
	"GIT_COMMITTER_EMAIL",
}
