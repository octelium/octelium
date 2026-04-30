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
	"encoding/binary"
	"io"
	"os"
	"os/exec"
	"strconv"
	"strings"
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

	sessCtx := &sessCtx{
		ch: ch,
	}
	closeFunc := func() {
		zap.L().Debug("Closing sess req channel")
		ch.Close()
		if sessCtx.term != nil {
			if err := sessCtx.term.close(); err != nil {
				zap.L().Debug("Error closing terminal", zap.Error(err))
			}
		}
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
	ptyParams *ptyReqParams
	env       []*envVar
}

func (c *dctx) handleSessionReq(ctx context.Context, sessCtx *sessCtx, req *ssh.Request) error {
	zap.L().Debug("New sess req", zap.String("type", req.Type))

	term := sessCtx.term

	switch req.Type {
	case "pty-req":
		ptyParams, err := parsePTYReq(req)
		if err != nil {
			return err
		}
		sessCtx.ptyParams = ptyParams

		if ptyParams.Env != "" {
			sessCtx.env = append(sessCtx.env, &envVar{
				key: "TERM",
				val: ptyParams.Env,
			})
		}

		if term == nil {
			term, err := newTerminal(c, sessCtx)
			if err != nil {
				zap.L().Debug("Could not start a new terminal", zap.Error(err))
				return err
			}
			sessCtx.term = term
			if err := term.run(ctx); err != nil {
				return err
			}
		} else {
			zap.L().Debug("There is an already running shell. No terminal to be created.")
		}

	case "shell":
		if term == nil {
			term, err := newTerminal(c, sessCtx)
			if err != nil {
				zap.L().Debug("Could not start a new terminal", zap.Error(err))
				return err
			}
			sessCtx.term = term
			if err := term.run(ctx); err != nil {
				return err
			}
		} else {
			zap.L().Debug("There is an already running shell. No terminal to be created...")
		}
	case "keepalive@openssh.com":
	case "window-change":
		if term != nil {
			w, h, err := parseDims(req.Payload)
			if err != nil {
				return err
			}
			zap.L().Debug("Changing win size to", zap.Uint32("w", w), zap.Uint32("h", h))
			if err := term.setWinSize(uint16(w), uint16(h)); err != nil {
				return err
			}
		}
	case "exec":
		if err := c.handleSessionReqExec(ctx, sessCtx, req); err != nil {
			zap.L().Debug("Could not handle exec req", zap.Error(err))
			return err
		}
	case "env":

		key, val, err := parseEnv(req.Payload)
		if err != nil {
			return err
		}

		zap.L().Debug("Adding env var", zap.String("key", key), zap.String("val", val))
		sessCtx.env = append(sessCtx.env, &envVar{
			key: key,
			val: val,
		})
	case "subsystem":
		var payload = struct{ Value string }{}
		if err := ssh.Unmarshal(req.Payload, &payload); err != nil {
			return err
		}
		zap.L().Debug("Subsystem request", zap.String("subsystem", payload.Value))

		switch payload.Value {
		case "sftp":
			if err := c.handleSubsystemSFTP(ctx, sessCtx, req); err != nil {
				zap.L().Debug("Could not handle sftp subsystem", zap.Error(err))
				return err
			}
			return nil
		default:
			zap.L().Debug("Unsupported subsystem", zap.String("subsystem", payload.Value))
			return req.Reply(false, nil)
		}
	default:
		zap.L().Debug("Unsupported session req type", zap.String("type", req.Type))
		return req.Reply(false, nil)
	}

	if req.WantReply {
		zap.L().Debug("Replying to req with true")
		req.Reply(true, nil)
	}

	return nil
}

func (c *dctx) handleSessionReqExec(ctx context.Context, sessCtx *sessCtx, req *ssh.Request) error {
	var err error
	// var r execRequest
	zap.L().Debug("exec payload", zap.String("payload", string(req.Payload)))

	ch := sessCtx.ch

	/*
		if err := ssh.Unmarshal(req.Payload, &r); err != nil {
			return err
		}
	*/

	var payload = struct{ Value string }{}
	if err := ssh.Unmarshal(req.Payload, &payload); err != nil {
		return err
	}

	zap.L().Debug("Payload cmd", zap.String("val", payload.Value))

	cmdStr := payload.Value

	zap.L().Debug("Handling exec req", zap.String("command", cmdStr))

	usr := c.usr

	shellPath, err := getShellPath(usr.Username)
	if err != nil {
		return err
	}

	cmd := exec.CommandContext(ctx, shellPath, "-c", cmdStr)

	if !c.sameUser {
		uid, err := strconv.ParseUint(usr.Uid, 10, 32)
		if err != nil {
			return err
		}
		gid, err := strconv.ParseUint(usr.Gid, 10, 32)
		if err != nil {
			return err
		}

		cmd.SysProcAttr = &syscall.SysProcAttr{
			Credential: &syscall.Credential{Uid: uint32(uid), Gid: uint32(gid)},
		}
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

	go func() {
		io.Copy(inPipe, ch)
		inPipe.Close()
	}()

	go func(ctx context.Context) {

		waitCh := make(chan error, 1)
		go func() {
			err := cmd.Wait()
			if err != nil {
				zap.L().Debug("cmd wait err", zap.Error(err))
			}
			waitCh <- err
		}()

		select {
		case <-ctx.Done():
			zap.L().Debug("ctx done. Exiting exec...")
			if cmd.Process != nil {
				cmd.Process.Kill()
			}

			sessCtx.sendSessionExitStatus(130)

		case err := <-waitCh:
			zap.L().Debug("cmd wait done...", zap.Error(err))
			if err == nil {
				sessCtx.sendSessionExitStatus(0)
			} else if exiterr, ok := err.(*exec.ExitError); ok {
				zap.L().Debug("exit code....", zap.Int("code", exiterr.ExitCode()))
				sessCtx.sendSessionExitStatus(exiterr.ExitCode())
			}
		}

		// c.close()
		ch.Close()

		// zap.L().Debug("ssh channel closed")

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

	if req.WantReply {
		if err := req.Reply(true, nil); err != nil {
			return err
		}
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

	go func() {
		defer ch.Close()

		errCh := make(chan error, 1)
		go func() {
			errCh <- srv.Serve()
		}()

		select {
		case <-ctx.Done():
			srv.Close()
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

	switch {
	case strings.HasPrefix(key, "LC_"):
	default:
		switch key {
		case "LANG", "TERM":
		default:
			return "", "", errors.Errorf("Unsupported env var key: %s", key)
		}
	}

	return key, val, nil
}
