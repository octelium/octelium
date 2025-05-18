/*
 * Copyright Octelium Labs, LLC. All rights reserved.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License version 3,
 * as published by the Free Software Foundation of the License.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

package ssh

import (
	"context"
	"fmt"
	"io"
	"time"

	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/cluster/common/otelutils"
	"github.com/octelium/octelium/cluster/vigil/vigil/logentry"
	"github.com/octelium/octelium/pkg/utils/utilrand"
	"go.uber.org/zap"
	"golang.org/x/crypto/ssh"
)

func (c *dctx) runSessionLoop(ctx context.Context,
	downstreamReqs, upstreamReqs <-chan *ssh.Request, downstreamCh, upstreamCh ssh.Channel) {
	zap.S().Debugf("Starting session's proxy loop for %+v", c.id)
	startTime := time.Now()
	sessionID := fmt.Sprintf("%s-%s", c.id, utilrand.GetRandomStringLowercase(6))

	closerChan := make(chan bool, 2)

	recorder := newRecorder(c, sessionID)
	recorder.run(ctx)

	stdinWriter := recorder.getStdinWriter()
	stdoutWriter := recorder.getStdoutWriter()

	go func() {
		mult := io.MultiWriter(downstreamCh, stdoutWriter)
		n, err := io.Copy(mult, upstreamCh)
		closerChan <- true
		zap.S().Debugf("Upstream goroutine ended: %d, %+v", n, err)
	}()

	go func() {
		mult := io.MultiWriter(upstreamCh, stdinWriter)
		n, err := io.Copy(mult, downstreamCh)
		closerChan <- true
		zap.S().Debugf("Downstream goroutine ended: %d, %+v", n, err)
	}()

	logE := logentry.InitializeLogEntry(&logentry.InitializeLogEntryOpts{
		StartTime:       startTime,
		IsAuthenticated: true,
		IsAuthorized:    true,
		ReqCtx:          c.i,
		ConnectionID:    c.id,
		SessionID:       sessionID,
		Reason:          c.reasonInit,
	})
	logE.Entry.Info.Type = &corev1.AccessLog_Entry_Info_Ssh{
		Ssh: &corev1.AccessLog_Entry_Info_SSH{
			Type: corev1.AccessLog_Entry_Info_SSH_SESSION_START,
		},
	}
	otelutils.EmitAccessLog(logE)

	defer func() {
		logE := logentry.InitializeLogEntry(&logentry.InitializeLogEntryOpts{
			StartTime:       startTime,
			IsAuthenticated: true,
			IsAuthorized:    true,
			ReqCtx:          c.i,
			ConnectionID:    c.id,
			SessionID:       sessionID,
			Reason:          c.reasonInit,
		})

		logE.Entry.Info.Type = &corev1.AccessLog_Entry_Info_Ssh{
			Ssh: &corev1.AccessLog_Entry_Info_SSH{
				Type: corev1.AccessLog_Entry_Info_SSH_SESSION_END,
			},
		}
		otelutils.EmitAccessLog(logE)
	}()

	for {
		select {
		case req, ok := <-downstreamReqs:
			if !ok || req == nil {
				zap.L().Debug("No more downstream reqs. Exiting doProxy...")
				return
			}
			zap.S().Debugf("Downstream Req: %s", req.Type)
			if err := c.handleSessionDownstreamReq(req, upstreamCh, sessionID); err != nil {
				zap.S().Debugf("Downstream req err: %+v", err)
			}

		case req, ok := <-upstreamReqs:
			if !ok || req == nil {
				zap.L().Debug("No more upstream reqs. Exiting doProxy...")
				return
			}
			zap.S().Debugf("Upstream Req: %s", req.Type)

			if err := c.handleSessionUpstreamReq(req, downstreamCh); err != nil {
				zap.S().Debugf("Upstream req err: %+v", err)
			}

		case <-closerChan:
			zap.S().Debugf("Exiting doProxy for %+v", c.id)
			return
		}
	}
}

func (c *dctx) handleSessionDownstreamReq(req *ssh.Request, ch ssh.Channel, sessionID string) error {
	zap.S().Debugf("New session req: %s for dctx: %s", req.Type, c.id)

	switch req.Type {
	case "keepalive@openssh.com":
		if req.WantReply {
			return req.Reply(true, nil)
		}
		return nil
	case "pty-req", "shell", "exec", "window-change", "signal", "env":
		ok, err := ch.SendRequest(req.Type, req.WantReply, req.Payload)
		if err != nil {
			return err
		}

		if req.WantReply {
			req.Reply(ok, nil)
		}
	case "subsystem":
		svcCfg := c.svcConfig
		if svcCfg == nil || svcCfg.GetSsh() == nil || !svcCfg.GetSsh().EnableSubsystem {
			return req.Reply(false, []byte("Subsystem requests are not supported"))
		}

		ok, err := ch.SendRequest(req.Type, req.WantReply, req.Payload)
		if err != nil {
			return err
		}

		if req.WantReply {
			req.Reply(ok, nil)
		}
	default:
		zap.S().Debugf("Unsupported session req: %s", req.Type)
		return req.Reply(false, nil)
	}

	return c.setLogSessionDownstreamReq(req, sessionID)
}

func (c *dctx) handleSessionUpstreamReq(req *ssh.Request, ch ssh.Channel) error {
	zap.S().Debugf("New session req: %s for dctx: %s", req.Type, c.id)
	switch req.Type {
	case "pty-req", "shell", "exec", "window-change", "exit-status", "signal", "env", "subsystem":
		ok, err := ch.SendRequest(req.Type, req.WantReply, req.Payload)
		if err != nil {
			return err
		}

		if req.WantReply {
			req.Reply(ok, nil)
		}
	case "keepalive@openssh.com":
		if req.WantReply {
			return req.Reply(true, nil)
		}
	default:
		zap.S().Debugf("Unsupported session req: %s", req.Type)
		return req.Reply(false, nil)
	}

	return nil
}

func (c *dctx) handleSessionRequests(ctx context.Context, newChannel ssh.NewChannel) {
	zap.S().Debugf("Handling session requests for %+v", c.id)

	{
		c.mu.Lock()
		if c.sessions >= 10 {
			c.mu.Unlock()
			zap.L().Debug("Maximum sessions reached")
			newChannel.Reject(ssh.ResourceShortage, "Maximum sessions reached")
			return
		}

		c.mu.Unlock()
	}

	zap.S().Debugf("Accepting a new session channel")

	sesschan, reqs, err := newChannel.Accept()
	if err != nil {
		zap.L().Debug("Could not accept a new channel", zap.Error(err))
		return
	}

	c.mu.Lock()
	c.sessions = c.sessions + 1
	c.mu.Unlock()

	defer sesschan.Close()

	stderr := sesschan.Stderr()

	zap.S().Debugf("Opening a new remote session channel")

	upstreamCh, upstreamReqs, err := c.remoteConn.sshClient.OpenChannel("session", []byte{})
	if err != nil {
		zap.L().Debug("Could not open channel on upstream", zap.Error(err))
		fmt.Fprintf(stderr, "Could not open channel on upstream\r\n")
		return
	}

	defer upstreamCh.Close()

	c.runSessionLoop(ctx, reqs, upstreamReqs, sesschan, upstreamCh)
	zap.S().Debugf("proxy loop ended for session of dctx: %+v", c.id)
}

func (c *dctx) setLogSessionDownstreamReq(req *ssh.Request, sessionID string) error {
	logE := logentry.InitializeLogEntry(&logentry.InitializeLogEntryOpts{
		StartTime:       time.Now(),
		IsAuthenticated: true,
		IsAuthorized:    true,
		ReqCtx:          c.i,
		SessionID:       sessionID,
		Reason:          c.reasonInit,
	})
	logE.Entry.Info.Type = &corev1.AccessLog_Entry_Info_Ssh{
		Ssh: &corev1.AccessLog_Entry_Info_SSH{},
	}

	switch req.Type {
	case "exec":
		msg := &reqExec{}
		if err := ssh.Unmarshal(req.Payload, msg); err != nil {
			return err
		}
		logE.Entry.Info.GetSsh().Type = corev1.AccessLog_Entry_Info_SSH_SESSION_REQUEST_EXEC
		logE.Entry.Info.GetSsh().Details = &corev1.AccessLog_Entry_Info_SSH_SessionRequestExec_{
			SessionRequestExec: &corev1.AccessLog_Entry_Info_SSH_SessionRequestExec{
				Command: msg.Command,
			},
		}
	case "shell":
		logE.Entry.Info.GetSsh().Type = corev1.AccessLog_Entry_Info_SSH_SESSION_REQUEST_SHELL
	case "subsystem":
		msg := &reqSubsystem{}
		if err := ssh.Unmarshal(req.Payload, msg); err != nil {
			return err
		}
		logE.Entry.Info.GetSsh().Type = corev1.AccessLog_Entry_Info_SSH_SESSION_REQUEST_SUBSYSTEM
		logE.Entry.Info.GetSsh().Details = &corev1.AccessLog_Entry_Info_SSH_SessionRequestSubsystem_{
			SessionRequestSubsystem: &corev1.AccessLog_Entry_Info_SSH_SessionRequestSubsystem{
				Name: msg.Name,
			},
		}
	}
	return nil
}

type reqExec struct {
	Command string
}

type reqEnv struct {
	Name  string
	Value string
}

type reqSubsystem struct {
	Name string
}

type reqWindowChange struct {
	W   uint32
	H   uint32
	Wpx uint32
	Hpx uint32
}

type reqPTYReq struct {
	Env   string
	W     uint32
	H     uint32
	Wpx   uint32
	Hpx   uint32
	Modes string
}
