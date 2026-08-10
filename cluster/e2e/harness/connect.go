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

package harness

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/octelium/octelium/apis/main/userv1"
	"github.com/octelium/octelium/pkg/common/pbutils"
	"github.com/pkg/errors"
	"go.uber.org/zap"
)

const ConnectBudget = 90 * time.Second

type ConnectOpts struct {
	Publish        map[string]int
	PublishOrdered []PublishSpec
	Serve          []string
	ServeAll       bool
	UseESSH        bool
	TunnelMode     string
	Root           bool
	Args           []string
}

type PublishSpec struct {
	Service string
	Port    int
}

type Conn struct {
	h   *H
	cmd *exec.Cmd

	ports map[string]int
}

func (c *Conn) Port(svc string) int {
	return c.ports[svc]
}

func (c *Conn) URL(svc string) string {
	return fmt.Sprintf("http://localhost:%d", c.ports[svc])
}

func (c *Conn) Addr(svc string) string {
	return fmt.Sprintf("localhost:%d", c.ports[svc])
}

func (c *Conn) Disconnect() error {
	if c.cmd == nil || c.cmd.ProcessState != nil {
		return nil
	}

	if err := c.h.Run(context.Background(), "octelium disconnect"); err != nil {
		return err
	}

	c.cmd.Wait()
	zap.L().Debug("octelium connect exited")
	return nil
}

func (h *H) Connect(t *testing.T, o ConnectOpts) *Conn {
	t.Helper()

	conn, err := h.connect(t, o)
	if err != nil {
		t.Fatalf("Could not connect: %+v", err)
	}

	return conn
}

func (h *H) connect(t *testing.T, o ConnectOpts) (*Conn, error) {
	ports := map[string]int{}
	var args []string

	names := make([]string, 0, len(o.Publish))
	for name := range o.Publish {
		names = append(names, name)
	}
	sort.Strings(names)

	for _, name := range names {
		ports[name] = o.Publish[name]
		args = append(args, fmt.Sprintf("-p %s:%d", name, o.Publish[name]))
	}

	for _, spec := range o.PublishOrdered {
		ports[spec.Service] = spec.Port
		args = append(args, fmt.Sprintf("-p %s:%d", spec.Service, spec.Port))
	}

	for _, svc := range o.Serve {
		args = append(args, fmt.Sprintf("--serve %s", svc))
	}
	if o.ServeAll {
		args = append(args, "--serve-all")
	}
	if o.UseESSH {
		args = append(args, "--essh")
	}
	if o.TunnelMode != "" {
		args = append(args, fmt.Sprintf("--tunnel-mode %s", o.TunnelMode))
	}
	args = append(args, o.Args...)

	bin := "octelium connect"
	if o.Root {
		bin = "sudo -E octelium connect"
	}

	cmdStr := bin
	if len(args) > 0 {
		cmdStr = fmt.Sprintf("%s %s", bin, strings.Join(args, " "))
	}

	ret := &Conn{
		h:     h,
		ports: ports,
	}

	cmd := h.Cmd(h.rootCtx, cmdStr)

	cmd.Env = append(os.Environ(), "OCTELIUM_DEV=true")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	zap.L().Debug("Running cmd", zap.String("cmd", cmdStr))
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	ret.cmd = cmd

	t.Cleanup(func() {
		if err := ret.Disconnect(); err != nil {
			zap.L().Warn("Could not cleanly disconnect", zap.Error(err))
		}
		if cmd.Process != nil && cmd.ProcessState == nil {
			cmd.Process.Kill()
			cmd.Wait()
		}
	})

	if err := h.waitConnected(t.Context()); err != nil {
		return nil, err
	}

	for _, port := range ports {
		if err := WaitPortOpen(port, ConnectBudget); err != nil {
			return nil, err
		}
	}

	return ret, nil
}

func (h *H) waitConnected(ctx context.Context) error {
	return h.EventuallyErr(ctx, "octelium connect to report a connected Session",
		ConnectBudget, func(ctx context.Context) error {
			out, err := h.Output(ctx, "octelium status -o json")
			if err != nil {
				return errors.Errorf("octelium status failed: %+v: %s", err, out)
			}

			status := &userv1.GetStatusResponse{}
			if err := pbutils.UnmarshalJSON(out, status); err != nil {
				return errors.Errorf("could not parse octelium status: %+v: %s", err, out)
			}

			if status.Session == nil || status.Session.Status == nil {
				return errors.Errorf("no Session in octelium status yet")
			}
			if !status.Session.Status.IsConnected {
				return errors.Errorf("the Session is not connected yet")
			}

			return nil
		})
}

func (h *H) Status(t *testing.T) *userv1.GetStatusResponse {
	t.Helper()

	ret := &userv1.GetStatusResponse{}
	h.MustOutputProto(t, "octelium status -o json", ret)
	return ret
}
