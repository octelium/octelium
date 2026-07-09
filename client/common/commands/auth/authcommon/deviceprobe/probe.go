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

package deviceprobe

import (
	"context"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"github.com/octelium/octelium/apis/main/authv1"
	"github.com/octelium/octelium/pkg/grpcerr"
	"github.com/pkg/errors"
)

const (
	defaultTimeout   = 15 * time.Second
	defaultMaxOutput = 1 << 15
)

func Run(ctx context.Context, client authv1.MainServiceClient) error {
	begin, err := client.RunDeviceProbeBegin(ctx, &authv1.RunDeviceProbeBeginRequest{})
	if err != nil {
		if grpcerr.IsUnimplemented(err) {
			return nil
		}
		return err
	}
	if len(begin.Probes) == 0 {
		return nil
	}

	results := make([]*authv1.DeviceProbeResult, 0, len(begin.Probes))
	for _, p := range begin.Probes {
		results = append(results, execute(ctx, p))
	}

	if _, err := client.RunDeviceProbeFinish(ctx, &authv1.RunDeviceProbeFinishRequest{
		Results: results,
	}); err != nil {
		if grpcerr.IsUnimplemented(err) {
			return nil
		}
		return err
	}
	return nil
}

func execute(ctx context.Context, p *authv1.DeviceProbe) *authv1.DeviceProbeResult {

	if p.RequireElevation && !isElevated() {
		return probeErr(p.Uid, "probe requires elevated privileges")
	}

	switch t := p.Type.(type) {
	case *authv1.DeviceProbe_RunCommand_:
		out, err := runCommand(ctx, t.RunCommand)
		if err != nil {
			return probeErr(p.Uid, err.Error())
		}
		return probeOut(p.Uid, out)
	case *authv1.DeviceProbe_ReadFile_:
		out, err := readFile(t.ReadFile)
		if err != nil {
			return probeErr(p.Uid, err.Error())
		}
		return probeOut(p.Uid, out)
	case *authv1.DeviceProbe_ReadRegistry_:
		out, err := readRegistry(t.ReadRegistry)
		if err != nil {
			return probeErr(p.Uid, err.Error())
		}
		return probeOut(p.Uid, out)
	default:
		return probeErr(p.Uid, "unknown probe type")
	}
}

func runCommand(ctx context.Context, rc *authv1.DeviceProbe_RunCommand) ([]byte, error) {
	if !filepath.IsAbs(rc.Command) {
		return nil, errors.Errorf("probe command must be an absolute path")
	}

	timeout := time.Duration(rc.TimeoutSeconds) * time.Second
	if timeout <= 0 {
		timeout = defaultTimeout
	}
	cctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	cmd := exec.CommandContext(cctx, rc.Command, rc.Args...)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	if err := cmd.Start(); err != nil {
		return nil, err
	}

	limit := int64(rc.MaxOutputBytes)
	if limit <= 0 {
		limit = defaultMaxOutput
	}
	out, _ := io.ReadAll(io.LimitReader(stdout, limit))
	waitErr := cmd.Wait()
	if len(out) == 0 && waitErr != nil {
		return nil, waitErr
	}
	return out, nil
}

func readFile(rf *authv1.DeviceProbe_ReadFile) ([]byte, error) {
	if !filepath.IsAbs(rf.Path) {
		return nil, errors.Errorf("probe file path must be absolute")
	}
	f, err := os.Open(rf.Path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	limit := int64(rf.MaxBytes)
	if limit <= 0 {
		limit = defaultMaxOutput
	}
	return io.ReadAll(io.LimitReader(f, limit))
}

func probeOut(uid string, out []byte) *authv1.DeviceProbeResult {
	return &authv1.DeviceProbeResult{
		Uid:  uid,
		Type: &authv1.DeviceProbeResult_Output{Output: out},
	}
}

func probeErr(uid, msg string) *authv1.DeviceProbeResult {
	return &authv1.DeviceProbeResult{
		Uid:  uid,
		Type: &authv1.DeviceProbeResult_Error{Error: msg},
	}
}
