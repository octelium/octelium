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
	"errors"
	"io"
	"io/fs"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/octelium/octelium/apis/main/authv1"
	"github.com/octelium/octelium/client/common/cliutils/deviceinfo"
	"github.com/octelium/octelium/pkg/grpcerr"
)

const (
	defaultTimeout = 15 * time.Second
	maxTimeout     = 60 * time.Second

	defaultMaxOutput = 1 << 14
	maxOutputBytes   = 1 << 16

	maxTotalBytes      = 128 * 1024
	maxAttemptDuration = 5 * time.Minute

	maxListItems   = 256
	maxListItemLen = 1024

	maxErrLen = 2048

	cmdWaitDelay = 3 * time.Second
)

func Run(ctx context.Context, client authv1.MainServiceClient) error {
	begin, err := client.RunDeviceProbeBegin(ctx, &authv1.RunDeviceProbeBeginRequest{})
	if err != nil {
		if grpcerr.IsUnimplemented(err) {
			return nil
		}
		return err
	}
	if begin.AttemptUID == "" || len(begin.Probes) == 0 {
		return nil
	}

	if _, err := client.RunDeviceProbeFinish(ctx, &authv1.RunDeviceProbeFinishRequest{
		AttemptUID: begin.AttemptUID,
		Results:    runProbes(ctx, begin.Probes),
	}); err != nil {
		if grpcerr.IsUnimplemented(err) {
			return nil
		}
		return err
	}
	return nil
}

func runProbes(ctx context.Context, probes []*authv1.DeviceProbe) []*authv1.DeviceProbeResult {
	cctx, cancel := context.WithTimeout(ctx, maxAttemptDuration)
	defer cancel()

	totalBytes := 0

	results := make([]*authv1.DeviceProbeResult, 0, len(probes))
	for _, p := range probes {
		if p == nil {
			continue
		}

		var res *authv1.DeviceProbeResult
		if cctx.Err() != nil {
			res = probeStatus(p.ProbeID, authv1.DeviceProbeResult_TIMEOUT, "the probe attempt duration is exceeded")
		} else {
			res = execute(cctx, p)
		}

		if !isResultWithinLimits(p, res) {
			res = probeStatus(p.ProbeID, authv1.DeviceProbeResult_FAILED, "the probe output limit is exceeded")
		}

		size := getResultSize(res)
		if totalBytes+size > maxTotalBytes {
			res = probeStatus(p.ProbeID, authv1.DeviceProbeResult_FAILED, "the probe attempt output limit is exceeded")
		} else {
			totalBytes += size
		}

		results = append(results, res)
	}

	return results
}

func execute(ctx context.Context, p *authv1.DeviceProbe) *authv1.DeviceProbeResult {
	if p.RequireElevation && !isElevated() {
		return probeStatus(p.ProbeID, authv1.DeviceProbeResult_PERMISSION_REQUIRED,
			"probe requires elevated privileges")
	}

	switch t := p.Type.(type) {
	case *authv1.DeviceProbe_RunCommand_:
		return runCommand(ctx, p.ProbeID, t.RunCommand)
	case *authv1.DeviceProbe_ReadFile_:
		return readFile(p.ProbeID, t.ReadFile.Path, t.ReadFile.MaxBytes)
	case *authv1.DeviceProbe_ReadRegistry_:
		return readRegistry(p.ProbeID, t.ReadRegistry)
	case *authv1.DeviceProbe_PlatformIdentifier_:
		return readPlatformIdentifier(ctx, p.ProbeID, t.PlatformIdentifier.Kind)
	default:
		return probeStatus(p.ProbeID, authv1.DeviceProbeResult_UNSUPPORTED, "unsupported probe type")
	}
}

type limitedBuffer struct {
	buf         []byte
	limit       int
	isTruncated bool
}

func (b *limitedBuffer) Write(p []byte) (int, error) {
	remaining := b.limit - len(b.buf)
	if remaining <= 0 {
		if len(p) > 0 {
			b.isTruncated = true
		}
		return len(p), nil
	}

	if len(p) > remaining {
		b.buf = append(b.buf, p[:remaining]...)
		b.isTruncated = true
		return len(p), nil
	}

	b.buf = append(b.buf, p...)
	return len(p), nil
}

func runCommand(ctx context.Context, probeID string, rc *authv1.DeviceProbe_RunCommand) *authv1.DeviceProbeResult {
	if !filepath.IsAbs(rc.Command) {
		return probeStatus(probeID, authv1.DeviceProbeResult_FAILED, "probe command must be an absolute path")
	}

	timeout := time.Duration(rc.TimeoutSeconds) * time.Second
	if timeout <= 0 {
		timeout = defaultTimeout
	}
	if timeout > maxTimeout {
		timeout = maxTimeout
	}

	cctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	out := &limitedBuffer{
		limit: getLimit(rc.MaxOutputBytes),
	}

	cmd := exec.CommandContext(cctx, rc.Command, rc.Args...)
	cmd.Env = getCommandEnv()
	cmd.Stdout = out
	cmd.WaitDelay = cmdWaitDelay
	setCommandProcAttrs(cmd)

	err := cmd.Run()
	cleanupCommand(cmd)

	ret := probeOut(probeID, out.buf, out.isTruncated)

	var exitErr *exec.ExitError
	switch {
	case cctx.Err() != nil:
		ret.Status = authv1.DeviceProbeResult_TIMEOUT
		ret.Detail = "the command timed out"
	case err == nil, errors.Is(err, exec.ErrWaitDelay):
	case errors.As(err, &exitErr):
		ret.Status = authv1.DeviceProbeResult_FAILED
		ret.ExitCode = int32(exitErr.ExitCode())
		ret.Detail = truncateErr(err.Error())
	default:
		ret.Status = getErrStatus(err)
		ret.Detail = truncateErr(err.Error())
	}

	return ret
}

func readFile(probeID, pth string, maxBytes uint32) *authv1.DeviceProbeResult {
	if !filepath.IsAbs(pth) {
		return probeStatus(probeID, authv1.DeviceProbeResult_FAILED, "probe file path must be absolute")
	}

	f, err := openProbeFile(pth)
	if err != nil {
		return probeErr(probeID, err)
	}
	defer f.Close()

	st, err := f.Stat()
	if err != nil {
		return probeErr(probeID, err)
	}

	if !st.Mode().IsRegular() {
		return probeStatus(probeID, authv1.DeviceProbeResult_FAILED, "the path is not a regular file")
	}

	limit := getLimit(maxBytes)

	out, err := io.ReadAll(io.LimitReader(f, int64(limit)+1))
	if err != nil {
		return probeErr(probeID, err)
	}

	isTruncated := len(out) > limit
	if isTruncated {
		out = out[:limit]
	}

	return probeOut(probeID, out, isTruncated)
}

func readPlatformIdentifier(ctx context.Context,
	probeID string, kind authv1.DeviceProbe_PlatformIdentifier_Kind) *authv1.DeviceProbeResult {

	var value string
	var err error

	switch kind {
	case authv1.DeviceProbe_PlatformIdentifier_HARDWARE_SERIAL:
		value, err = deviceinfo.GetSerialNumber(ctx)
	case authv1.DeviceProbe_PlatformIdentifier_HARDWARE_UUID:
		value, err = deviceinfo.GetHardwareUUID(ctx)
	case authv1.DeviceProbe_PlatformIdentifier_OS_INSTALLATION_ID:
		value, err = deviceinfo.GetOSInstallationID()
	case authv1.DeviceProbe_PlatformIdentifier_MAC_ADDRESS:
		addrs, err := deviceinfo.GetMacAddresses()
		if err != nil {
			return probeErr(probeID, err)
		}
		if len(addrs) == 0 {
			return probeStatus(probeID, authv1.DeviceProbeResult_NOT_FOUND, "")
		}
		return &authv1.DeviceProbeResult{
			ProbeID: probeID,
			Status:  authv1.DeviceProbeResult_OK,
			Value: &authv1.DeviceProbeResult_List_{
				List: &authv1.DeviceProbeResult_List{
					Items: addrs,
				},
			},
		}
	default:
		return probeStatus(probeID, authv1.DeviceProbeResult_UNSUPPORTED, "unsupported platform identifier")
	}

	if err != nil {
		return probeErr(probeID, err)
	}

	value = strings.TrimSpace(value)
	if value == "" {
		return probeStatus(probeID, authv1.DeviceProbeResult_NOT_FOUND, "")
	}

	return probeText(probeID, value)
}

func getLimit(declared uint32) int {
	limit := int(declared)
	if limit <= 0 {
		limit = defaultMaxOutput
	}
	if limit > maxOutputBytes {
		limit = maxOutputBytes
	}
	return limit
}

func getProbeLimit(p *authv1.DeviceProbe) int {
	switch t := p.Type.(type) {
	case *authv1.DeviceProbe_RunCommand_:
		return getLimit(t.RunCommand.MaxOutputBytes)
	case *authv1.DeviceProbe_ReadFile_:
		return getLimit(t.ReadFile.MaxBytes)
	default:
		return getLimit(0)
	}
}

func isResultWithinLimits(p *authv1.DeviceProbe, res *authv1.DeviceProbeResult) bool {
	if getResultSize(res) > getProbeLimit(p) {
		return false
	}

	items := res.GetList().GetItems()
	if len(items) > maxListItems {
		return false
	}

	for _, itm := range items {
		if len(itm) > maxListItemLen {
			return false
		}
	}

	return true
}

func getResultSize(r *authv1.DeviceProbeResult) int {
	switch r.Value.(type) {
	case *authv1.DeviceProbeResult_Text:
		return len(r.GetText())
	case *authv1.DeviceProbeResult_Data:
		return len(r.GetData())
	case *authv1.DeviceProbeResult_List_:
		ret := 0
		for _, itm := range r.GetList().GetItems() {
			ret += len(itm)
		}
		return ret
	default:
		return 0
	}
}

func getErrStatus(err error) authv1.DeviceProbeResult_Status {
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return authv1.DeviceProbeResult_NOT_FOUND
	case errors.Is(err, fs.ErrPermission):
		return authv1.DeviceProbeResult_PERMISSION_REQUIRED
	case errors.Is(err, context.DeadlineExceeded):
		return authv1.DeviceProbeResult_TIMEOUT
	default:
		return authv1.DeviceProbeResult_FAILED
	}
}

func probeOut(probeID string, out []byte, isTruncated bool) *authv1.DeviceProbeResult {
	if utf8.Valid(out) {
		return &authv1.DeviceProbeResult{
			ProbeID:     probeID,
			Status:      authv1.DeviceProbeResult_OK,
			IsTruncated: isTruncated,
			Value: &authv1.DeviceProbeResult_Text{
				Text: string(out),
			},
		}
	}

	return &authv1.DeviceProbeResult{
		ProbeID:     probeID,
		Status:      authv1.DeviceProbeResult_OK,
		IsTruncated: isTruncated,
		Value: &authv1.DeviceProbeResult_Data{
			Data: out,
		},
	}
}

func probeText(probeID, text string) *authv1.DeviceProbeResult {
	return probeOut(probeID, []byte(text), false)
}

func probeErr(probeID string, err error) *authv1.DeviceProbeResult {
	return probeStatus(probeID, getErrStatus(err), err.Error())
}

func probeStatus(probeID string, status authv1.DeviceProbeResult_Status, msg string) *authv1.DeviceProbeResult {
	return &authv1.DeviceProbeResult{
		ProbeID: probeID,
		Status:  status,
		Detail:  truncateErr(msg),
	}
}

func truncateErr(msg string) string {
	msg = strings.ToValidUTF8(msg, "")
	if len(msg) > maxErrLen {
		return strings.ToValidUTF8(msg[:maxErrLen], "")
	}
	return msg
}
