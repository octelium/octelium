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

package deviceprobe

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/octelium/octelium/apis/main/authv1"
	"github.com/stretchr/testify/assert"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func lookPath(t *testing.T, name string) string {
	ret, err := exec.LookPath(name)
	if err != nil {
		t.Skipf("Could not find %s: %+v", name, err)
	}
	ret, err = filepath.Abs(ret)
	assert.Nil(t, err)
	return ret
}

func TestLimitedBuffer(t *testing.T) {
	b := &limitedBuffer{limit: 5}

	n, err := b.Write([]byte("abc"))
	assert.Nil(t, err)
	assert.Equal(t, 3, n)
	assert.False(t, b.isTruncated)

	n, err = b.Write([]byte("defg"))
	assert.Nil(t, err)
	assert.Equal(t, 4, n)
	assert.True(t, b.isTruncated)
	assert.Equal(t, []byte("abcde"), b.buf)

	n, err = b.Write([]byte("h"))
	assert.Nil(t, err)
	assert.Equal(t, 1, n)
	assert.Equal(t, []byte("abcde"), b.buf)
}

func TestRunCommand(t *testing.T) {
	ctx := context.Background()

	echo := lookPath(t, "echo")
	sh := lookPath(t, "sh")
	sleep := lookPath(t, "sleep")
	head := lookPath(t, "head")
	env := lookPath(t, "env")

	run := func(command string, args []string, timeout, maxOutput uint32) *authv1.DeviceProbeResult {
		return runCommand(ctx, "probe", &authv1.DeviceProbe_RunCommand{
			Command:        command,
			Args:           args,
			TimeoutSeconds: timeout,
			MaxOutputBytes: maxOutput,
		})
	}

	{
		res := run(echo, []string{"hello"}, 0, 0)
		assert.Equal(t, authv1.DeviceProbeResult_OK, res.Status)
		assert.Equal(t, "hello\n", res.GetText())
		assert.Equal(t, "probe", res.ProbeID)
		assert.False(t, res.IsTruncated)
	}

	{
		res := run(echo, []string{"other", "args"}, 0, 0)
		assert.Equal(t, authv1.DeviceProbeResult_OK, res.Status)
		assert.Equal(t, "other args\n", res.GetText())
	}

	{
		res := run("echo", []string{"hello"}, 0, 0)
		assert.Equal(t, authv1.DeviceProbeResult_FAILED, res.Status)
	}

	{
		res := run("/nonexistent/octelium/cmd", nil, 0, 0)
		assert.Equal(t, authv1.DeviceProbeResult_NOT_FOUND, res.Status)
	}

	{
		res := run(sh, []string{"-c", "echo out; exit 3"}, 0, 0)
		assert.Equal(t, authv1.DeviceProbeResult_FAILED, res.Status)
		assert.Equal(t, int32(3), res.ExitCode)
		assert.Equal(t, "out\n", res.GetText())
		assert.NotEmpty(t, res.Detail)
	}

	{
		startedAt := time.Now()
		res := run(sleep, []string{"5"}, 1, 0)
		assert.Equal(t, authv1.DeviceProbeResult_TIMEOUT, res.Status)
		assert.Less(t, time.Since(startedAt), 4*time.Second)
	}

	{
		startedAt := time.Now()
		res := run(sh, []string{"-c", "sleep 30 & echo hi"}, 20, 0)
		assert.Equal(t, authv1.DeviceProbeResult_OK, res.Status)
		assert.Equal(t, "hi\n", res.GetText())
		assert.Less(t, time.Since(startedAt), 10*time.Second,
			"a descendant holding the output open must not block the probe")
	}

	{
		res := run(head, []string{"-c", "100000", "/dev/zero"}, 0, 1000)
		assert.Equal(t, authv1.DeviceProbeResult_OK, res.Status)
		assert.True(t, res.IsTruncated)
		assert.Equal(t, 1000, getResultSize(res))
	}

	{
		t.Setenv("OCTELIUM_TEST_PROBE_SECRET", "secret-value")
		res := run(env, nil, 0, 0)
		assert.Equal(t, authv1.DeviceProbeResult_OK, res.Status)
		assert.NotContains(t, res.GetText(), "secret-value")
		assert.Contains(t, res.GetText(), "PATH=")
	}
}

func TestReadFile(t *testing.T) {
	dir := t.TempDir()
	outside := t.TempDir()

	textFile := filepath.Join(dir, "text")
	assert.Nil(t, os.WriteFile(textFile, []byte("content"), 0600))

	binFile := filepath.Join(dir, "bin")
	assert.Nil(t, os.WriteFile(binFile, []byte{0xff, 0xfe, 0x00, 0x01}, 0600))

	outsideFile := filepath.Join(outside, "outside")
	assert.Nil(t, os.WriteFile(outsideFile, []byte("outside"), 0600))

	link := filepath.Join(dir, "link")
	assert.Nil(t, os.Symlink(outsideFile, link))

	subDir := filepath.Join(dir, "sub")
	assert.Nil(t, os.Mkdir(subDir, 0700))

	fifo := filepath.Join(dir, "fifo")
	assert.Nil(t, syscall.Mkfifo(fifo, 0600))

	{
		res := readFile("probe", textFile, 0)
		assert.Equal(t, authv1.DeviceProbeResult_OK, res.Status)
		assert.Equal(t, "content", res.GetText())
		assert.False(t, res.IsTruncated)
	}

	{
		res := readFile("probe", textFile, 3)
		assert.Equal(t, authv1.DeviceProbeResult_OK, res.Status)
		assert.Equal(t, "con", res.GetText())
		assert.True(t, res.IsTruncated)
	}

	{
		largeFile := filepath.Join(dir, "large")
		assert.Nil(t, os.WriteFile(largeFile, []byte(strings.Repeat("a", 20*1024)), 0600))

		res := readFile("probe", largeFile, 0)
		assert.Equal(t, authv1.DeviceProbeResult_OK, res.Status)
		assert.True(t, res.IsTruncated)
		assert.Equal(t, defaultMaxOutput, getResultSize(res),
			"an omitted limit must be the Cluster's default limit")
	}

	{
		res := readFile("probe", binFile, 0)
		assert.Equal(t, authv1.DeviceProbeResult_OK, res.Status)
		assert.Equal(t, []byte{0xff, 0xfe, 0x00, 0x01}, res.GetData())
	}

	{
		res := readFile("probe", outsideFile, 0)
		assert.Equal(t, authv1.DeviceProbeResult_OK, res.Status)
		assert.Equal(t, "outside", res.GetText())
	}

	{
		res := readFile("probe", link, 0)
		assert.Equal(t, authv1.DeviceProbeResult_OK, res.Status)
		assert.Equal(t, "outside", res.GetText())
	}

	{
		res := readFile("probe", subDir, 0)
		assert.Equal(t, authv1.DeviceProbeResult_FAILED, res.Status)
	}

	{
		startedAt := time.Now()
		res := readFile("probe", fifo, 0)
		assert.Equal(t, authv1.DeviceProbeResult_FAILED, res.Status)
		assert.Less(t, time.Since(startedAt), 2*time.Second, "reading a FIFO must not block")
	}

	{
		res := readFile("probe", filepath.Join(dir, "missing"), 0)
		assert.Equal(t, authv1.DeviceProbeResult_NOT_FOUND, res.Status)
	}

	{
		res := readFile("probe", "relative/path", 0)
		assert.Equal(t, authv1.DeviceProbeResult_FAILED, res.Status)
	}
}

func TestExecute(t *testing.T) {
	ctx := context.Background()

	for _, p := range []*authv1.DeviceProbe{
		{
			ProbeID: "none",
		},
		{
			ProbeID: "identifier",
			Type: &authv1.DeviceProbe_PlatformIdentifier_{
				PlatformIdentifier: &authv1.DeviceProbe_PlatformIdentifier{
					Kind: authv1.DeviceProbe_PlatformIdentifier_Kind(100),
				},
			},
		},
	} {
		res := execute(ctx, p)
		assert.Equal(t, authv1.DeviceProbeResult_UNSUPPORTED, res.Status, "probe: %s", p.ProbeID)
		assert.Equal(t, p.ProbeID, res.ProbeID)
	}

	{
		res := execute(ctx, &authv1.DeviceProbe{
			ProbeID: "registry",
			Type: &authv1.DeviceProbe_ReadRegistry_{
				ReadRegistry: &authv1.DeviceProbe_ReadRegistry{
					Key:  `HKLM\SOFTWARE\Vendor`,
					Name: "Name",
				},
			},
		})
		assert.Equal(t, authv1.DeviceProbeResult_UNSUPPORTED, res.Status)
	}

	{
		echo := lookPath(t, "echo")
		res := execute(ctx, &authv1.DeviceProbe{
			ProbeID: "cmd",
			Type: &authv1.DeviceProbe_RunCommand_{
				RunCommand: &authv1.DeviceProbe_RunCommand{
					Command: echo,
					Args:    []string{"cmd"},
				},
			},
		})
		assert.Equal(t, authv1.DeviceProbeResult_OK, res.Status)
		assert.Equal(t, "cmd\n", res.GetText())
	}

	{
		pth := filepath.Join(t.TempDir(), "file")
		assert.Nil(t, os.WriteFile(pth, []byte("file"), 0600))

		res := execute(ctx, &authv1.DeviceProbe{
			ProbeID: "file",
			Type: &authv1.DeviceProbe_ReadFile_{
				ReadFile: &authv1.DeviceProbe_ReadFile{
					Path: pth,
				},
			},
		})
		assert.Equal(t, authv1.DeviceProbeResult_OK, res.Status)
		assert.Equal(t, "file", res.GetText())
	}

	{
		res := execute(ctx, &authv1.DeviceProbe{
			ProbeID: "macs",
			Type: &authv1.DeviceProbe_PlatformIdentifier_{
				PlatformIdentifier: &authv1.DeviceProbe_PlatformIdentifier{
					Kind: authv1.DeviceProbe_PlatformIdentifier_MAC_ADDRESS,
				},
			},
		})

		switch res.Status {
		case authv1.DeviceProbeResult_OK:
			assert.NotEmpty(t, res.GetList().GetItems())
		case authv1.DeviceProbeResult_NOT_FOUND:
		default:
			t.Fatalf("Unexpected status: %s", res.Status)
		}
	}

	if !isElevated() {
		res := execute(ctx, &authv1.DeviceProbe{
			ProbeID:          "elevated",
			RequireElevation: true,
			Type: &authv1.DeviceProbe_PlatformIdentifier_{
				PlatformIdentifier: &authv1.DeviceProbe_PlatformIdentifier{
					Kind: authv1.DeviceProbe_PlatformIdentifier_HARDWARE_UUID,
				},
			},
		})
		assert.Equal(t, authv1.DeviceProbeResult_PERMISSION_REQUIRED, res.Status)
	}
}

func TestRunProbes(t *testing.T) {
	ctx := context.Background()

	echo := lookPath(t, "echo")
	head := lookPath(t, "head")

	cmdProbe := func(id, command string, maxOutput uint32, args ...string) *authv1.DeviceProbe {
		return &authv1.DeviceProbe{
			ProbeID: id,
			Type: &authv1.DeviceProbe_RunCommand_{
				RunCommand: &authv1.DeviceProbe_RunCommand{
					Command:        command,
					Args:           args,
					MaxOutputBytes: maxOutput,
				},
			},
		}
	}

	{
		results := runProbes(ctx, []*authv1.DeviceProbe{
			nil,
			cmdProbe("p1", "echo", 0, "relative"),
			cmdProbe("p2", echo, 0, "first"),
			cmdProbe("p3", echo, 0, "second"),
		})

		assert.Equal(t, 3, len(results))
		assert.Equal(t, "p1", results[0].ProbeID)
		assert.Equal(t, authv1.DeviceProbeResult_FAILED, results[0].Status)
		assert.Equal(t, authv1.DeviceProbeResult_OK, results[1].Status)
		assert.Equal(t, "first\n", results[1].GetText())
		assert.Equal(t, authv1.DeviceProbeResult_OK, results[2].Status)
		assert.Equal(t, "second\n", results[2].GetText())
	}

	{
		results := runProbes(ctx, []*authv1.DeviceProbe{
			cmdProbe("p1", head, maxOutputBytes, "-c", "65536", "/dev/zero"),
			cmdProbe("p2", head, maxOutputBytes, "-c", "65536", "/dev/zero"),
			cmdProbe("p3", echo, 0, "first"),
		})

		assert.Equal(t, authv1.DeviceProbeResult_OK, results[0].Status)
		assert.Equal(t, maxOutputBytes, getResultSize(results[0]))
		assert.Equal(t, authv1.DeviceProbeResult_OK, results[1].Status)
		assert.Equal(t, authv1.DeviceProbeResult_FAILED, results[2].Status,
			"the output of an attempt must not exceed its total limit")
		assert.Nil(t, results[2].Value)
	}

	{
		cctx, cancel := context.WithCancel(ctx)
		cancel()

		results := runProbes(cctx, []*authv1.DeviceProbe{
			cmdProbe("p1", echo, 0, "first"),
		})

		assert.Equal(t, authv1.DeviceProbeResult_TIMEOUT, results[0].Status)
	}
}

type fakeAuthClient struct {
	authv1.MainServiceClient

	beginReq  *authv1.RunDeviceProbeBeginRequest
	beginResp *authv1.RunDeviceProbeBeginResponse
	beginErr  error

	finishReq *authv1.RunDeviceProbeFinishRequest
	finishErr error
}

func (c *fakeAuthClient) RunDeviceProbeBegin(ctx context.Context,
	in *authv1.RunDeviceProbeBeginRequest, opts ...grpc.CallOption) (*authv1.RunDeviceProbeBeginResponse, error) {
	c.beginReq = in
	if c.beginErr != nil {
		return nil, c.beginErr
	}
	return c.beginResp, nil
}

func (c *fakeAuthClient) RunDeviceProbeFinish(ctx context.Context,
	in *authv1.RunDeviceProbeFinishRequest, opts ...grpc.CallOption) (*authv1.RunDeviceProbeFinishResponse, error) {
	c.finishReq = in
	if c.finishErr != nil {
		return nil, c.finishErr
	}
	return &authv1.RunDeviceProbeFinishResponse{}, nil
}

func TestRun(t *testing.T) {
	ctx := context.Background()

	echo := lookPath(t, "echo")

	beginResp := func() *authv1.RunDeviceProbeBeginResponse {
		return &authv1.RunDeviceProbeBeginResponse{
			AttemptUID: "attempt",
			Probes: []*authv1.DeviceProbe{
				{
					ProbeID: "p1",
					Type: &authv1.DeviceProbe_RunCommand_{
						RunCommand: &authv1.DeviceProbe_RunCommand{
							Command: echo,
							Args:    []string{"aid"},
						},
					},
				},
				{
					ProbeID: "p2",
					Type: &authv1.DeviceProbe_PlatformIdentifier_{
						PlatformIdentifier: &authv1.DeviceProbe_PlatformIdentifier{
							Kind: authv1.DeviceProbe_PlatformIdentifier_Kind(100),
						},
					},
				},
			},
		}
	}

	{
		c := &fakeAuthClient{
			beginResp: beginResp(),
		}

		err := Run(ctx, c)
		assert.Nil(t, err)

		assert.NotNil(t, c.beginReq)

		assert.NotNil(t, c.finishReq)
		assert.Equal(t, "attempt", c.finishReq.AttemptUID)
		assert.Equal(t, 2, len(c.finishReq.Results))
		assert.Equal(t, "aid\n", c.finishReq.Results[0].GetText())
		assert.Equal(t, authv1.DeviceProbeResult_UNSUPPORTED, c.finishReq.Results[1].Status)
	}

	for i, resp := range []*authv1.RunDeviceProbeBeginResponse{
		{},
		{
			AttemptUID: "attempt",
		},
		{
			Probes: beginResp().Probes,
		},
	} {
		c := &fakeAuthClient{
			beginResp: resp,
		}

		assert.Nil(t, Run(ctx, c))
		assert.Nil(t, c.finishReq, "response: %d", i)
	}

	{
		c := &fakeAuthClient{
			beginErr: status.Error(codes.Unimplemented, "unimplemented"),
		}
		assert.Nil(t, Run(ctx, c))
		assert.Nil(t, c.finishReq)
	}

	{
		c := &fakeAuthClient{
			beginErr: status.Error(codes.PermissionDenied, "denied"),
		}
		assert.NotNil(t, Run(ctx, c))
	}

	{
		c := &fakeAuthClient{
			beginResp: beginResp(),
			finishErr: status.Error(codes.Unimplemented, "unimplemented"),
		}
		assert.Nil(t, Run(ctx, c))
	}

	{
		c := &fakeAuthClient{
			beginResp: beginResp(),
			finishErr: status.Error(codes.InvalidArgument, "invalid"),
		}
		assert.NotNil(t, Run(ctx, c))
	}
}
