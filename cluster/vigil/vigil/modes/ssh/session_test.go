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
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/apis/main/metav1"
	"github.com/octelium/octelium/cluster/common/sshutils"
	"github.com/octelium/octelium/cluster/vigil/vigil/metricutils"
	"github.com/octelium/octelium/pkg/utils/utilrand"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
	"golang.org/x/crypto/ssh"
)

type tstExitStatus struct {
	Status uint32
}

func tstPayload(n int) []byte {
	ret := make([]byte, n)
	for i := range ret {
		ret[i] = byte('a' + (i % 26))
	}
	return ret
}

func newTstDctx(t *testing.T, skipRecording bool) *dctx {
	ctx := context.Background()

	svc := &corev1.Service{
		Metadata: &metav1.Metadata{
			Name: fmt.Sprintf("%s.default", utilrand.GetRandomStringCanonical(6)),
			Uid:  utilrand.GetRandomStringCanonical(8),
		},
		Spec: &corev1.Service_Spec{
			Mode: corev1.Service_Spec_SSH,
		},
		Status: &corev1.Service_Status{
			NamespaceRef: &metav1.ObjectReference{
				Name: "default",
			},
			RegionRef: &metav1.ObjectReference{
				Name: "default",
			},
		},
	}

	commonMetrics, err := metricutils.NewCommonMetrics(ctx, svc)
	require.Nil(t, err)

	sshMetrics, err := metricutils.NewSSHMetrics(ctx, svc)
	require.Nil(t, err)

	return &dctx{
		id:          utilrand.GetRandomStringCanonical(8),
		svc:         svc,
		createdAt:   time.Now(),
		keepAliveCh: make(chan struct{}),
		i: &corev1.RequestContext{
			Service: svc,
		},
		commonMetrics: commonMetrics,
		sshMetrics:    sshMetrics,
		recordOpts: recordOpts{
			skipRecording: skipRecording,
		},
	}
}

func newTstConnPair(t *testing.T) (<-chan ssh.NewChannel, *ssh.Client) {
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	require.Nil(t, err, "%+v", err)

	signer, err := sshutils.GenerateSigner()
	require.Nil(t, err)

	sshConfig := &ssh.ServerConfig{
		NoClientAuth: true,
	}
	sshConfig.AddHostKey(signer)

	type srvRes struct {
		conn  *ssh.ServerConn
		chans <-chan ssh.NewChannel
		err   error
	}

	srvCh := make(chan *srvRes, 1)

	go func() {
		netConn, err := lis.Accept()
		if err != nil {
			srvCh <- &srvRes{err: err}
			return
		}

		conn, chans, reqs, err := ssh.NewServerConn(netConn, sshConfig)
		if err == nil {
			go ssh.DiscardRequests(reqs)
		}
		srvCh <- &srvRes{conn: conn, chans: chans, err: err}
	}()

	addr := lis.Addr().String()

	netConn, err := net.Dial("tcp", addr)
	require.Nil(t, err, "%+v", err)

	c, chans, reqs, err := ssh.NewClientConn(netConn, addr, &ssh.ClientConfig{
		User:            "root",
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	})
	require.Nil(t, err, "%+v", err)

	srv := <-srvCh
	require.Nil(t, srv.err, "%+v", srv.err)

	client := ssh.NewClient(c, chans, reqs)

	t.Cleanup(func() {
		client.Close()
		srv.conn.Close()
		lis.Close()
	})

	return srv.chans, client
}

type tstAcceptedChannel struct {
	ch   ssh.Channel
	reqs <-chan *ssh.Request
	err  error
}

func tstAcceptChannel(chans <-chan ssh.NewChannel) <-chan *tstAcceptedChannel {
	ret := make(chan *tstAcceptedChannel, 1)

	go func() {
		nch, ok := <-chans
		if !ok {
			ret <- &tstAcceptedChannel{err: errors.Errorf("No new channels")}
			return
		}
		ch, reqs, err := nch.Accept()
		ret <- &tstAcceptedChannel{ch: ch, reqs: reqs, err: err}
	}()

	return ret
}

type tstSessionProxy struct {
	sess    *ssh.Session
	srvCh   ssh.Channel
	srvReqs <-chan *ssh.Request
	doneCh  chan struct{}
}

func newTstSessionProxy(t *testing.T, ctx context.Context, c *dctx) *tstSessionProxy {
	downstreamChans, downstreamClient := newTstConnPair(t)
	upstreamChans, upstreamClient := newTstConnPair(t)

	downstreamAccepted := tstAcceptChannel(downstreamChans)

	sess, err := downstreamClient.NewSession()
	require.Nil(t, err, "%+v", err)

	upstreamAccepted := tstAcceptChannel(upstreamChans)

	upstreamCh, upstreamReqs, err := upstreamClient.OpenChannel("session", nil)
	require.Nil(t, err, "%+v", err)

	downstream := <-downstreamAccepted
	require.Nil(t, downstream.err, "%+v", downstream.err)

	upstream := <-upstreamAccepted
	require.Nil(t, upstream.err, "%+v", upstream.err)

	ret := &tstSessionProxy{
		sess:    sess,
		srvCh:   upstream.ch,
		srvReqs: upstream.reqs,
		doneCh:  make(chan struct{}),
	}

	go func() {
		defer close(ret.doneCh)
		defer downstream.ch.Close()
		defer upstreamCh.Close()

		c.runSessionLoop(ctx, downstream.reqs, upstreamReqs, downstream.ch, upstreamCh)
	}()

	return ret
}

func (p *tstSessionProxy) handleExec(fn func(ch ssh.Channel, cmd string)) {
	go func() {
		for req := range p.srvReqs {
			switch req.Type {
			case "exec":
				msg := &reqExec{}
				if err := ssh.Unmarshal(req.Payload, msg); err != nil {
					if req.WantReply {
						req.Reply(false, nil)
					}
					return
				}
				if req.WantReply {
					req.Reply(true, nil)
				}

				fn(p.srvCh, msg.Command)
				return
			default:
				if req.WantReply {
					req.Reply(false, nil)
				}
			}
		}
	}()
}

func tstSendExitStatus(ch ssh.Channel, status uint32) {
	ch.SendRequest("exit-status", false, ssh.Marshal(&tstExitStatus{Status: status}))
}

type tstSessionResult struct {
	stdout []byte
	stderr []byte
	err    error
}

func tstRunSession(t *testing.T, c *dctx, stdin []byte,
	fn func(ch ssh.Channel, cmd string)) *tstSessionResult {
	ctx, cancelFn := context.WithCancel(context.Background())
	defer cancelFn()

	proxy := newTstSessionProxy(t, ctx, c)
	proxy.handleExec(fn)

	var stdout, stderr bytes.Buffer

	proxy.sess.Stdout = &stdout
	proxy.sess.Stderr = &stderr
	if stdin != nil {
		proxy.sess.Stdin = bytes.NewReader(stdin)
	}

	errCh := make(chan error, 1)
	go func() {
		errCh <- proxy.sess.Run(utilrand.GetRandomStringCanonical(6))
	}()

	select {
	case err := <-errCh:
		select {
		case <-proxy.doneCh:
		case <-time.After(sshCommandTimeout):
			t.Fatalf("Timed out while waiting for the session loop to exit")
		}

		return &tstSessionResult{
			stdout: stdout.Bytes(),
			stderr: stderr.Bytes(),
			err:    err,
		}
	case <-time.After(sshCommandTimeout):
		t.Fatalf("Timed out while waiting for the ssh command to end")
	}

	return nil
}

func TestRunSessionLoop(t *testing.T) {

	t.Run("StdoutAndStderr", func(t *testing.T) {
		stdout := []byte(fmt.Sprintf("stdout-%s", utilrand.GetRandomStringCanonical(12)))
		stderr := []byte(fmt.Sprintf("stderr-%s", utilrand.GetRandomStringCanonical(12)))

		res := tstRunSession(t, newTstDctx(t, false), nil, func(ch ssh.Channel, cmd string) {
			ch.Write(stdout)
			ch.Stderr().Write(stderr)
			tstSendExitStatus(ch, 0)
			ch.Close()
		})

		assert.Nil(t, res.err, "%+v", res.err)
		assert.Equal(t, stdout, res.stdout)
		assert.Equal(t, stderr, res.stderr)
		assert.NotContains(t, string(res.stdout), string(stderr),
			"the upstream stderr must not be merged into the downstream stdout")
		assert.NotContains(t, string(res.stderr), string(stdout),
			"the upstream stdout must not be merged into the downstream stderr")
	})

	t.Run("StderrOnly", func(t *testing.T) {
		stderr := []byte(utilrand.GetRandomStringCanonical(32))

		res := tstRunSession(t, newTstDctx(t, false), nil, func(ch ssh.Channel, cmd string) {
			ch.Stderr().Write(stderr)
			tstSendExitStatus(ch, 0)
			ch.Close()
		})

		assert.Nil(t, res.err, "%+v", res.err)
		assert.Empty(t, res.stdout)
		assert.Equal(t, stderr, res.stderr)
	})

	t.Run("TrailingStderr", func(t *testing.T) {
		stdout := tstPayload(4096)
		stderr := []byte(utilrand.GetRandomStringCanonical(64))

		res := tstRunSession(t, newTstDctx(t, false), nil, func(ch ssh.Channel, cmd string) {
			ch.Write(stdout)
			ch.Stderr().Write(stderr)
			tstSendExitStatus(ch, 0)
			ch.Close()
		})

		assert.Nil(t, res.err, "%+v", res.err)
		assert.Equal(t, stdout, res.stdout)
		assert.Equal(t, stderr, res.stderr,
			"the trailing upstream stderr must not be truncated by the downstream EOF")
	})

	t.Run("ExitStatus", func(t *testing.T) {
		stderr := []byte(utilrand.GetRandomStringCanonical(32))

		res := tstRunSession(t, newTstDctx(t, false), nil, func(ch ssh.Channel, cmd string) {
			ch.Stderr().Write(stderr)
			tstSendExitStatus(ch, 7)
			ch.Close()
		})

		require.NotNil(t, res.err)

		exitErr, ok := res.err.(*ssh.ExitError)
		require.True(t, ok, "%+v", res.err)
		assert.Equal(t, 7, exitErr.ExitStatus())
		assert.Equal(t, stderr, res.stderr)
	})

	t.Run("ExitStatusRace", func(t *testing.T) {
		for range 20 {
			res := tstRunSession(t, newTstDctx(t, true), nil,
				func(ch ssh.Channel, cmd string) {
					tstSendExitStatus(ch, 9)
					ch.Close()
				})

			exitErr, ok := res.err.(*ssh.ExitError)
			require.True(t, ok,
				"the upstream exit-status was dropped at the end of the session: %+v",
				res.err)
			require.Equal(t, 9, exitErr.ExitStatus())
		}
	})

	t.Run("Stdin", func(t *testing.T) {
		stdin := tstPayload(64 * 1024)

		res := tstRunSession(t, newTstDctx(t, false), stdin, func(ch ssh.Channel, cmd string) {
			in, err := io.ReadAll(ch)
			if err != nil {
				return
			}
			ch.Stderr().Write(in)
			tstSendExitStatus(ch, 0)
			ch.Close()
		})

		assert.Nil(t, res.err, "%+v", res.err)
		assert.Empty(t, res.stdout)
		assert.Equal(t, stdin, res.stderr)
	})

	t.Run("LargeStderr", func(t *testing.T) {
		stderr := tstPayload(4 * 1024 * 1024)

		res := tstRunSession(t, newTstDctx(t, true), nil, func(ch ssh.Channel, cmd string) {
			ch.Stderr().Write(stderr)
			tstSendExitStatus(ch, 0)
			ch.Close()
		})

		assert.Nil(t, res.err, "%+v", res.err)
		assert.Empty(t, res.stdout)
		assert.Equal(t, len(stderr), len(res.stderr))
		assert.True(t, bytes.Equal(stderr, res.stderr))
	})

	t.Run("LargeBoth", func(t *testing.T) {
		stdout := tstPayload(2 * 1024 * 1024)
		stderr := tstPayload(2*1024*1024 + 1)

		res := tstRunSession(t, newTstDctx(t, true), nil, func(ch ssh.Channel, cmd string) {
			var wg sync.WaitGroup
			wg.Add(2)

			go func() {
				defer wg.Done()
				ch.Write(stdout)
			}()

			go func() {
				defer wg.Done()
				ch.Stderr().Write(stderr)
			}()

			wg.Wait()
			tstSendExitStatus(ch, 0)
			ch.Close()
		})

		assert.Nil(t, res.err, "%+v", res.err)
		assert.Equal(t, len(stdout), len(res.stdout))
		assert.Equal(t, len(stderr), len(res.stderr))
		assert.True(t, bytes.Equal(stdout, res.stdout))
		assert.True(t, bytes.Equal(stderr, res.stderr))
	})

	t.Run("UpstreamEOFWithoutExitStatus", func(t *testing.T) {
		stderr := []byte(utilrand.GetRandomStringCanonical(32))

		res := tstRunSession(t, newTstDctx(t, false), nil, func(ch ssh.Channel, cmd string) {
			ch.Stderr().Write(stderr)
			ch.Close()
		})

		assert.NotNil(t, res.err)
		assert.Equal(t, stderr, res.stderr)
	})
}

func TestRunSessionLoopMetrics(t *testing.T) {
	ctx := context.Background()
	metricsReader := setTestMeterProvider(t)

	stdout := tstPayload(2048)
	stderr := tstPayload(4096)

	res := tstRunSession(t, newTstDctx(t, false), nil, func(ch ssh.Channel, cmd string) {
		ch.Write(stdout)
		ch.Stderr().Write(stderr)
		tstSendExitStatus(ch, 0)
		ch.Close()
	})

	assert.Nil(t, res.err, "%+v", res.err)

	rm := collectMetrics(t, ctx, metricsReader, func(rm *metricdata.ResourceMetrics) bool {
		return hasSumDataPoint(rm, "req.bytes_sent")
	})

	sentDP := findSumDataPoint(t, rm, "req.bytes_sent")
	assert.Equal(t, int64(len(stdout)+len(stderr)), sentDP.Value,
		"the upstream stderr bytes must be accounted for")
}
