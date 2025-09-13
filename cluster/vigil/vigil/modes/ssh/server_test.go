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
	"crypto/ed25519"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/creack/pty"
	"github.com/moby/term"
	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/apis/main/metav1"
	"github.com/octelium/octelium/apis/rsc/rmetav1"
	"github.com/octelium/octelium/cluster/apiserver/apiserver/admin"
	"github.com/octelium/octelium/cluster/apiserver/apiserver/user"
	"github.com/octelium/octelium/cluster/common/octeliumc"
	"github.com/octelium/octelium/cluster/common/sshutils"
	"github.com/octelium/octelium/cluster/common/tests"
	"github.com/octelium/octelium/cluster/common/tests/tstuser"
	"github.com/octelium/octelium/cluster/vigil/vigil/loadbalancer"
	"github.com/octelium/octelium/cluster/vigil/vigil/modes"
	"github.com/octelium/octelium/cluster/vigil/vigil/octovigilc"
	"github.com/octelium/octelium/cluster/vigil/vigil/secretman"
	"github.com/octelium/octelium/cluster/vigil/vigil/vcache"
	"github.com/octelium/octelium/pkg/apiutils/ucorev1"
	"github.com/octelium/octelium/pkg/utils"
	utils_cert "github.com/octelium/octelium/pkg/utils/cert"
	"github.com/octelium/octelium/pkg/utils/utilrand"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
	"go.uber.org/zap"
	"golang.org/x/crypto/ssh"
)

type tstSrv struct {
	sshConfig *ssh.ServerConfig
	cancelFn  context.CancelFunc
	lis       net.Listener
}

func newTestServer(ctx context.Context, octeliumC octeliumc.ClientInterface,
	nocClientAuth bool,
	passwordCallback func(conn ssh.ConnMetadata, password []byte) (*ssh.Permissions, error),
	publicKeyCallback func(conn ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error)) (*tstSrv, error) {
	ret := &tstSrv{}

	ret.sshConfig = &ssh.ServerConfig{
		NoClientAuth:      nocClientAuth,
		PasswordCallback:  passwordCallback,
		PublicKeyCallback: publicKeyCallback,
	}

	signer, err := sshutils.GenerateSigner()
	if err != nil {
		return nil, err
	}

	hostSigner, err := sshutils.GenerateHostSigner(ctx, octeliumC, signer)
	if err != nil {
		return nil, err
	}

	ret.sshConfig.AddHostKey(hostSigner)

	return ret, nil
}

func (s *tstSrv) run(addr string) error {

	if err := func() error {
		var err error
		for i := 0; i < 1000; i++ {
			s.lis, err = net.Listen("tcp", addr)
			if err == nil {
				return nil
			}
			time.Sleep(200 * time.Millisecond)
		}
		return errors.Errorf("Could not listen to addr: %s", addr)
	}(); err != nil {
		return err
	}

	ctx, cancelFn := context.WithCancel(context.Background())
	s.cancelFn = cancelFn

	go s.serve(ctx)

	return nil
}

func (s *tstSrv) serve(ctx context.Context) {

	for {
		conn, err := s.lis.Accept()
		if err != nil {
			if opErr, ok := err.(*net.OpError); ok && opErr.Timeout() {
				time.Sleep(100 * time.Millisecond)
				continue
			}

			select {
			case <-ctx.Done():
				return
			default:
				time.Sleep(100 * time.Millisecond)
				continue
			}
		}

		go s.handleConn(conn)
	}
}

func (s *tstSrv) close() error {
	s.cancelFn()

	if s.lis != nil {
		s.lis.Close()
		s.lis = nil
	}

	return nil
}

func (s *tstSrv) handleConn(c net.Conn) {

	sshConn, chans, reqs, err := ssh.NewServerConn(c, s.sshConfig)
	if err != nil {
		c.Close()
		return
	}

	defer sshConn.Close()

	for {
		select {
		case req := <-reqs:
			if req == nil {
				return
			}
			go s.handleGlobalReq(req)
		case nch := <-chans:
			if nch == nil {
				return
			}
			go s.handleNewChannel(nch)
		}
	}
}

func (s *tstSrv) handleGlobalReq(req *ssh.Request) {
	if req == nil {
		return
	}

	switch req.Type {
	case "keepalive@openssh.com":
		if req.WantReply {
			req.Reply(true, nil)
		}
	default:
		req.Reply(false, nil)
	}
}

func (s *tstSrv) handleNewChannel(nch ssh.NewChannel) {
	switch nch.ChannelType() {
	case "session":
		go s.handleSessionRequests(nch)
	default:
		nch.Reject(ssh.UnknownChannelType, fmt.Sprintf("Unsupported channel type: %s", nch.ChannelType()))
	}
}

func (s *tstSrv) handleSessionRequests(newChannel ssh.NewChannel) {

	sesschan, reqs, err := newChannel.Accept()
	if err != nil {
		return
	}

	s.doHandleSessionReqs(reqs, sesschan)
}

func (s *tstSrv) doHandleSessionReqs(reqs <-chan *ssh.Request, ch ssh.Channel) {
	var closer sync.Once
	closeFunc := func() {
		ch.Close()
	}

	defer closer.Do(closeFunc)

	for {
		select {
		case req := <-reqs:
			if req == nil {
				return
			}
			if err := s.handleSessionReq(req, ch); err != nil {
				zap.L().Debug("could not handle sess req", zap.Error(err))
			}
		}
	}
}

type ptyReqParams struct {
	Env   string
	W     uint32
	H     uint32
	Wpx   uint32
	Hpx   uint32
	Modes string
}

func parsePTYReq(req *ssh.Request) (*ptyReqParams, error) {
	var r ptyReqParams
	if err := ssh.Unmarshal(req.Payload, &r); err != nil {
		return nil, err
	}

	return &r, nil
}

func (s *tstSrv) handleSessionReq(req *ssh.Request, ch ssh.Channel) error {
	switch req.Type {
	case "pty-req":
	case "shell":
		var err error
		term, err := newTerminal(ch)
		if err != nil {
			return err
		}

		if err := term.run(); err != nil {
			return err
		}
	case "keepalive@openssh.com":
		if req.WantReply {
			return req.Reply(true, nil)
		}
	case "window-change":

		return nil
	default:
		return req.Reply(false, nil)
	}

	if req.WantReply {
		req.Reply(true, nil)
	}

	return nil
}

type tstTerminal struct {
	cmd *exec.Cmd

	pty *os.File
	tty *os.File

	closeCh chan struct{}

	ch ssh.Channel

	mu sync.Mutex
}

func newTerminal(ch ssh.Channel) (*tstTerminal, error) {
	ret := &tstTerminal{
		ch:      ch,
		closeCh: make(chan struct{}),
	}

	homeDir, err := os.UserHomeDir()
	if err != nil {
		return nil, err
	}

	shellPath := "/bin/bash"

	ret.pty, ret.tty, err = pty.Open()
	if err != nil {
		return nil, err
	}

	if err := ret.resetWinSize(); err != nil {
		return nil, err
	}

	cmd := &exec.Cmd{
		Path: shellPath,
		Dir:  homeDir,
		Env: []string{
			"TERM=xterm-256color",
			"LANG=en_US.utf8",
			fmt.Sprintf("SHELL=%s", shellPath),
			"EDITOR=vim",
			"VISUAL=vim",
			fmt.Sprintf("HOME=%s", homeDir),
		},
	}

	cmd.Stdin = ret.tty
	cmd.Stdout = ret.tty
	cmd.Stderr = ret.tty

	cmd.SysProcAttr = &syscall.SysProcAttr{
		Setsid:  true,
		Setctty: true,
	}

	ret.cmd = cmd

	return ret, nil
}

func (t *tstTerminal) resetWinSize() error {
	return term.SetWinsize(t.pty.Fd(), &term.Winsize{
		Width:  uint16(24),
		Height: uint16(80),
	})
}

func (t *tstTerminal) setWinSize(w, h uint16) error {
	return term.SetWinsize(t.pty.Fd(), &term.Winsize{
		Width:  w,
		Height: h,
	})
}

func (t *tstTerminal) run() error {
	var once sync.Once
	closeFn := func() {
		close(t.closeCh)
	}
	err := t.cmd.Start()
	if err != nil {
		return err
	}

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

	go func() {
		t.waitAndClose()

	}()

	return nil
}

func (t *tstTerminal) waitAndClose() error {

	waitCh := make(chan error)
	go func() {
		err := t.cmd.Wait()

		waitCh <- err
	}()

	select {
	case <-waitCh:
	case <-t.closeCh:
		t.cmd.Process.Kill()
	}

	return t.close()
}

func (t *tstTerminal) close() error {

	t.mu.Lock()
	defer t.mu.Unlock()

	if t.tty != nil {
		t.tty.Close()
		t.tty = nil
	}

	if t.pty != nil {
		t.tty.Close()
		t.pty = nil
	}

	return nil
}

func getClientConfig(t *testing.T, octeliumC octeliumc.ClientInterface, user string) *ssh.ClientConfig {
	ctx := context.Background()
	ca, err := sshutils.GetCAPublicKey(ctx, octeliumC)
	assert.Nil(t, err)
	sgnr, err := sshutils.GenerateSigner()
	assert.Nil(t, err)
	signer, err := sshutils.GenerateUserSigner(ctx, octeliumC, sgnr)
	assert.Nil(t, err)
	assert.Nil(t, err)
	ret := &ssh.ClientConfig{
		User:            user,
		HostKeyCallback: sshutils.GetHostKeyCACallback(ca),
		Auth: []ssh.AuthMethod{
			ssh.PublicKeys(signer),
		},
	}

	return ret
}

func TestServer(t *testing.T) {

	ctx := context.Background()
	tst, err := tests.Initialize(nil)
	assert.Nil(t, err, "%+v", err)
	t.Cleanup(func() {
		tst.Destroy()
	})
	fakeC := tst.C

	{
		cc, err := fakeC.OcteliumC.CoreV1Utils().GetClusterConfig(ctx)
		assert.Nil(t, err)

		cc.Status.Network.ClusterNetwork = &metav1.DualStackNetwork{
			V4: "127.0.0.0/8",
			V6: "::1/128",
		}
		_, err = fakeC.OcteliumC.CoreC().UpdateClusterConfig(ctx, cc)
		assert.Nil(t, err)
	}

	upstreamPort := tests.GetPort()

	upstreamSrv, err := newTestServer(ctx, fakeC.OcteliumC, true, nil, nil)
	assert.Nil(t, err)
	upstreamAddr := net.JoinHostPort("localhost", fmt.Sprintf("%d", upstreamPort))
	upstreamSrv.run(upstreamAddr)

	adminSrv := admin.NewServer(&admin.Opts{
		OcteliumC:  fakeC.OcteliumC,
		IsEmbedded: true,
	})
	usrSrv := user.NewServer(fakeC.OcteliumC)

	svc, err := adminSrv.CreateService(ctx, &corev1.Service{
		Metadata: &metav1.Metadata{
			Name: utilrand.GetRandomStringCanonical(6),
		},
		Spec: &corev1.Service_Spec{
			Port: uint32(tests.GetPort()),
			Mode: corev1.Service_Spec_SSH,

			Config: &corev1.Service_Spec_Config{
				Upstream: &corev1.Service_Spec_Config_Upstream{
					Type: &corev1.Service_Spec_Config_Upstream_Url{
						Url: fmt.Sprintf("ssh://localhost:%d", upstreamPort),
					},
				},
			},
			Authorization: &corev1.Service_Spec_Authorization{
				InlinePolicies: []*corev1.InlinePolicy{
					{
						Spec: &corev1.Policy_Spec{
							Rules: []*corev1.Policy_Spec_Rule{
								{
									Effect: corev1.Policy_Spec_Rule_ALLOW,
									Condition: &corev1.Condition{
										Type: &corev1.Condition_MatchAny{
											MatchAny: true,
										},
									},
								},
							},
						},
					},
				},
			},
		},
	})

	assert.Nil(t, err)

	vCache, err := vcache.NewCache(ctx)
	assert.Nil(t, err)
	vCache.SetService(svc)

	octovigilC, err := octovigilc.NewClient(ctx, &octovigilc.Opts{
		VCache:    vCache,
		OcteliumC: fakeC.OcteliumC,
	})
	assert.Nil(t, err)

	secretMan, err := secretman.New(ctx, fakeC.OcteliumC, vCache)
	assert.Nil(t, err)

	/*
		logMan, err := logmanager.NewLogManager(ctx, &logmanager.LogManagerOpts{})
		assert.Nil(t, err)

		metricsStore, err := metricsstore.NewMetricsStore(ctx, nil)
		assert.Nil(t, err)
	*/

	secretMan.ApplyService(ctx)

	srv, err := New(ctx, &modes.Opts{
		OcteliumC:  fakeC.OcteliumC,
		OctovigilC: octovigilC,
		VCache:     vCache,
		SecretMan:  secretMan,
		// LogManager:   logMan,
		LBManager: loadbalancer.NewLbManager(fakeC.OcteliumC, vCache),
		// MetricsStore: metricsStore,
	})
	assert.Nil(t, err)

	err = srv.Run(ctx)
	assert.Nil(t, err)

	usr, err := tstuser.NewUser(fakeC.OcteliumC, adminSrv, usrSrv, nil)
	assert.Nil(t, err)
	err = usr.Connect()
	assert.Nil(t, err, "%+v", err)

	usr.Session.Status.Connection = &corev1.Session_Status_Connection{
		Addresses: []*metav1.DualStackNetwork{
			{
				V4: "127.0.0.1/32",
				V6: "::1/128",
			},
		},
		Type:   corev1.Session_Status_Connection_WIREGUARD,
		L3Mode: corev1.Session_Status_Connection_V4,
	}

	usr.Session, err = fakeC.OcteliumC.CoreC().UpdateSession(ctx, usr.Session)
	assert.Nil(t, err)
	usr.Resync()

	srv.octovigilC.GetCache().SetSession(usr.Session)
	usr.Resync()

	time.Sleep(1 * time.Second)

	srvAddr := fmt.Sprintf("localhost:%d", ucorev1.ToService(svc).RealPort())

	doConnect := func(srvAddr, sshUser string) {
		c, err := net.Dial("tcp", srvAddr)
		assert.Nil(t, err, "%+v", err)

		clientConn, clientChans, clientReqs, err := ssh.NewClientConn(c, srvAddr, getClientConfig(t, fakeC.OcteliumC, sshUser))
		assert.Nil(t, err, "Could not create ssh client %+v", err)
		sshC := ssh.NewClient(clientConn, clientChans, clientReqs)

		sess, err := sshC.NewSession()
		assert.Nil(t, err, "%+v", err)
		err = sess.RequestPty("xterm", 80, 24, ssh.TerminalModes{
			ssh.ECHO:          0,
			ssh.TTY_OP_ISPEED: 14400,
			ssh.TTY_OP_OSPEED: 14400,
		})
		assert.Nil(t, err)

		stdoutPipe, err := sess.StdoutPipe()
		assert.Nil(t, err)

		stdinPipe, err := sess.StdinPipe()
		assert.Nil(t, err)

		err = sess.Shell()
		assert.Nil(t, err)
		time.Sleep(1 * time.Second)

		_, err = stdinPipe.Write([]byte("ls -la \r\n"))
		assert.Nil(t, err)
		buf := make([]byte, 1024)
		n, err := stdoutPipe.Read(buf)
		assert.Nil(t, err)
		zap.S().Debugf("%s", buf[:n])

		sshC.Close()
		c.Close()
	}

	doConnect(srvAddr, "")

	{
		// change upstream host key to invalid
		k, err := utils_cert.GenerateECDSA()
		assert.Nil(t, err)
		key, err := ssh.NewSignerFromKey(k.PrivateKey)

		assert.Nil(t, err)

		svc.Spec.Config = &corev1.Service_Spec_Config{
			Upstream: &corev1.Service_Spec_Config_Upstream{
				Type: &corev1.Service_Spec_Config_Upstream_Url{
					Url: fmt.Sprintf("ssh://localhost:%d", upstreamPort),
				},
			},
			Type: &corev1.Service_Spec_Config_Ssh{
				Ssh: &corev1.Service_Spec_Config_SSH{
					UpstreamHostKey: &corev1.Service_Spec_Config_SSH_UpstreamHostKey{
						Type: &corev1.Service_Spec_Config_SSH_UpstreamHostKey_Key{
							Key: string(ssh.MarshalAuthorizedKey(key.PublicKey())),
						},
					},
				},
			},
		}
		_, err = adminSrv.UpdateService(ctx, svc)
		assert.Nil(t, err)

		svc, err = fakeC.OcteliumC.CoreC().GetService(ctx, &rmetav1.GetOptions{Uid: svc.Metadata.Uid})
		assert.Nil(t, err)

		vCache.SetService(svc)

		c, err := net.Dial("tcp", srvAddr)
		assert.Nil(t, err, "%+v", err)

		clientConn, clientChans, clientReqs, err := ssh.NewClientConn(c, srvAddr, getClientConfig(t, fakeC.OcteliumC, ""))
		assert.Nil(t, err, "Could not create ssh client %+v", err)
		sshC := ssh.NewClient(clientConn, clientChans, clientReqs)

		_, err = sshC.NewSession()
		assert.NotNil(t, err)

	}
	{
		secretName := utilrand.GetRandomStringCanonical(6)
		secret, err := adminSrv.CreateSecret(ctx, &corev1.Secret{
			Metadata: &metav1.Metadata{
				Name: secretName,
			},
			Spec: &corev1.Secret_Spec{},
			Data: &corev1.Secret_Data{
				Type: &corev1.Secret_Data_Value{
					Value: utilrand.GetRandomString(12),
				},
			},
		})
		assert.Nil(t, err)
		upstreamSrv.close()
		upstreamSrv, err = newTestServer(ctx, srv.octeliumC, false,
			func(conn ssh.ConnMetadata, password []byte) (*ssh.Permissions, error) {
				if utils.SecureBytesEqual([]byte(secret.Data.GetValue()), password) {
					return &ssh.Permissions{}, nil
				}
				return nil, errors.Errorf("Invalid password")
			}, nil)
		assert.Nil(t, err)
		err = upstreamSrv.run(upstreamAddr)
		assert.Nil(t, err)
		svc.Spec.Config = &corev1.Service_Spec_Config{
			Upstream: &corev1.Service_Spec_Config_Upstream{
				Type: &corev1.Service_Spec_Config_Upstream_Url{
					Url: fmt.Sprintf("ssh://localhost:%d", upstreamPort),
				},
			},
			Type: &corev1.Service_Spec_Config_Ssh{
				Ssh: &corev1.Service_Spec_Config_SSH{
					Auth: &corev1.Service_Spec_Config_SSH_Auth{
						Type: &corev1.Service_Spec_Config_SSH_Auth_Password_{
							Password: &corev1.Service_Spec_Config_SSH_Auth_Password{
								Type: &corev1.Service_Spec_Config_SSH_Auth_Password_FromSecret{
									FromSecret: secretName,
								},
							},
						},
					},
				},
			},
		}
		_, err = adminSrv.UpdateService(ctx, svc)
		assert.Nil(t, err)

		svc, err = fakeC.OcteliumC.CoreC().GetService(ctx, &rmetav1.GetOptions{Uid: svc.Metadata.Uid})
		assert.Nil(t, err)

		vCache.SetService(svc)

		doConnect(srvAddr, "")
	}

	{
		secretName := utilrand.GetRandomStringCanonical(6)
		key, err := utils_cert.GenerateECDSA()
		assert.Nil(t, err)
		privPEM, err := key.GetPrivateKeyPEM()
		assert.Nil(t, err)
		_, err = adminSrv.CreateSecret(ctx, &corev1.Secret{
			Metadata: &metav1.Metadata{
				Name: secretName,
			},
			Spec: &corev1.Secret_Spec{},
			Data: &corev1.Secret_Data{
				Type: &corev1.Secret_Data_ValueBytes{
					ValueBytes: []byte(privPEM),
				},
			},
		})
		assert.Nil(t, err)
		upstreamSrv.close()
		sshKey, err := ssh.ParsePrivateKey([]byte(privPEM))
		assert.Nil(t, err)

		upstreamSrv, err = newTestServer(ctx, srv.octeliumC, false, nil,
			func(conn ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
				if utils.SecureBytesEqual(key.Marshal(), sshKey.PublicKey().Marshal()) {
					return &ssh.Permissions{}, nil
				}
				return nil, errors.Errorf("Invalid key")
			})
		assert.Nil(t, err)
		err = upstreamSrv.run(upstreamAddr)
		assert.Nil(t, err)
		svc.Spec.Config = &corev1.Service_Spec_Config{
			Upstream: &corev1.Service_Spec_Config_Upstream{
				Type: &corev1.Service_Spec_Config_Upstream_Url{
					Url: fmt.Sprintf("ssh://localhost:%d", upstreamPort),
				},
			},
			Type: &corev1.Service_Spec_Config_Ssh{
				Ssh: &corev1.Service_Spec_Config_SSH{
					Auth: &corev1.Service_Spec_Config_SSH_Auth{
						Type: &corev1.Service_Spec_Config_SSH_Auth_PrivateKey_{
							PrivateKey: &corev1.Service_Spec_Config_SSH_Auth_PrivateKey{
								Type: &corev1.Service_Spec_Config_SSH_Auth_PrivateKey_FromSecret{
									FromSecret: secretName,
								},
							},
						},
					},
				},
			},
		}
		_, err = adminSrv.UpdateService(ctx, svc)
		assert.Nil(t, err)

		svc, err = fakeC.OcteliumC.CoreC().GetService(ctx, &rmetav1.GetOptions{Uid: svc.Metadata.Uid})
		assert.Nil(t, err)

		vCache.SetService(svc)

		doConnect(srvAddr, "")
	}

	time.Sleep(2 * time.Second)
	err = srv.Close()
	assert.Nil(t, err)

	{

		usr, err := tstuser.NewUser(fakeC.OcteliumC, adminSrv, usrSrv, nil)
		assert.Nil(t, err)

		svc, err := adminSrv.CreateService(ctx, &corev1.Service{
			Metadata: &metav1.Metadata{
				Name: utilrand.GetRandomStringCanonical(6),
			},
			Spec: &corev1.Service_Spec{
				Port: uint32(tests.GetPort()),
				Mode: corev1.Service_Spec_SSH,
				Config: &corev1.Service_Spec_Config{
					Type: &corev1.Service_Spec_Config_Ssh{
						Ssh: &corev1.Service_Spec_Config_SSH{
							ESSHMode: true,
						},
					},
				},
				Authorization: &corev1.Service_Spec_Authorization{
					InlinePolicies: []*corev1.InlinePolicy{
						{
							Spec: &corev1.Policy_Spec{
								Rules: []*corev1.Policy_Spec_Rule{
									{
										Effect: corev1.Policy_Spec_Rule_ALLOW,
										Condition: &corev1.Condition{
											Type: &corev1.Condition_MatchAny{
												MatchAny: true,
											},
										},
									},
								},
							},
						},
					},
				},
			},
		})
		assert.Nil(t, err)

		vCache, err := vcache.NewCache(ctx)
		assert.Nil(t, err)
		vCache.SetService(svc)

		octovigilC, err := octovigilc.NewClient(ctx, &octovigilc.Opts{
			VCache:    vCache,
			OcteliumC: fakeC.OcteliumC,
		})
		assert.Nil(t, err)

		secretMan, err := secretman.New(ctx, fakeC.OcteliumC, vCache)
		assert.Nil(t, err)

		/*
			logMan, err := logmanager.NewLogManager(ctx, &logmanager.LogManagerOpts{})
			assert.Nil(t, err)

			metricsStore, err := metricsstore.NewMetricsStore(ctx, nil)
			assert.Nil(t, err)
		*/

		secretMan.ApplyService(ctx)

		srv, err := New(ctx, &modes.Opts{
			OcteliumC:  fakeC.OcteliumC,
			OctovigilC: octovigilC,
			VCache:     vCache,
			SecretMan:  secretMan,
			// LogManager:   logMan,
			LBManager: loadbalancer.NewLbManager(fakeC.OcteliumC, vCache),
			// MetricsStore: metricsStore,
		})
		assert.Nil(t, err)
		vCache.SetService(svc)

		err = srv.lbManager.Run(ctx)
		assert.Nil(t, err)

		err = srv.Run(ctx)
		assert.Nil(t, err)

		defer srv.Close()

		err = usr.ConnectWithServeAll()
		assert.Nil(t, err)

		pubK, privK, err := ed25519.GenerateKey(nil)
		assert.Nil(t, err)
		signer, err := ssh.NewSignerFromKey(privK)
		assert.Nil(t, err)

		usr.Session.Status.Connection.Ed25519PublicKey = pubK[:]

		usr.Session.Status.Connection.ESSHEnable = true
		usr.Session.Status.Connection.ESSHPort = 23000
		usr.Session.Status.Connection.Addresses = []*metav1.DualStackNetwork{
			{
				V4: "127.0.0.1/32",
			},
		}
		usr.Session.Status.Connection.L3Mode = corev1.Session_Status_Connection_V4

		usr.Session, err = fakeC.OcteliumC.CoreC().UpdateSession(ctx, usr.Session)
		assert.Nil(t, err)

		srv.octovigilC.GetCache().SetSession(usr.Session)
		usr.Resync()

		srv.lbManager.SetSession(usr.Session)

		ca, err := sshutils.GetCAPublicKey(ctx, fakeC.OcteliumC)
		assert.Nil(t, err)

		tstSrv := &tstSrv{}

		tstSrv.sshConfig = &ssh.ServerConfig{

			PublicKeyCallback: func(conn ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
				checker := &ssh.CertChecker{
					IsUserAuthority: func(auth ssh.PublicKey) bool {
						authBytes := auth.Marshal()
						if len(authBytes) == 0 {
							return false
						}

						return utils.SecureBytesEqual(authBytes, ca.Marshal())
					},
				}

				ret, err := checker.Authenticate(conn, key)
				if err != nil {
					zap.S().Debugf("Could not authenticate ssh key: %+v : %+v", err, key)
					return nil, err
				}

				zap.S().Debugf("SSH client successfully authenticated with permissions: %+v", ret)
				return ret, nil
			},
		}

		tstSrv.sshConfig.AddHostKey(signer)

		addr := net.JoinHostPort("127.0.0.1", "23000")

		err = tstSrv.run(addr)
		assert.Nil(t, err)

		{
			usrDownstream, err := tstuser.NewUser(fakeC.OcteliumC, adminSrv, usrSrv, nil)
			assert.Nil(t, err)
			err = usrDownstream.Connect()
			assert.Nil(t, err, "%+v", err)

			usrDownstream.Session.Status.Connection = &corev1.Session_Status_Connection{
				Addresses: []*metav1.DualStackNetwork{
					{
						V4: "127.0.0.1/32",
						V6: "::1/128",
					},
				},
				Type:   corev1.Session_Status_Connection_WIREGUARD,
				L3Mode: corev1.Session_Status_Connection_V4,
			}

			usrDownstream.Session, err = fakeC.OcteliumC.CoreC().UpdateSession(ctx, usrDownstream.Session)
			assert.Nil(t, err)
			usrDownstream.Resync()

			srv.octovigilC.GetCache().SetSession(usrDownstream.Session)
			usrDownstream.Resync()

			time.Sleep(1 * time.Second)
		}

		doConnect(fmt.Sprintf("localhost:%d", ucorev1.ToService(svc).RealPort()), usr.Session.Metadata.Name)
	}

	time.Sleep(2 * time.Second)
}
