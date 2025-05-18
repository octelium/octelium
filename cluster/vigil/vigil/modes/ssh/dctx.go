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
	"crypto/ed25519"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/octelium/octelium/apis/cluster/coctovigilv1"
	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/apis/main/metav1"
	"github.com/octelium/octelium/cluster/common/octeliumc"
	"github.com/octelium/octelium/cluster/common/sshutils"
	"github.com/octelium/octelium/cluster/common/vutils"
	"github.com/octelium/octelium/cluster/vigil/vigil/loadbalancer"
	"github.com/octelium/octelium/cluster/vigil/vigil/modes"
	"github.com/octelium/octelium/cluster/vigil/vigil/secretman"
	"github.com/octelium/octelium/cluster/vigil/vigil/vigilutils"
	"github.com/octelium/octelium/pkg/apiutils/ucorev1"
	"github.com/octelium/octelium/pkg/apiutils/umetav1"
	"github.com/pkg/errors"
	"go.uber.org/zap"
	"golang.org/x/crypto/ssh"
	"golang.org/x/net/context"
)

type dctx struct {
	id        string
	createdAt time.Time
	conn      net.Conn
	sshConn   *ssh.ServerConn

	mu       sync.Mutex
	sessions uint32

	remoteConn struct {
		mu        sync.Mutex
		netConn   net.Conn
		sshClient *ssh.Client
	}

	isClosed    bool
	keepAliveCh chan struct{}

	i      *corev1.RequestContext
	svcRef *metav1.ObjectReference

	upstreamSession *corev1.Session

	recordOpts *recordOpts

	svcConfig  *corev1.Service_Spec_Config
	reasonInit *corev1.AccessLog_Entry_Common_Reason
	authResp   *coctovigilv1.AuthenticateAndAuthorizeResponse
	opts       *modes.Opts
}

func newDctx(ctx context.Context, opts *modes.Opts, conn net.Conn, sshConn *ssh.ServerConn, i *corev1.RequestContext,
	upstreamSession *corev1.Session,
	recrecordOpts *recordOpts,
	authResp *coctovigilv1.AuthenticateAndAuthorizeResponse, reasonInit *corev1.AccessLog_Entry_Common_Reason) *dctx {
	ret := &dctx{
		id:              vutils.GenerateLogID(),
		conn:            conn,
		sshConn:         sshConn,
		createdAt:       time.Now(),
		keepAliveCh:     make(chan struct{}),
		i:               i,
		svcRef:          umetav1.GetObjectReference(i.Service),
		upstreamSession: upstreamSession,
		recordOpts:      recrecordOpts,
		authResp:        authResp,
		svcConfig:       vigilutils.GetServiceConfig(ctx, authResp),
		reasonInit:      reasonInit,
		opts:            opts,
	}

	zap.S().Debugf("new dctx %s created for session: %s", ret.id, i.Session.Metadata.Uid)

	return ret
}

func (c *dctx) close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.isClosed {
		return nil
	}
	c.isClosed = true

	zap.S().Debugf("Closing downstream context: %s", c.id)

	if c.sshConn != nil {
		c.sshConn.Close()
	}

	if c.conn != nil {
		c.conn.Close()
	}

	if c.remoteConn.sshClient != nil {
		c.remoteConn.sshClient.Close()
	}

	if c.remoteConn.netConn != nil {
		c.remoteConn.netConn.Close()
	}

	return nil
}

func (c *dctx) connect(ctx context.Context, octeliumC octeliumc.ClientInterface,
	svc *corev1.Service, lbMan *loadbalancer.LBManager,
	userSginer ssh.Signer, secretMan *secretman.SecretManager) error {

	zap.S().Debugf("Connecting to upstream")
	var err error
	var upstream *loadbalancer.Upstream

	if c.opts.GetUpstream != nil {
		upstream, err = c.opts.GetUpstream(ctx, c.opts, c.i)
		if err != nil {
			return err
		}

	} else if ucorev1.ToService(svc).IsESSH() {
		zap.L().Debug("Getting upstream for eSSH mode")
		if c.upstreamSession == nil || !ucorev1.ToSession(c.upstreamSession).IsClientConnectedESSH() {
			return errors.Errorf("Upstream Session is not connected or not eSSH")
		}

		addr := func() string {
			conn := c.upstreamSession.Status.Connection
			for _, addr := range conn.Addresses {
				if addr.V6 != "" && ucorev1.ToSession(c.upstreamSession).HasV6() {
					return umetav1.ToDualStackNetwork(addr).ToIP().Ipv6
				} else if addr.V4 != "" && ucorev1.ToSession(c.upstreamSession).HasV4() {
					return umetav1.ToDualStackNetwork(addr).ToIP().Ipv4
				}
			}
			return ""
		}()
		if addr == "" {
			return errors.Errorf("Cannot find upstream Session IP addr")
		}

		upstream = &loadbalancer.Upstream{
			HostPort: net.JoinHostPort(addr,
				fmt.Sprintf("%d", c.upstreamSession.Status.Connection.ESSHPort)),
			IsUser:           true,
			Ed25519PublicKey: c.upstreamSession.Status.Connection.Ed25519PublicKey,
			IsESSH:           true,
		}
	} else {
		upstream, err = lbMan.GetUpstream(ctx, c.authResp)
		if err != nil {
			return err
		}
	}

	zap.L().Debug("Got upstream", zap.Any("upstream", upstream))

	clientConfig, err := c.getClientConfig(ctx, octeliumC, svc, userSginer, secretMan, upstream)
	if err != nil {
		return err
	}

	zap.S().Debugf("Dialing remote addr: %s", upstream.HostPort)

	conn, err := net.DialTimeout("tcp", upstream.HostPort, 20*time.Second)
	if err != nil {
		zap.S().Warn("Error dialing remote addr: %s: %+v", upstream.HostPort, err)
		return err
	}

	zap.L().Debug("Creating sshClientConn")
	clientConn, clientChans, clientReqs, err := ssh.NewClientConn(conn, upstream.HostPort, clientConfig)
	if err != nil {
		zap.S().Debugf("Could not create new client conn: %+v", err)
		return err
	}

	c.remoteConn.sshClient = ssh.NewClient(clientConn, clientChans, clientReqs)
	c.remoteConn.netConn = conn

	zap.L().Debug("ssh client now connected", zap.String("upstream", upstream.HostPort))

	return nil
}

func (c *dctx) getEffectiveSSHUser() string {
	if c.svcConfig == nil ||
		c.svcConfig.GetSsh() == nil ||
		c.svcConfig.GetSsh().User == "" {
		return c.sshConn.User()
	}
	return c.svcConfig.GetSsh().User
}

func (c *dctx) getClientConfig(ctx context.Context,
	octeliumC octeliumc.ClientInterface, svc *corev1.Service,
	userSigner ssh.Signer, secretMan *secretman.SecretManager, upstream *loadbalancer.Upstream) (*ssh.ClientConfig, error) {

	zap.L().Debug("Setting remote ssh client", zap.String("id", c.id))

	ca, err := sshutils.GetCAPublicKey(ctx, octeliumC)
	if err != nil {
		return nil, errors.Errorf("Could not get caPublicKey: %+v", err)
	}

	clientConfig := &ssh.ClientConfig{
		User:            c.getEffectiveSSHUser(),
		Timeout:         10 * time.Second,
		HostKeyCallback: sshutils.GetHostKeyCACallback(ca),
		Auth: []ssh.AuthMethod{
			ssh.PublicKeys(userSigner),
		},
	}

	if upstream.IsESSH && upstream.Ed25519PublicKey != nil {
		pubKey, err := ssh.NewPublicKey(ed25519.PublicKey(upstream.Ed25519PublicKey))
		if err != nil {
			return nil, err
		}
		clientConfig.HostKeyCallback = ssh.FixedHostKey(pubKey)
		return clientConfig, nil
	}

	if c.svcConfig == nil || c.svcConfig.GetSsh() == nil {
		zap.L().Debug("No SSH config found. Returning default client config.")
		return clientConfig, nil
	}

	spec := c.svcConfig.GetSsh()

	if spec.UpstreamHostKey != nil {
		switch spec.UpstreamHostKey.Type.(type) {
		case *corev1.Service_Spec_Config_SSH_UpstreamHostKey_InsecureIgnoreHostKey:
			if !spec.UpstreamHostKey.GetInsecureIgnoreHostKey() {
				return nil, errors.Errorf("Either insecureIgnoreHostKey must be true or a host key is provided")
			}

			clientConfig.HostKeyCallback = ssh.InsecureIgnoreHostKey()
		case *corev1.Service_Spec_Config_SSH_UpstreamHostKey_Key:
			srvHostKey, _, _, _, err := ssh.ParseAuthorizedKey([]byte(spec.UpstreamHostKey.GetKey()))
			if err != nil {
				return nil, err
			}
			clientConfig.HostKeyCallback = ssh.FixedHostKey(srvHostKey)

		}
	}

	if spec.Auth != nil {
		switch spec.Auth.Type.(type) {
		case *corev1.Service_Spec_Config_SSH_Auth_Password_:
			switch spec.Auth.GetPassword().Type.(type) {
			case *corev1.Service_Spec_Config_SSH_Auth_Password_FromSecret:
				clientConfig.Auth = []ssh.AuthMethod{
					ssh.PasswordCallback(func() (string, error) {
						secret, err := secretMan.GetByName(ctx, spec.Auth.GetPassword().GetFromSecret())
						if err != nil {
							return "", err
						}
						return ucorev1.ToSecret(secret).GetValueStr(), nil
					}),
				}
			}
		case *corev1.Service_Spec_Config_SSH_Auth_PrivateKey_:
			switch spec.Auth.GetPrivateKey().Type.(type) {
			case *corev1.Service_Spec_Config_SSH_Auth_PrivateKey_FromSecret:
				clientConfig.Auth = []ssh.AuthMethod{
					ssh.PublicKeysCallback(func() ([]ssh.Signer, error) {
						zap.S().Debugf("Getting private key from Secret with name: %s",
							spec.Auth.GetPrivateKey().GetFromSecret())
						secret, err := secretMan.GetByName(ctx, spec.Auth.GetPrivateKey().GetFromSecret())
						if err != nil {
							return nil, err
						}

						key, err := ssh.ParsePrivateKey(ucorev1.ToSecret(secret).GetValueBytes())
						if err != nil {
							return nil, err
						}
						return []ssh.Signer{key}, nil
					}),
				}
			}
		}
	}

	zap.L().Debug("Successfully got sshClientConfig for dctx: %s",
		zap.String("id", c.id), zap.String("user", clientConfig.User))

	return clientConfig, nil
}

func (c *dctx) startKeepAliveUpstreamLoop(ctx context.Context) {
	tickerCh := time.NewTicker(30 * time.Second)
	defer tickerCh.Stop()

	n := 0

	for {
		select {
		case <-ctx.Done():
			zap.S().Debugf("keepalive loop ctx done for dctx: %s", c.id)
			return
		case <-tickerCh.C:
			err := c.sendKeepAliveUpstream()
			if err == nil {
				zap.S().Debugf("Upstream responded successfully to keepalive for dctx :%s", c.id)
				n = 0
				tickerCh.Reset(30 * time.Second)
				continue
			}

			n = n + 1
			tickerCh.Reset(8 * time.Second)
			if n < 5 {
				zap.S().Debugf("Keepalive failed for dctx :%s. %+v", c.id, err)
				continue
			}

			zap.S().Debugf("Upstream is not responding to keepalives. Removing dctx: %s", c.id)

			close(c.keepAliveCh)
			return
		}
	}
}

func (c *dctx) sendKeepAliveUpstream() error {
	errCh := make(chan error, 1)
	go func() {
		_, _, err := c.remoteConn.sshClient.SendRequest("keepalive@openssh.com", true, nil)
		errCh <- err
	}()
	select {
	case <-time.After(5 * time.Second):
		return errors.Errorf("keepalive upstream timeout")
	case err := <-errCh:
		return err
	}
}

func (c *dctx) handleGlobalReq(req *ssh.Request) {
	if req == nil {
		zap.L().Debug("Nil req. No need to handleGlobalReq")
		return
	}
	zap.S().Debugf("New global req: %s", req.Type)

	switch req.Type {
	case "keepalive@openssh.com":
		if req.WantReply {
			req.Reply(true, nil)
		}
	default:
		req.Reply(false, nil)
	}
}

func (c *dctx) handleNewChannel(ctx context.Context, nch ssh.NewChannel) {
	if nch == nil {
		zap.L().Debug("Nil nch. No need to handleNewChannel")
		return
	}

	zap.S().Debugf("New Channel: %s", nch.ChannelType())

	switch nch.ChannelType() {
	case "direct-tcpip":
		go c.handleDirectTCPIP(ctx, nch)
	case "session":
		go c.handleSessionRequests(ctx, nch)
	default:
		zap.L().Debug("Unsupported channel type", zap.String("type", nch.ChannelType()))
		nch.Reject(ssh.UnknownChannelType, fmt.Sprintf("Channel type: %s is unsupported", nch.ChannelType()))
	}
}
