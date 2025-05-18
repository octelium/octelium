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

package mysql

import (
	"context"
	"crypto/tls"
	"net"
	"time"

	"github.com/go-mysql-org/go-mysql/client"
	"github.com/go-mysql-org/go-mysql/packet"
	"github.com/go-mysql-org/go-mysql/server"
	"github.com/octelium/octelium/apis/cluster/coctovigilv1"
	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/cluster/common/otelutils"
	"github.com/octelium/octelium/cluster/common/vutils"
	"github.com/octelium/octelium/cluster/vigil/vigil/loadbalancer"
	"github.com/octelium/octelium/cluster/vigil/vigil/logentry"
	"github.com/octelium/octelium/cluster/vigil/vigil/secretman"
	"github.com/octelium/octelium/cluster/vigil/vigil/vigilutils"
	"github.com/octelium/octelium/pkg/apiutils/ucorev1"
	"github.com/pkg/errors"
	"go.uber.org/zap"
)

type dctx struct {
	id      string
	sessUID string
	conn    net.Conn

	createdAt time.Time
	secretMan *secretman.SecretManager

	upstreamConnSQL   *packet.Conn
	downstreamConnSQL *server.Conn

	downstreamCh chan error
	upstreamCh   chan error

	reqCtx *corev1.RequestContext

	svcConfig *corev1.Service_Spec_Config
	authResp  *coctovigilv1.AuthenticateAndAuthorizeResponse
}

func newDctx(ctx context.Context, conn net.Conn,
	i *corev1.RequestContext, secretMan *secretman.SecretManager,
	downstreamConnSQL *server.Conn,
	authResp *coctovigilv1.AuthenticateAndAuthorizeResponse) *dctx {

	return &dctx{
		id:                vutils.GenerateLogID(),
		reqCtx:            i,
		sessUID:           i.Session.Metadata.Uid,
		conn:              conn,
		secretMan:         secretMan,
		createdAt:         time.Now(),
		downstreamConnSQL: downstreamConnSQL,

		downstreamCh: make(chan error, 1),
		upstreamCh:   make(chan error, 1),

		svcConfig: vigilutils.GetServiceConfig(ctx, authResp),
		authResp:  authResp,
	}
}

func (c *dctx) close() error {
	if c.conn != nil {
		c.conn.Close()
	}
	c.conn = nil
	if c.upstreamConnSQL != nil {
		c.upstreamConnSQL.Close()
	}
	return nil
}

func (c *dctx) connect(ctx context.Context, lbManager *loadbalancer.LBManager, svc *corev1.Service, secretMan *secretman.SecretManager) error {

	zap.L().Debug("Starting connecting", zap.String("id", c.id))
	upstream, err := lbManager.GetUpstream(ctx, c.authResp)
	if err != nil {
		return err
	}

	zap.L().Debug("Downstream info",
		zap.String("user", c.downstreamConnSQL.GetUser()),
		zap.Any("attrs", c.downstreamConnSQL.Attributes()))

	if c.svcConfig == nil || c.svcConfig.GetMysql() == nil {
		return errors.Errorf("No mySQL config")
	}

	cfg := c.svcConfig.GetMysql()

	if cfg.User == "" {
		return errors.Errorf("no MySQL user in the config")
	}
	if cfg.Database == "" {
		return errors.Errorf("No MySQL db in the config")
	}
	if cfg.Auth.GetPassword() == nil {
		return errors.Errorf("No mySQL password in the config")
	}

	passwordSecret, err := c.secretMan.GetByName(ctx, cfg.Auth.GetPassword().GetFromSecret())
	if err != nil {
		return err
	}

	dialer := func(ctx context.Context, network, address string) (net.Conn, error) {
		var ret net.Dialer
		return ret.DialContext(ctx, network, address)
	}

	optTLS := func(c *client.Conn) error {
		if cfg.IsTLS {
			zap.L().Debug("Setting TLS....")
			c.SetTLSConfig(&tls.Config{
				MinVersion: tls.VersionTLS12,
				MaxVersion: tls.VersionTLS13,
				ServerName: upstream.SNIHost,
			})
		}
		return nil
	}

	upstreamConn, err := client.ConnectWithDialer(ctx, "tcp", upstream.HostPort,
		cfg.User, ucorev1.ToSecret(passwordSecret).GetValueStr(),
		cfg.Database, dialer, optTLS)
	if err != nil {
		return errors.Errorf("Could not connect to upstream: %+v", err)
	}

	c.upstreamConnSQL = packet.NewConn(upstreamConn)
	zap.L().Debug("Connecting is successful", zap.String("id", c.id))

	return nil
}

func (c *dctx) serve(ctx context.Context) error {
	defer c.upstreamConnSQL.Close()

	go c.startDownstreamLoop(ctx)
	go c.startUpstreamLoop(ctx)

	zap.L().Debug("Waiting to end serving dctx", zap.String("id", c.id))
	select {
	case <-ctx.Done():
		zap.L().Debug("ctx done")
	case err := <-c.downstreamCh:
		zap.L().Debug("downstream ch done", zap.Error(err))
	case err := <-c.upstreamCh:
		zap.L().Debug("upstream ch done", zap.Error(err))
	}

	return nil
}

func (c *dctx) startDownstreamLoop(ctx context.Context) {

	zap.L().Debug("Starting downstreamLoop")
	defer zap.L().Debug("downstreamLoop exited...")

	for {
		select {
		case <-ctx.Done():
			zap.L().Debug("ctx done. Exiting downstreamLoop")
			return
		default:
			packetBytes, err := readPacket(c.downstreamConnSQL)
			if err != nil {
				c.downstreamCh <- errors.Errorf("Could not read downstream packet: %+v", err)
				return
			}

			pkt, err := decodePacket(packetBytes[4:])
			if err != nil {
				zap.L().Debug("Could not decode downstream packet. Skipping it...", zap.Error(err))
				continue
			}

			c.setLog(pkt)

			switch {
			case pkt.isQuit():
				zap.L().Debug("Got quit msg. Exiting...")
				c.downstreamCh <- nil
				return
			case pkt.isChangeUser():
				c.downstreamCh <- errors.Errorf("Cannot change user")
				return
			}

			zap.L().Debug("downstream msg",
				zap.Int("seq", int(packetBytes[3])),
				zap.Int("type", int(pkt.typ)),
				zap.String("content", string(pkt.content)))

			if err := writePacket(packetBytes, c.upstreamConnSQL); err != nil {
				c.downstreamCh <- errors.Errorf("Could not write packet to upstream: %+v", err)
				return
			}
		}

	}
}

func (c *dctx) startUpstreamLoop(ctx context.Context) {
	defer zap.L().Debug("upstreamLoop exited...")
	zap.L().Debug("Starting upstreamLoop")

	for {
		select {
		case <-ctx.Done():
			zap.L().Debug("ctx done. Exiting upstreamLoop")
			return
		default:
			packetBytes, err := readPacket(c.upstreamConnSQL.Conn)
			if err != nil {
				c.upstreamCh <- err
				return
			}

			if err := writePacket(packetBytes, c.downstreamConnSQL); err != nil {
				c.upstreamCh <- err
				return
			}
		}
	}
}

/*
func getRawPacket(pkt []byte) []byte {
	ret := make([]byte, len(pkt)+4)
	copy(ret[4:], pkt)
	return ret
}
*/

func (c *dctx) setLog(packet *mysqlPacket) {

	logE := logentry.InitializeLogEntry(&logentry.InitializeLogEntryOpts{
		StartTime:       time.Now(),
		IsAuthenticated: true,
		IsAuthorized:    true,
		ReqCtx:          c.reqCtx,
		ConnectionID:    c.id,
	})

	logE.Entry.Info.Type = &corev1.AccessLog_Entry_Info_Mysql{
		Mysql: &corev1.AccessLog_Entry_Info_MySQL{},
	}

	info := logE.Entry.Info.GetMysql()

	switch {
	case packet.isQuery():
		info.Type = corev1.AccessLog_Entry_Info_MySQL_QUERY
		info.Details = &corev1.AccessLog_Entry_Info_MySQL_Query_{
			Query: &corev1.AccessLog_Entry_Info_MySQL_Query{
				Query: packet.toQuery().query,
			},
		}
	case packet.isInitDB():
		info.Type = corev1.AccessLog_Entry_Info_MySQL_INIT_DB
		info.Details = &corev1.AccessLog_Entry_Info_MySQL_InitDB_{
			InitDB: &corev1.AccessLog_Entry_Info_MySQL_InitDB{
				Database: packet.toInitDB().db,
			},
		}
	case packet.isCreateDB():
		info.Type = corev1.AccessLog_Entry_Info_MySQL_CREATE_DB
		info.Details = &corev1.AccessLog_Entry_Info_MySQL_CreateDB_{
			CreateDB: &corev1.AccessLog_Entry_Info_MySQL_CreateDB{
				Database: packet.toCreateDB().db,
			},
		}
	case packet.isDropDB():
		info.Type = corev1.AccessLog_Entry_Info_MySQL_DROP_DB
		info.Details = &corev1.AccessLog_Entry_Info_MySQL_DropDB_{
			DropDB: &corev1.AccessLog_Entry_Info_MySQL_DropDB{
				Database: packet.toDropDB().db,
			},
		}
	case packet.isPreparedStatement():
		info.Type = corev1.AccessLog_Entry_Info_MySQL_PREPARE_STATEMENT
		info.Details = &corev1.AccessLog_Entry_Info_MySQL_PrepareStatement_{
			PrepareStatement: &corev1.AccessLog_Entry_Info_MySQL_PrepareStatement{
				Query: packet.toPreparedStatement().query,
			},
		}
	case packet.isExecuteStatement():
		info.Type = corev1.AccessLog_Entry_Info_MySQL_EXECUTE_STATEMENT
	case packet.isCloseStatement():
		info.Type = corev1.AccessLog_Entry_Info_MySQL_CLOSE_STATEMENT
	case packet.isResetStatement():
		info.Type = corev1.AccessLog_Entry_Info_MySQL_RESET_STATEMENT
	case packet.isFetchStatement():
		info.Type = corev1.AccessLog_Entry_Info_MySQL_FETCH_STATEMENT
	case packet.isDebug():
		info.Type = corev1.AccessLog_Entry_Info_MySQL_DEBUG
	case packet.isQuit():
		info.Type = corev1.AccessLog_Entry_Info_MySQL_QUIT
	case packet.isChangeUser():
		info.Type = corev1.AccessLog_Entry_Info_MySQL_CHANGE_USER
	default:
		return
	}

	// zap.L().Debug("Log", zap.Any("log", logE))
	otelutils.EmitAccessLog(logE)
}
