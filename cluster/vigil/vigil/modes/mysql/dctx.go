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
	"unicode/utf8"

	"github.com/go-mysql-org/go-mysql/client"
	"github.com/go-mysql-org/go-mysql/mysql"
	"github.com/go-mysql-org/go-mysql/packet"
	"github.com/go-mysql-org/go-mysql/server"
	"github.com/octelium/octelium/apis/cluster/coctovigilv1"
	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/cluster/common/otelutils"
	"github.com/octelium/octelium/cluster/common/vutils"
	"github.com/octelium/octelium/cluster/vigil/vigil/loadbalancer"
	"github.com/octelium/octelium/cluster/vigil/vigil/logentry"
	"github.com/octelium/octelium/cluster/vigil/vigil/metricutils"
	"github.com/octelium/octelium/cluster/vigil/vigil/modes"
	"github.com/octelium/octelium/cluster/vigil/vigil/octovigilc"
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

	octovigilC *octovigilc.Client
	reasonInit *corev1.AccessLog_Entry_Common_Reason

	commonMetrics *metricutils.CommonMetrics
	dbMetrics     *metricutils.DBMetrics
}

func newDctx(ctx context.Context, conn net.Conn,
	i *corev1.RequestContext, secretMan *secretman.SecretManager,
	downstreamConnSQL *server.Conn,
	octovigilC *octovigilc.Client,
	commonMetrics *metricutils.CommonMetrics,
	dbMetrics *metricutils.DBMetrics,
	authResp *coctovigilv1.AuthenticateAndAuthorizeResponse,
	reasonInit *corev1.AccessLog_Entry_Common_Reason) *dctx {

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

		svcConfig:     vigilutils.GetServiceConfig(ctx, authResp),
		authResp:      authResp,
		octovigilC:    octovigilC,
		reasonInit:    reasonInit,
		commonMetrics: commonMetrics,
		dbMetrics:     dbMetrics,
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
		zap.Any("attrs", c.downstreamConnSQL.Attributes()),
		zap.Uint32("capabilities", c.downstreamConnSQL.Capability()))

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

	upstreamConn, err := client.ConnectWithDialer(ctx, "tcp", upstream.HostPort,
		cfg.User, ucorev1.ToSecret(passwordSecret).GetValueStr(),
		cfg.Database, dialer,
		func(conn *client.Conn) error {
			downstreamCaps := c.downstreamConnSQL.Capability()

			const mirrorCaps uint32 = mysql.CLIENT_DEPRECATE_EOF |
				mysql.CLIENT_SESSION_TRACK |
				mysql.CLIENT_QUERY_ATTRIBUTES |
				mysql.CLIENT_OPTIONAL_RESULTSET_METADATA |
				mysql.CLIENT_MULTI_RESULTS |
				mysql.CLIENT_PS_MULTI_RESULTS

			const forcedOnCaps uint32 = mysql.CLIENT_PROTOCOL_41 |
				mysql.CLIENT_SECURE_CONNECTION |
				mysql.CLIENT_PLUGIN_AUTH |
				mysql.CLIENT_LONG_PASSWORD |
				mysql.CLIENT_TRANSACTIONS

			const proxyCaps uint32 = mysql.CLIENT_SSL |
				mysql.CLIENT_COMPRESS |
				mysql.CLIENT_ZSTD_COMPRESSION_ALGORITHM |
				mysql.CLIENT_CONNECT_WITH_DB |
				mysql.CLIENT_PLUGIN_AUTH_LENENC_CLIENT_DATA

			conn.UnsetCapability(mirrorCaps)
			conn.SetCapability(downstreamCaps & mirrorCaps)

			conn.SetCapability(forcedOnCaps)

			conn.UnsetCapability(proxyCaps)

			if cfg.IsTLS {
				zap.L().Debug("Setting TLS....")
				conn.SetTLSConfig(&tls.Config{
					MinVersion: tls.VersionTLS12,
					MaxVersion: tls.VersionTLS13,
					ServerName: upstream.SNIHost,
				})
			}
			return nil
		})
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
	defer modes.Recover(func(err any) {
		c.downstreamCh <- errors.Errorf("downstream loop panic: %v", err)
	})

	zap.L().Debug("Starting downstreamLoop")
	defer zap.L().Debug("downstreamLoop exited...")

	var bytesFromClient int64
	defer func() {
		c.commonMetrics.AddBytesTransferred(0, bytesFromClient)
	}()

	pktReader := newPacketReader(c.downstreamConnSQL)

	var isDeniedPayload bool

	for {
		select {
		case <-ctx.Done():
			zap.L().Debug("ctx done. Exiting downstreamLoop")
			return
		default:
			packetBytes, isCommand, err := pktReader.read()
			if err != nil {
				c.downstreamCh <- errors.Errorf("Could not read downstream packet: %+v", err)
				return
			}
			bytesFromClient += int64(len(packetBytes))

			if isCommand {
				isDeniedPayload = false

				pkt, err := decodePacket(packetBytes[4:])
				if err != nil {
					zap.L().Debug("Could not decode downstream packet. Skipping it...", zap.Error(err))
					continue
				}

				authzStartedAt := time.Now()
				proceed, reason, err := c.authorizeCommand(ctx, pkt)
				if err != nil {
					c.dbMetrics.AddCommand(mysqlCommandName(pkt),
						"ERROR", metricutils.ValueUnset)
					c.downstreamCh <- err
					return
				}

				state := "ALLOWED"
				if !proceed {
					state = "DENIED"
				}

				if c.isAuthorizingCommands() {
					c.dbMetrics.RecordAuthz(authzStartedAt, state)
				}

				c.setLog(pkt, proceed, reason)

				switch {
				case pkt.isQuit():
					zap.L().Debug("Got quit msg. Exiting...")
					c.dbMetrics.AddCommand("QUIT", "ALLOWED", metricutils.ValueUnset)
					c.downstreamCh <- nil
					return
				case pkt.isChangeUser():
					c.dbMetrics.AddCommand("CHANGE_USER", "DENIED", "UNSUPPORTED")
					c.downstreamCh <- errors.Errorf("Cannot change user")
					return
				}

				c.dbMetrics.AddCommand(mysqlCommandName(pkt), state,
					reason.GetType().String())

				zap.L().Debug("downstream msg",
					zap.Int("seq", int(packetBytes[3])),
					zap.Int("type", int(pkt.typ)),
					zap.String("content", string(pkt.content)))

				isDeniedPayload = !proceed
			}

			if isDeniedPayload {
				if !pktReader.hasMore() {
					isDeniedPayload = false
					if err := c.sendUnauthorized(packetBytes[3] + 1); err != nil {
						c.downstreamCh <- errors.Errorf(
							"Could not write the error packet to downstream: %+v", err)
						return
					}
				}
				continue
			}

			if err := writePacket(packetBytes, c.upstreamConnSQL); err != nil {
				c.downstreamCh <- errors.Errorf("Could not write packet to upstream: %+v", err)
				return
			}
		}

	}
}

func (c *dctx) startUpstreamLoop(ctx context.Context) {
	defer modes.Recover(func(err any) {
		c.upstreamCh <- errors.Errorf("upstream loop panic: %v", err)
	})

	defer zap.L().Debug("upstreamLoop exited...")
	zap.L().Debug("Starting upstreamLoop")

	var bytesToClient int64
	defer func() {
		c.commonMetrics.AddBytesTransferred(bytesToClient, 0)
	}()

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
			bytesToClient += int64(len(packetBytes))

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

func mysqlCommandName(packet *mysqlPacket) string {
	switch {
	case packet.isQuery():
		return "QUERY"
	case packet.isInitDB():
		return "INIT_DB"
	case packet.isCreateDB():
		return "CREATE_DB"
	case packet.isDropDB():
		return "DROP_DB"
	case packet.isPreparedStatement():
		return "PREPARE_STATEMENT"
	case packet.isExecuteStatement():
		return "EXECUTE_STATEMENT"
	case packet.isCloseStatement():
		return "CLOSE_STATEMENT"
	case packet.isResetStatement():
		return "RESET_STATEMENT"
	case packet.isFetchStatement():
		return "FETCH_STATEMENT"
	case packet.isChangeUser():
		return "CHANGE_USER"
	case packet.isQuit():
		return "QUIT"
	case packet.isDebug():
		return "DEBUG"
	default:
		return metricutils.ValueOther
	}
}

func (c *dctx) isAuthorizingCommands() bool {
	auth := c.svcConfig.GetMysql().GetAuthorization()
	return auth != nil &&
		auth.Mode == corev1.Service_Spec_Config_MySQL_Authorization_ALL
}

func (c *dctx) sendUnauthorized(seq byte) error {
	return writePacket(newErrPacket(seq,
		mysql.ER_SPECIFIC_ACCESS_DENIED_ERROR, "42000", "Octelium: Unauthorized"),
		c.downstreamConnSQL)
}

func getMySQLRequest(pkt *mysqlPacket) *corev1.RequestContext_Request {
	ret := &corev1.RequestContext_Request_MySQL{}

	switch {
	case pkt.isQuery():
		zap.L().Debug("Received a query", zap.String("query", pkt.toQuery().query))
		ret.Type = &corev1.RequestContext_Request_MySQL_Query_{
			Query: &corev1.RequestContext_Request_MySQL_Query{
				Query: pkt.toQuery().query,
			},
		}
	case pkt.isPreparedStatement():
		zap.L().Debug("Received a prepare statement",
			zap.String("query", pkt.toPreparedStatement().query))
		ret.Type = &corev1.RequestContext_Request_MySQL_PrepareStatement_{
			PrepareStatement: &corev1.RequestContext_Request_MySQL_PrepareStatement{
				Query: pkt.toPreparedStatement().query,
			},
		}
	case pkt.isInitDB():
		zap.L().Debug("Received an initDB", zap.String("database", pkt.toInitDB().db))
		ret.Type = &corev1.RequestContext_Request_MySQL_InitDB_{
			InitDB: &corev1.RequestContext_Request_MySQL_InitDB{
				Database: pkt.toInitDB().db,
			},
		}
	default:
		return nil
	}

	return &corev1.RequestContext_Request{
		Type: &corev1.RequestContext_Request_Mysql{
			Mysql: ret,
		},
	}
}

func (c *dctx) authorizeCommand(ctx context.Context,
	pkt *mysqlPacket) (bool, *corev1.AccessLog_Entry_Common_Reason, error) {
	if !c.isAuthorizingCommands() {
		return true, c.reasonInit, nil
	}

	request := getMySQLRequest(pkt)
	if request == nil {
		return true, c.reasonInit, nil
	}

	resp, err := c.octovigilC.Authorize(ctx, &coctovigilv1.AuthorizeRequest{
		SessionUID: c.sessUID,
		Request:    request,
	})
	if err != nil {
		return false, nil, err
	}

	if !resp.IsAuthorized {
		return false, resp.Reason, nil
	}

	return true, resp.Reason, nil
}

func truncateQuery(arg string) string {
	if len(arg) <= maxLoggedQueryLen {
		return arg
	}

	ret := arg[:maxLoggedQueryLen]
	for len(ret) > 0 && !utf8.ValidString(ret) {
		ret = ret[:len(ret)-1]
	}

	return ret
}

func (c *dctx) getLoggedQuery(query string) (string, bool) {
	if c.svcConfig.GetMysql().GetVisibility().GetDisableQuery() {
		return "", false
	}

	return truncateQuery(query), len(query) > maxLoggedQueryLen
}

func (c *dctx) setLog(packet *mysqlPacket, isAuthorized bool,
	reason *corev1.AccessLog_Entry_Common_Reason) {

	logE := logentry.InitializeLogEntry(&logentry.InitializeLogEntryOpts{
		StartTime:       time.Now(),
		IsAuthenticated: true,
		IsAuthorized:    isAuthorized,
		ReqCtx:          c.reqCtx,
		ConnectionID:    c.id,
		Reason:          reason,
	})

	logE.Entry.Info.Type = &corev1.AccessLog_Entry_Info_Mysql{
		Mysql: &corev1.AccessLog_Entry_Info_MySQL{},
	}

	info := logE.Entry.Info.GetMysql()

	switch {
	case packet.isQuery():
		query, isTruncated := c.getLoggedQuery(packet.toQuery().query)
		info.Type = corev1.AccessLog_Entry_Info_MySQL_QUERY
		info.IsTruncated = isTruncated
		info.Details = &corev1.AccessLog_Entry_Info_MySQL_Query_{
			Query: &corev1.AccessLog_Entry_Info_MySQL_Query{
				Query: query,
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
		query, isTruncated := c.getLoggedQuery(packet.toPreparedStatement().query)
		info.Type = corev1.AccessLog_Entry_Info_MySQL_PREPARE_STATEMENT
		info.IsTruncated = isTruncated
		info.Details = &corev1.AccessLog_Entry_Info_MySQL_PrepareStatement_{
			PrepareStatement: &corev1.AccessLog_Entry_Info_MySQL_PrepareStatement{
				Query: query,
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
