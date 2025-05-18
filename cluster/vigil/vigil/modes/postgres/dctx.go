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

package postgres

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/jackc/pgconn"
	"github.com/jackc/pgproto3/v2"
	"github.com/octelium/octelium/apis/cluster/coctovigilv1"
	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/cluster/common/otelutils"
	"github.com/octelium/octelium/cluster/common/vutils"
	"github.com/octelium/octelium/cluster/vigil/vigil/loadbalancer"
	"github.com/octelium/octelium/cluster/vigil/vigil/logentry"
	"github.com/octelium/octelium/cluster/vigil/vigil/octovigilc"
	"github.com/octelium/octelium/cluster/vigil/vigil/secretman"
	"github.com/octelium/octelium/cluster/vigil/vigil/vcache"
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

	pgBackend  *pgproto3.Backend
	pgFrontend *pgproto3.Frontend

	upstreamConn *pgconn.PgConn

	startupMessage       pgproto3.FrontendMessage
	upstreamHijackedConn *pgconn.HijackedConn

	downstreamCh chan error
	upstreamCh   chan error

	reqCtx *corev1.RequestContext

	svcConfig *corev1.Service_Spec_Config

	dbUser string
	dbName string

	octovigilC *octovigilc.Client
	vCache     *vcache.Cache

	reasonInit *corev1.AccessLog_Entry_Common_Reason
	authResp   *coctovigilv1.AuthenticateAndAuthorizeResponse
}

func newDctx(ctx context.Context, conn net.Conn,
	i *corev1.RequestContext, secretMan *secretman.SecretManager,
	pgBackend *pgproto3.Backend, startupMessage pgproto3.FrontendMessage,
	octovigilC *octovigilc.Client,
	vCache *vcache.Cache,
	authResp *coctovigilv1.AuthenticateAndAuthorizeResponse,
	reasonInit *corev1.AccessLog_Entry_Common_Reason) *dctx {
	return &dctx{
		id:         vutils.GenerateLogID(),
		sessUID:    i.Session.Metadata.Uid,
		conn:       conn,
		secretMan:  secretMan,
		createdAt:  time.Now(),
		octovigilC: octovigilC,
		vCache:     vCache,

		downstreamCh: make(chan error, 1),
		upstreamCh:   make(chan error, 1),

		pgBackend:      pgBackend,
		startupMessage: startupMessage,
		reqCtx:         i,
		svcConfig:      vigilutils.GetServiceConfig(ctx, authResp),
		authResp:       authResp,
		reasonInit:     reasonInit,
	}
}

func (c *dctx) close() error {
	if c.conn != nil {
		c.conn.Close()
	}
	c.conn = nil
	return nil
}

func (c *dctx) getEffectiveUser() string {
	cfg := c.svcConfig.GetPostgres()
	if cfg.User != "" {
		return cfg.User
	}

	return c.startupMessage.(*pgproto3.StartupMessage).Parameters["user"]
}

func (c *dctx) getEffectiveDB() string {
	cfg := c.svcConfig.GetPostgres()
	if cfg.Database != "" {
		return cfg.Database
	}
	return c.startupMessage.(*pgproto3.StartupMessage).Parameters["database"]
}

func (c *dctx) connect(ctx context.Context, lbManager *loadbalancer.LBManager, svc *corev1.Service, secretMan *secretman.SecretManager) error {

	zap.L().Debug("Starting connecting",
		zap.String("id", c.id),
		zap.Any("startupMsgParams", c.startupMessage.(*pgproto3.StartupMessage).Parameters))
	upstream, err := lbManager.GetUpstream(ctx, c.authResp)
	if err != nil {
		return err
	}

	if c.svcConfig == nil || c.svcConfig.GetPostgres() == nil {
		return errors.Errorf("No postgres config")
	}

	cfg := c.svcConfig.GetPostgres()

	if cfg.Auth.GetPassword() == nil {
		return errors.Errorf("No postgres password in the config")
	}

	passwordSecret, err := c.secretMan.GetByName(ctx, cfg.Auth.GetPassword().GetFromSecret())
	if err != nil {
		return err
	}

	c.dbUser = c.getEffectiveUser()
	c.dbName = c.getEffectiveDB()

	connStr := fmt.Sprintf("user=%s password=%s host=%s port=%d",
		c.dbUser, ucorev1.ToSecret(passwordSecret).GetValueStr(),
		upstream.Host, upstream.Port,
	)
	if c.dbName != "" {
		connStr = fmt.Sprintf("%s dbname=%s", connStr, c.dbName)
	}

	switch cfg.SslMode {
	case corev1.Service_Spec_Config_Postgres_DISABLE:
		connStr = fmt.Sprintf("%s sslmode=disable", connStr)
	case corev1.Service_Spec_Config_Postgres_REQUIRE:
		connStr = fmt.Sprintf("%s sslmode=require", connStr)
	default:
		connStr = fmt.Sprintf("%s sslmode=prefer", connStr)
	}

	pgCfg, err := pgconn.ParseConfig(connStr)
	if err != nil {
		return err
	}

	c.upstreamConn, err = pgconn.ConnectConfig(ctx, pgCfg)
	if err != nil {
		return err
	}

	c.upstreamHijackedConn, err = c.upstreamConn.Hijack()
	if err != nil {
		return err
	}

	c.pgFrontend = pgproto3.NewFrontend(
		pgproto3.NewChunkReader(c.upstreamHijackedConn.Conn), c.upstreamHijackedConn.Conn)

	if err := c.pgBackend.Send(&pgproto3.AuthenticationOk{}); err != nil {
		return err
	}

	if err := c.pgBackend.Send(&pgproto3.BackendKeyData{
		ProcessID: c.upstreamHijackedConn.PID,
		SecretKey: c.upstreamHijackedConn.SecretKey,
	}); err != nil {
		return err
	}

	for k, v := range c.upstreamHijackedConn.ParameterStatuses {
		if err := c.pgBackend.Send(&pgproto3.ParameterStatus{Name: k, Value: v}); err != nil {
			return err
		}
	}

	if err := c.pgBackend.Send(&pgproto3.ReadyForQuery{TxStatus: 'I'}); err != nil {
		return err
	}

	zap.L().Debug("Connecting is successful", zap.String("id", c.id))

	return nil
}

func (c *dctx) serve(ctx context.Context) error {
	serverConn, err := pgconn.Construct(c.upstreamHijackedConn)
	if err != nil {
		return err
	}
	defer func() {
		serverConn.Close(ctx)
	}()

	go c.startDownstreamLoop(ctx)
	go c.startUpstreamLoop(ctx, serverConn)

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
			message, err := c.pgBackend.Receive()
			if err != nil {
				c.downstreamCh <- err
				return
			}
			zap.L().Debug("downstream msg", zap.Any("msg", message))

			switch message.(type) {
			case *pgproto3.Terminate:
				zap.L().Debug("Received terminate msg. Exiting downstreamLoop")
				c.downstreamCh <- nil
				return
			default:
				proceed, reason, err := c.authorizeCommand(ctx, message)
				if err != nil {
					c.downstreamCh <- err
					return
				}
				c.setMessageLog(message, reason)
				if !proceed {
					continue
				}
			}

			err = c.pgFrontend.Send(message)
			if err != nil {
				c.downstreamCh <- err
				return
			}
		}

	}
}

func (c *dctx) authorizeCommand(ctx context.Context, message pgproto3.FrontendMessage) (bool, *corev1.AccessLog_Entry_Common_Reason, error) {
	auth := c.svcConfig.GetPostgres().Authorization
	if auth == nil {
		return true, c.reasonInit, nil
	}

	if auth.Mode != corev1.Service_Spec_Config_Postgres_Authorization_ALL {
		return true, c.reasonInit, nil
	}

	request := &corev1.RequestContext_Request{
		Type: &corev1.RequestContext_Request_Postgres_{
			Postgres: &corev1.RequestContext_Request_Postgres{},
		},
	}

	switch msg := message.(type) {
	case *pgproto3.Query:
		zap.L().Debug("Received a query", zap.String("query", msg.String))
		request.GetPostgres().Type = &corev1.RequestContext_Request_Postgres_Query_{
			Query: &corev1.RequestContext_Request_Postgres_Query{
				Query: msg.String,
			},
		}
	case *pgproto3.Parse:
		zap.L().Debug("Received a parse", zap.String("query", msg.Query))
		request.GetPostgres().Type = &corev1.RequestContext_Request_Postgres_Parse_{
			Parse: &corev1.RequestContext_Request_Postgres_Parse{
				Query: msg.Query,
				Name:  msg.Name,
			},
		}
	default:
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
		if err := c.pgBackend.Send(&pgproto3.ErrorResponse{
			Severity: "FATAL",
			Code:     "28000",
			Message:  "Octelium: Unauthorized",
		}); err != nil {
			return false, resp.Reason, err
		}
		if err := c.pgBackend.Send(&pgproto3.ReadyForQuery{TxStatus: 'I'}); err != nil {
			return false, resp.Reason, err
		}

		return false, resp.Reason, nil
	}

	return true, resp.Reason, nil
}

func (c *dctx) startUpstreamLoop(ctx context.Context, serverConn *pgconn.PgConn) {
	defer zap.L().Debug("upstreamLoop exited...")
	zap.L().Debug("Starting upstreamLoop")
	for {
		select {
		case <-ctx.Done():
			zap.L().Debug("ctx done. Exiting upstreamLoop")
			return
		default:
			message, err := c.pgFrontend.Receive()
			if err != nil {
				if serverConn.IsClosed() {
					c.upstreamCh <- nil
					return
				}
				c.upstreamCh <- err
				return
			}
			zap.L().Debug("upstream msg", zap.Any("msg", message))

			err = c.pgBackend.Send(message)
			if err != nil {
				c.upstreamCh <- err
				return
			}
		}

	}
}

func (c *dctx) setMessageLog(msg pgproto3.FrontendMessage, reason *corev1.AccessLog_Entry_Common_Reason) {
	logE := logentry.InitializeLogEntry(&logentry.InitializeLogEntryOpts{
		StartTime:       time.Now(),
		IsAuthenticated: true,
		IsAuthorized:    true,
		ReqCtx:          c.reqCtx,
		ConnectionID:    c.id,
		Reason:          reason,
	})
	logE.Entry.Info.Type = &corev1.AccessLog_Entry_Info_Postgres_{
		Postgres: &corev1.AccessLog_Entry_Info_Postgres{},
	}
	info := logE.Entry.Info.GetPostgres()

	switch m := msg.(type) {
	case *pgproto3.Query:
		info.Type = corev1.AccessLog_Entry_Info_Postgres_QUERY
		info.Details = &corev1.AccessLog_Entry_Info_Postgres_Query_{
			Query: &corev1.AccessLog_Entry_Info_Postgres_Query{
				Query: m.String,
			},
		}
	case *pgproto3.Parse:
		info.Type = corev1.AccessLog_Entry_Info_Postgres_PARSE
		info.Details = &corev1.AccessLog_Entry_Info_Postgres_Parse_{
			Parse: &corev1.AccessLog_Entry_Info_Postgres_Parse{
				Name:  m.Name,
				Query: m.Query,
			},
		}
	case *pgproto3.Bind:
		info.Type = corev1.AccessLog_Entry_Info_Postgres_BIND
	case *pgproto3.Execute:
		info.Type = corev1.AccessLog_Entry_Info_Postgres_EXECUTE
	case *pgproto3.Close:
		info.Type = corev1.AccessLog_Entry_Info_Postgres_CLOSE
	case *pgproto3.FunctionCall:
		info.Type = corev1.AccessLog_Entry_Info_Postgres_FUNCTION_CALL
	}

	otelutils.EmitAccessLog(logE)
}
