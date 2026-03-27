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
	"io"
	"net"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgproto3"
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

	lastTxStatus byte
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
		lastTxStatus:   'I',
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
	c.upstreamConn = nil

	c.pgFrontend = c.upstreamHijackedConn.Frontend

	c.pgBackend.Send(&pgproto3.AuthenticationOk{})

	c.pgBackend.Send(&pgproto3.BackendKeyData{
		ProcessID: c.upstreamHijackedConn.PID,
		SecretKey: c.upstreamHijackedConn.SecretKey,
	})

	for k, v := range c.upstreamHijackedConn.ParameterStatuses {
		c.pgBackend.Send(&pgproto3.ParameterStatus{Name: k, Value: v})
	}

	c.pgBackend.Send(&pgproto3.ReadyForQuery{TxStatus: 'I'})

	if err := c.pgBackend.Flush(); err != nil {
		return err
	}

	zap.L().Debug("Connecting is successful", zap.String("id", c.id))

	return nil
}

func (c *dctx) serve(ctx context.Context) error {
	defer func() {
		zap.L().Debug("Closing upstream hijacked conn", zap.String("id", c.id))
		if c.upstreamHijackedConn != nil && c.upstreamHijackedConn.Conn != nil {
			c.upstreamHijackedConn.Conn.Close()
		}
	}()

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

	var pendingSync bool

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

			zap.L().Debug("downstream msg received",
				zap.String("type", fmt.Sprintf("%T", message)),
				zap.Bool("pendingSync", pendingSync))

			switch message.(type) {
			case *pgproto3.Terminate:
				zap.L().Debug("Received terminate msg. Exiting downstreamLoop")
				c.downstreamCh <- nil
				return
			case *pgproto3.Sync:
				if pendingSync {
					pendingSync = false
					continue
				}
			default:
				if pendingSync {
					continue
				}
				proceed, reason, err := c.authorizeCommand(ctx, message)
				if err != nil {
					c.downstreamCh <- err
					return
				}
				c.setMessageLog(message, reason)
				if !proceed {
					pendingSync = true
					continue
				}
			}

			c.pgFrontend.Send(message)
			if err := c.pgFrontend.Flush(); err != nil {
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
		c.pgBackend.Send(&pgproto3.ErrorResponse{
			Severity: "ERROR",
			Code:     "42501",
			Message:  "Octelium: Unauthorized",
		})
		c.pgBackend.Send(&pgproto3.ReadyForQuery{TxStatus: c.lastTxStatus})

		if err := c.pgBackend.Flush(); err != nil {
			return false, resp.Reason, err
		}

		return false, resp.Reason, nil
	}

	return true, resp.Reason, nil
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
			message, err := c.pgFrontend.Receive()
			if err != nil {
				if (c.upstreamConn != nil && c.upstreamConn.IsClosed()) ||
					errors.Is(err, io.EOF) ||
					errors.Is(err, net.ErrClosed) {
					c.upstreamCh <- nil
					return
				}
				c.upstreamCh <- err
				return
			}
			zap.L().Debug("upstream msg received",
				zap.String("type", fmt.Sprintf("%T", message)))

			switch msg := message.(type) {
			case *pgproto3.ReadyForQuery:
				c.lastTxStatus = msg.TxStatus
			}

			c.pgBackend.Send(message)
			if err := c.pgBackend.Flush(); err != nil {
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
