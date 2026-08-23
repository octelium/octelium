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

package harness

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"go.uber.org/zap"
)

type MCPSrv struct {
	Port int

	lis net.Listener
	srv *http.Server
}

type mcpEchoParams struct {
	Input string `json:"input"`
}

func (s *MCPSrv) doEcho(ctx context.Context,
	req *mcp.CallToolRequest, params *mcpEchoParams) (*mcp.CallToolResult, any, error) {
	zap.L().Debug("New mcp doEcho req", zap.Any("req", req), zap.Any("params", params))

	return &mcp.CallToolResult{
		Content: []mcp.Content{
			&mcp.TextContent{Text: params.Input},
		},
	}, nil, nil
}

type mcpTransferParams struct {
	Amount int `json:"amount"`
}

func (s *MCPSrv) doTransfer(ctx context.Context,
	req *mcp.CallToolRequest, params *mcpTransferParams) (*mcp.CallToolResult, any, error) {
	zap.L().Debug("New mcp doTransfer req", zap.Any("req", req), zap.Any("params", params))

	return &mcp.CallToolResult{
		Content: []mcp.Content{
			&mcp.TextContent{Text: fmt.Sprintf("transferred %d", params.Amount)},
		},
	}, nil, nil
}

func (s *MCPSrv) Run(ctx context.Context) error {
	addr := fmt.Sprintf("localhost:%d", s.Port)

	server := mcp.NewServer(&mcp.Implementation{
		Name:    "echo-server",
		Version: "1.0.0",
	}, nil)

	mcp.AddTool(server, &mcp.Tool{
		Name:        "echo",
		Description: "Echo the input",
	}, s.doEcho)

	mcp.AddTool(server, &mcp.Tool{
		Name:        "transfer",
		Description: "Transfer an amount",
	}, s.doTransfer)

	handler := mcp.NewStreamableHTTPHandler(func(req *http.Request) *mcp.Server {
		return server
	}, nil)

	lis, err := listenWithRetry(addr, nil)
	if err != nil {
		return err
	}
	s.lis = lis

	s.srv = &http.Server{Addr: addr, Handler: handler}
	go s.srv.Serve(s.lis)

	if err := WaitPortOpen(s.Port, 30*time.Second); err != nil {
		return err
	}

	zap.L().Debug("Started running mcp server", zap.String("addr", addr))
	return nil
}

func (s *MCPSrv) Close() {
	if s.srv != nil {
		s.srv.Close()
	}
	if s.lis != nil {
		s.lis.Close()
	}
}

func (h *H) StartMCPUpstream(t *testing.T, srv *MCPSrv) *MCPSrv {
	t.Helper()

	if srv == nil {
		srv = &MCPSrv{}
	}
	if srv.Port == 0 {
		srv.Port = h.Port()
	}

	if err := srv.Run(t.Context()); err != nil {
		t.Fatalf("Could not start the local MCP upstream: %+v", err)
	}

	t.Cleanup(srv.Close)
	return srv
}
