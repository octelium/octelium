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

package e2e

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/pkg/errors"
)

type params struct {
	Input string `json:"input"`
}

func (s *mcpServer) doEcho(ctx context.Context, req *mcp.CallToolRequest, params *params) (*mcp.CallToolResult, any, error) {

	return &mcp.CallToolResult{
		Content: []mcp.Content{
			&mcp.TextContent{Text: params.Input},
		},
	}, nil, nil
}

type mcpServer struct {
	port int
	lis  net.Listener
	srv  *http.Server
}

func (s *mcpServer) run(ctx context.Context) error {

	addr := fmt.Sprintf("localhost:%d", s.port)
	var err error

	server := mcp.NewServer(&mcp.Implementation{
		Name:    "echo-server",
		Version: "1.0.0",
	}, nil)

	mcp.AddTool(server, &mcp.Tool{
		Name:        "echo",
		Description: "Echo the input",
	}, s.doEcho)

	handler := mcp.NewStreamableHTTPHandler(func(req *http.Request) *mcp.Server {
		return server
	}, nil)

	s.lis, err = func() (net.Listener, error) {
		for range 100 {
			ret, err := net.Listen("tcp", addr)
			if err == nil {
				return ret, nil
			}
			time.Sleep(1 * time.Second)
		}
		return nil, errors.Errorf("Could not listen mcpSrv")
	}()
	if err != nil {
		return err
	}

	s.srv = &http.Server{
		Addr:    addr,
		Handler: handler,
	}

	go s.srv.Serve(s.lis)

	time.Sleep(1 * time.Second)

	return nil
}

func (s *mcpServer) close() {
	if s.srv != nil {
		s.srv.Close()
	}
	if s.lis != nil {
		s.lis.Close()
	}
}
