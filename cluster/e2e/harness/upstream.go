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
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"github.com/pkg/errors"
	"go.uber.org/zap"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"
)

type TestSrvHTTP struct {
	Port    int
	IsHTTP2 bool
	IsWS    bool

	Crt         *tls.Certificate
	CAPool      *x509.CertPool
	BearerToken string

	serveFn atomic.Pointer[func(w http.ResponseWriter, r *http.Request)]
	srv     *http.Server
	lis     net.Listener
}

func (s *TestSrvHTTP) SetServeFn(fn func(w http.ResponseWriter, r *http.Request)) {
	if fn == nil {
		s.serveFn.Store(nil)
		return
	}
	s.serveFn.Store(&fn)
}

type tstResp struct {
	Hello string `json:"hello"`
}

func (s *TestSrvHTTP) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	zap.L().Debug("New TestSrvHTTP req",
		zap.Any("req", r.Header),
		zap.String("path", r.RequestURI),
		zap.String("method", r.Method),
		zap.String("host", r.Host),
		zap.String("url", r.URL.String()))

	if fn := s.serveFn.Load(); fn != nil {
		(*fn)(w, r)
		return
	}

	if r.Method == http.MethodPost {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		defer r.Body.Close()

		var req tstResp
		if err := json.Unmarshal(body, &req); err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		resp, err := json.Marshal(&tstResp{Hello: req.Hello})
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.Write(resp)
		return
	}

	if s.BearerToken != "" {
		tkn := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		if s.BearerToken != tkn {
			w.WriteHeader(http.StatusForbidden)
			return
		}
	}

	if !s.IsWS {
		w.Header().Set("Content-Type", "application/json")
		resp, err := json.Marshal(&tstResp{Hello: "world"})
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.Write(resp)
		return
	}

	upgrader := websocket.Upgrader{
		ReadBufferSize:  1024,
		WriteBufferSize: 1024,
		CheckOrigin:     func(r *http.Request) bool { return true },
	}

	wsConn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	defer wsConn.Close()

	ctx := r.Context()
	for {
		select {
		case <-ctx.Done():
			return
		default:
			_, payload, err := wsConn.ReadMessage()
			if err != nil {
				return
			}
			wsConn.WriteMessage(websocket.BinaryMessage, payload)
		}
	}
}

func (s *TestSrvHTTP) Run(ctx context.Context) error {
	addr := fmt.Sprintf("localhost:%d", s.Port)

	var handler http.Handler = http.AllowQuerySemicolons(s)
	if s.IsHTTP2 {
		handler = h2c.NewHandler(handler, &http2.Server{})
	}

	s.srv = &http.Server{Addr: addr, Handler: handler}

	lis, err := listenWithRetry(addr, s.tlsConfig())
	if err != nil {
		return err
	}
	s.lis = lis

	go s.srv.Serve(s.lis)

	return WaitPortOpen(s.Port, 30*time.Second)
}

func (s *TestSrvHTTP) tlsConfig() *tls.Config {
	if s.Crt == nil {
		return nil
	}

	return &tls.Config{
		Certificates: []tls.Certificate{*s.Crt},
		NextProtos: func() []string {
			if s.IsHTTP2 {
				return []string{"h2", "http/1.1"}
			}
			return []string{"http/1.1"}
		}(),
		RootCAs: s.CAPool,
	}
}

func (s *TestSrvHTTP) Close() {
	if s.srv != nil {
		s.srv.Close()
	}
	if s.lis != nil {
		s.lis.Close()
	}
}

func (h *H) StartHTTPUpstream(t *testing.T, srv *TestSrvHTTP) *TestSrvHTTP {
	t.Helper()

	if srv == nil {
		srv = &TestSrvHTTP{}
	}
	if srv.Port == 0 {
		srv.Port = h.Port()
	}

	if err := srv.Run(t.Context()); err != nil {
		t.Fatalf("Could not start the local HTTP upstream: %+v", err)
	}

	t.Cleanup(srv.Close)
	return srv
}

func listenWithRetry(addr string, tlsCfg *tls.Config) (net.Listener, error) {
	deadline := time.Now().Add(30 * time.Second)

	var lastErr error
	for time.Now().Before(deadline) {
		var lis net.Listener
		var err error

		if tlsCfg != nil {
			lis, err = tls.Listen("tcp", addr, tlsCfg)
		} else {
			lis, err = net.Listen("tcp", addr)
		}

		if err == nil {
			return lis, nil
		}

		lastErr = err
		time.Sleep(DefaultPollInterval)
	}

	return nil, errors.Errorf("Could not listen on %s: %+v", addr, lastErr)
}
