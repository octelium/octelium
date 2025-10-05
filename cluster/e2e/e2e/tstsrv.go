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
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/gorilla/websocket"
	"github.com/pkg/errors"
	"go.uber.org/zap"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"
)

type tstSrvHTTP struct {
	port        int
	srv         *http.Server
	isHTTP2     bool
	crt         *tls.Certificate
	isWS        bool
	bearerToken string
	caPool      *x509.CertPool
	lis         net.Listener
}

type tstResp struct {
	Hello string `json:"hello"`
}

func (s *tstSrvHTTP) ServeHTTP(w http.ResponseWriter, r *http.Request) {

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
		resp, err := json.Marshal(&tstResp{
			Hello: req.Hello,
		})
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.Write(resp)
		return
	}

	if s.bearerToken != "" {
		bearer := r.Header.Get("Authorization")
		tkn := strings.TrimPrefix(bearer, "Bearer ")
		if s.bearerToken != tkn {
			w.WriteHeader(http.StatusForbidden)
			return
		}
	}

	if !s.isWS {
		w.Header().Set("Content-Type", "application/json")
		resp, err := json.Marshal(&tstResp{
			Hello: "world",
		})
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
		CheckOrigin: func(r *http.Request) bool {
			return true
		},
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
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
			wsConn.WriteMessage(websocket.BinaryMessage, payload)
		}
	}
}

func (s *tstSrvHTTP) run(ctx context.Context) error {
	addr := fmt.Sprintf("localhost:%d", s.port)
	var err error

	handler := http.AllowQuerySemicolons(s)
	if s.isHTTP2 {
		handler = h2c.NewHandler(handler, &http2.Server{})
	}
	s.srv = &http.Server{
		Addr:    addr,
		Handler: handler,
	}

	if s.crt != nil {
		zap.L().Debug("upstream listening over TLS")
		s.lis, err = func() (net.Listener, error) {
			for range 100 {
				ret, err := tls.Listen("tcp", addr, s.getTLSConfig())
				if err == nil {
					return ret, nil
				}
				time.Sleep(1 * time.Second)
			}
			return nil, errors.Errorf("Could not listen tstSrvHTTP")
		}()
		if err != nil {
			return err
		}
	} else {
		s.lis, err = func() (net.Listener, error) {
			for range 100 {
				ret, err := net.Listen("tcp", addr)
				if err == nil {
					return ret, nil
				}
				time.Sleep(1 * time.Second)
			}
			return nil, errors.Errorf("Could not listen tstSrvHTTP")
		}()
		if err != nil {
			return err
		}
	}

	go s.srv.Serve(s.lis)

	time.Sleep(1 * time.Second)

	return nil
}

func (s *tstSrvHTTP) getTLSConfig() *tls.Config {
	if s.crt == nil {
		return nil
	}

	return &tls.Config{
		Certificates: []tls.Certificate{*s.crt},
		NextProtos: func() []string {
			if s.isHTTP2 {
				return []string{"h2", "http/1.1"}
			} else {
				return []string{"http/1.1"}
			}
		}(),
		RootCAs: s.caPool,
	}

}

func (s *tstSrvHTTP) close() {
	if s.srv != nil {
		s.srv.Close()
	}
	if s.lis != nil {
		s.lis.Close()
	}
}
