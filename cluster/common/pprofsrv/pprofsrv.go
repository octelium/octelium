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

package pprofsrv

import (
	"context"
	"net/http"
	"net/http/pprof"
)

type PprofServer struct {
	srv *http.Server
}

func New() *PprofServer {
	mux := http.NewServeMux()

	mux.HandleFunc("/debug/pprof/", pprof.Index)
	mux.HandleFunc("/debug/pprof/cmdline", pprof.Cmdline)
	mux.HandleFunc("/debug/pprof/profile", pprof.Profile)
	mux.HandleFunc("/debug/pprof/symbol", pprof.Symbol)
	mux.HandleFunc("/debug/pprof/trace", pprof.Trace)
	return &PprofServer{
		srv: &http.Server{
			Addr:    "localhost:49998",
			Handler: mux,
		},
	}
}

func (p *PprofServer) Run(ctx context.Context) error {
	go p.srv.ListenAndServe()
	return nil
}

func (p *PprofServer) Close() error {
	return p.srv.Close()
}
