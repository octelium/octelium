// Copyright Octelium Labs, LLC. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

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
