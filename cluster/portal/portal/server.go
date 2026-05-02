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

package portal

import (
	"context"
	"net/http"
	"time"

	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/cluster/common/healthcheck"
	"github.com/octelium/octelium/cluster/common/octeliumc"
	"github.com/octelium/octelium/cluster/common/vutils"
	"github.com/patrickmn/go-cache"
	"go.uber.org/zap"
)

type server struct {
	domain string

	octeliumC octeliumc.ClientInterface

	stateCache *cache.Cache
	genCache   *cache.Cache
}

func initServer(ctx context.Context,
	octeliumC octeliumc.ClientInterface,
	clusterCfg *corev1.ClusterConfig) (*server, error) {

	ret := &server{
		domain:    clusterCfg.Status.Domain,
		octeliumC: octeliumC,

		stateCache: cache.New(14*time.Minute, 1*time.Minute),
		genCache:   cache.New(cache.NoExpiration, 1*time.Minute),
	}

	ret.setTemplateGlobals(clusterCfg)

	zap.L().Debug("initializing server completed")

	return ret, nil
}

func (s *server) setTemplateGlobals(clusterCfg *corev1.ClusterConfig) {
	t := &templateGlobals{
		Cluster: templateGlobalsCluster{
			Domain:      clusterCfg.Status.Domain,
			DisplayName: clusterCfg.Metadata.DisplayName,
		},
	}

	s.genCache.Set("template-globals", t, cache.NoExpiration)
}

func (s *server) getTemplateGlobals() *templateGlobals {
	val, found := s.genCache.Get("template-globals")
	if !found {
		return nil
	}

	return val.(*templateGlobals)
}

func (s *server) getMux() *http.ServeMux {
	mux := http.NewServeMux()

	mux.Handle("GET /assets/{file}", s.handleStatic())

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			s.handleIndex(w, r)
		} else {
			w.WriteHeader(http.StatusNotFound)
		}
	})

	return mux
}

func (s *server) run(ctx context.Context) error {

	go func() error {
		srv := &http.Server{
			Handler:      s.getMux(),
			Addr:         vutils.ManagedServiceAddr,
			WriteTimeout: 15 * time.Second,
			ReadTimeout:  15 * time.Second,
		}

		return srv.ListenAndServe()
	}()

	return nil
}

func Run(ctx context.Context) error {

	octeliumC, err := octeliumc.NewClient(ctx)
	if err != nil {
		return err
	}

	clusterCfg, err := octeliumC.CoreV1Utils().GetClusterConfig(ctx)
	if err != nil {
		return err
	}

	s, err := initServer(ctx, octeliumC, clusterCfg)
	if err != nil {
		return err
	}

	if err := s.run(ctx); err != nil {
		return err
	}

	healthcheck.Run(vutils.HealthCheckPortManagedService)
	zap.S().Info("Portal is running")
	<-ctx.Done()

	return nil
}
