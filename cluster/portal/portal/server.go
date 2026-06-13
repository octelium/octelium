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
	"bytes"
	"context"
	"embed"
	"encoding/json"
	"fmt"
	"html/template"
	"io/fs"
	"net/http"
	"path/filepath"
	"strings"
	"time"

	"github.com/PuerkitoBio/goquery"
	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/cluster/common/healthcheck"
	"github.com/octelium/octelium/cluster/common/octeliumc"
	"github.com/octelium/octelium/cluster/common/vutils"
	"github.com/octelium/octelium/pkg/utils/utilrand"
	"github.com/patrickmn/go-cache"
	"github.com/pkg/errors"
	"go.uber.org/zap"
)

//go:embed web
var fsWeb embed.FS

type server struct {
	domain    string
	octeliumC octeliumc.ClientInterface
	genCache  *cache.Cache
}

type templateGlobals struct {
	Cluster templateGlobalsCluster `json:"cluster,omitempty"`
}

type templateGlobalsCluster struct {
	Domain string `json:"domain,omitempty"`
}

var indexTmpl = template.Must(template.New("state").Parse(
	`<script nonce="{{ .Nonce }}">window.__OCTELIUM_GLOBALS__ = {{ .Globals }}</script>`,
))

func initServer(ctx context.Context,
	octeliumC octeliumc.ClientInterface,
	clusterCfg *corev1.ClusterConfig) (*server, error) {

	ret := &server{
		domain:    clusterCfg.Status.Domain,
		octeliumC: octeliumC,
		genCache:  cache.New(cache.NoExpiration, 1*time.Minute),
	}

	ret.setTemplateGlobals(clusterCfg)

	return ret, nil
}

func (s *server) setTemplateGlobals(clusterCfg *corev1.ClusterConfig) {
	t := &templateGlobals{
		Cluster: templateGlobalsCluster{
			Domain: clusterCfg.Status.Domain,
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

func (s *server) setSecurityHeaders(w http.ResponseWriter, nonce string) {
	csp := strings.Join([]string{
		"default-src 'none'",
		fmt.Sprintf("script-src 'self' 'nonce-%s'", nonce),
		"style-src 'self' 'unsafe-inline'",
		"img-src 'self' data: https:",
		"font-src 'self'",
		fmt.Sprintf("connect-src 'self' https://octelium-api.%s", s.domain),
		"frame-src 'none'",
		"frame-ancestors 'none'",
		"object-src 'none'",
		"base-uri 'none'",
		"form-action 'self'",
		"manifest-src 'self'",
	}, "; ")

	w.Header().Set("Content-Security-Policy", csp)
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
	w.Header().Set("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=()")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
}

func (s *server) renderIndex(w http.ResponseWriter) {
	nonce := utilrand.GetRandomStringCanonical(24)

	blob, err := fs.ReadFile(fsWeb, filepath.Join("web", "index.html"))
	if err != nil {
		zap.L().Error("Could not read index.html", zap.Error(err))
		w.WriteHeader(http.StatusNotFound)
		return
	}

	doc, err := goquery.NewDocumentFromReader(bytes.NewReader(blob))
	if err != nil {
		zap.L().Error("Could not parse index.html", zap.Error(err))
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	globalsJSON, err := json.Marshal(s.getTemplateGlobals())
	if err != nil {
		zap.L().Error("Could not marshal globals", zap.Error(err))
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	var scripts bytes.Buffer
	if err := indexTmpl.Execute(&scripts, struct {
		Nonce   string
		Globals template.JS
	}{
		Nonce:   nonce,
		Globals: template.JS(globalsJSON),
	}); err != nil {
		zap.L().Error("Could not execute template", zap.Error(err))
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	head := doc.Find("head").First()
	if head.Length() == 0 {
		zap.L().Error("No <head> in index.html")
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	head.AppendHtml(scripts.String())

	doc.Find("script[src]").Each(func(_ int, sel *goquery.Selection) {
		sel.SetAttr("nonce", nonce)
	})
	doc.Find("link[rel='modulepreload']").Each(func(_ int, sel *goquery.Selection) {
		sel.SetAttr("nonce", nonce)
	})

	var out bytes.Buffer
	out.WriteString("<!DOCTYPE html>")
	if err := goquery.Render(&out, head.Parent()); err != nil {
		zap.L().Error("Could not render index.html", zap.Error(err))
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	s.setDomainCookie(w)
	s.setSecurityHeaders(w, nonce)
	w.Write(out.Bytes())
}

func (s *server) setDomainCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     "octelium_domain",
		Value:    s.domain,
		Secure:   true,
		Domain:   s.domain,
		Path:     "/",
		SameSite: http.SameSiteNoneMode,
	})
}

func (s *server) handleIndex(w http.ResponseWriter, r *http.Request) {
	s.renderIndex(w)
}

func (s *server) handleStatic() http.Handler {
	subFS, err := fs.Sub(fsWeb, "web")
	if err != nil {
		zap.L().Fatal("Could not initialize static fs", zap.Error(err))
	}
	return http.FileServer(http.FS(subFS))
}

func (s *server) getMux() *http.ServeMux {
	mux := http.NewServeMux()
	mux.Handle("GET /assets/{file}", s.handleStatic())
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			s.handleIndex(w, r)
		} else {
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
	})
	return mux
}

func (s *server) run(ctx context.Context) error {
	go func() {
		srv := &http.Server{
			Handler:           s.getMux(),
			Addr:              vutils.ManagedServiceAddr,
			WriteTimeout:      15 * time.Second,
			ReadTimeout:       15 * time.Second,
			ReadHeaderTimeout: 5 * time.Second,
			IdleTimeout:       60 * time.Second,
			MaxHeaderBytes:    32 * 1024,
		}
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			zap.L().Error("Portal HTTP server exited", zap.Error(err))
		}
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
	zap.L().Info("Portal is running")
	<-ctx.Done()
	return nil
}
