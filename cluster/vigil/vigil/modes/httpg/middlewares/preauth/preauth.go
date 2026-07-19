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

package preauth

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/go-faster/errors"
	"github.com/octelium/octelium/apis/cluster/coctovigilv1"
	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/cluster/common/octeliumc"
	"github.com/octelium/octelium/cluster/common/vutils"
	"github.com/octelium/octelium/cluster/vigil/vigil/modes/httpg/httputils"
	"github.com/octelium/octelium/cluster/vigil/vigil/modes/httpg/middlewares"
	"github.com/octelium/octelium/pkg/apiutils/ucorev1"
	"github.com/octelium/octelium/pkg/common/pbutils"
	"go.uber.org/zap"
	"google.golang.org/grpc/codes"
)

type middleware struct {
	octeliumC octeliumc.ClientInterface
	next      http.Handler
	domain    string
}

func New(ctx context.Context, next http.Handler, octeliumC octeliumc.ClientInterface, domain string) (http.Handler, error) {

	return &middleware{
		next:      next,
		octeliumC: octeliumC,
		domain:    domain,
	}, nil
}

func (m *middleware) ServeHTTP(w http.ResponseWriter, req *http.Request) {

	ctx := req.Context()
	reqCtx := middlewares.GetCtxRequestContext(ctx)
	svc := reqCtx.Service

	if svc.Spec.IsDisabled {
		w.WriteHeader(http.StatusServiceUnavailable)
		return
	}

	if err := cleanRequest(req); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	var err error

	additional := &additionalInfo{}

	cfg := svc.Spec.Config

	if (cfg != nil &&
		cfg.GetHttp() != nil &&
		cfg.GetHttp().EnableRequestBuffering) ||
		(cfg != nil && cfg.GetHttp() != nil &&
			cfg.GetHttp().Auth != nil &&
			cfg.GetHttp().Auth.GetSigv4() != nil) {
		defer req.Body.Close()

		limit := getMaxBodySize(cfg)
		body, err := io.ReadAll(io.LimitReader(req.Body, limit+1))
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		if int64(len(body)) > limit {
			w.WriteHeader(http.StatusRequestEntityTooLarge)
			return
		}
		additional.Body = body
		reqCtx.Body = additional.Body

		if cfg != nil && cfg.GetHttp() != nil && cfg.GetHttp().Body != nil {
			buffer := cfg.GetHttp().Body

			if buffer.MaxRequestSize > 0 && len(additional.Body) > int(buffer.MaxRequestSize) {
				w.WriteHeader(http.StatusRequestEntityTooLarge)
				return
			}

			switch buffer.Mode {
			case corev1.Service_Spec_Config_HTTP_Body_JSON:
				if len(additional.Body) > 0 {
					additional.bodyMap = make(map[string]any)
					if err := json.Unmarshal(additional.Body, &additional.bodyMap); err != nil {
						w.WriteHeader(http.StatusBadRequest)
						return
					}
					reqCtx.BodyJSONMap = additional.bodyMap
				}
			}
		}

		req.Body = io.NopCloser(bytes.NewReader(additional.Body))
		req.ContentLength = int64(len(additional.Body))
	}

	downstreamReq, err := m.getDownstreamReq(req, reqCtx, additional)
	if err != nil {
		zap.L().Debug("Could not get downstreamReq", zap.Error(err))
		if ucorev1.ToService(reqCtx.Service).IsGRPC() {
			w.Header().Set("Grpc-Status", fmt.Sprintf("%d", codes.Unimplemented))
			w.Header().Set("Grpc-Message", "Octelium: unimplemented")
			w.Header().Set("Content-Type", "application/grpc")
		} else {
			w.WriteHeader(http.StatusBadRequest)
		}

		return
	}

	reqCtx.DownstreamRequest = downstreamReq

	if httputils.IsAnonymousMode(req) {

		// TODO: set Namespace
		reqCtx.DownstreamInfo = &corev1.RequestContext{
			Request: downstreamReq.Request,
			Service: svc,
		}
		reqCtx.AuthResponse = &coctovigilv1.AuthenticateAndAuthorizeResponse{
			RequestContext: reqCtx.DownstreamInfo,
		}

		m.next.ServeHTTP(w, req)
		return
	}

	reqCtx.DownstreamInfo = &corev1.RequestContext{
		Request: downstreamReq.Request,
		Service: svc,
	}

	reqCtx.ServiceConfig = svc.Spec.Config

	m.next.ServeHTTP(w, req)
}

type additionalInfo struct {
	Body       []byte
	IsBodyJSON bool
	bodyMap    map[string]any
}

const maxReqCtxBodySize = 2 * 1024 * 1024

func (m *middleware) getDownstreamReq(req *http.Request,
	reqCtx *middlewares.RequestContext,
	additional *additionalInfo) (*coctovigilv1.DownstreamRequest, error) {

	svc := reqCtx.Service

	httpC := &corev1.RequestContext_Request_HTTP{
		Headers: httputils.GetHeaders(req.Header),
		Host:    req.Host,
		Method:  req.Method,
		Scheme:  req.URL.Scheme,
		Size:    req.ContentLength,
		Path:    req.URL.Path,
		Uri:     req.URL.RequestURI(),
		Body:    additional.Body,
	}

	if len(httpC.Body) > maxReqCtxBodySize {
		httpC.Body = nil
	}

	if httpC.Body != nil {
		httpC.BodyMap, _ = pbutils.MapToStruct(additional.bodyMap)
	}

	if qry := req.URL.Query(); len(qry) > 0 {
		httpC.QueryParams = make(map[string]string)
		for k, v := range qry {
			if len(v) > 0 {
				httpC.QueryParams[k] = v[0]
			}
		}
	}

	ip := req.Header.Get(vutils.GetDownstreamIPHeaderCanonical())

	switch {
	case ucorev1.ToService(svc).IsKubernetes():
		k8sReq, err := httputils.ParseKubernetesRequest(req)
		if err != nil {
			return nil, err
		}

		return &coctovigilv1.DownstreamRequest{
			Source: getDownstreamSource(req),
			Request: &corev1.RequestContext_Request{
				Ip: ip,
				Type: &corev1.RequestContext_Request_Kubernetes_{
					Kubernetes: &corev1.RequestContext_Request_Kubernetes{
						Http:        httpC,
						Verb:        k8sReq.Verb,
						ApiPrefix:   k8sReq.APIPrefix,
						ApiGroup:    k8sReq.APIGroup,
						ApiVersion:  k8sReq.APIVersion,
						Namespace:   k8sReq.Namespace,
						Resource:    k8sReq.Resource,
						Subresource: k8sReq.Subresource,
						Name:        k8sReq.Name,
					},
				},
			},
		}, nil
	case ucorev1.ToService(svc).IsGRPC():
		info, err := httputils.GetGRPCInfo(req.URL.Path)
		if err != nil {
			return nil, err
		}
		return &coctovigilv1.DownstreamRequest{
			Source: getDownstreamSource(req),
			Request: &corev1.RequestContext_Request{
				Ip: ip,
				Type: &corev1.RequestContext_Request_Grpc{
					Grpc: &corev1.RequestContext_Request_GRPC{
						Http:            httpC,
						Service:         info.Service,
						ServiceFullName: info.FullServiceName,
						Method:          info.Method,
						Package:         info.Package,
					},
				},
			},
		}, nil
	default:
		return &coctovigilv1.DownstreamRequest{
			Source: getDownstreamSource(req),
			Request: &corev1.RequestContext_Request{
				Ip: ip,
				Type: &corev1.RequestContext_Request_Http{
					Http: httpC,
				},
			},
		}, nil
	}
}

func getDownstreamSource(r *http.Request) *coctovigilv1.DownstreamRequest_Source {
	address, port, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return &coctovigilv1.DownstreamRequest_Source{}
	}

	portInt, err := strconv.ParseInt(port, 10, 32)
	if err != nil {
		return &coctovigilv1.DownstreamRequest_Source{}
	}

	return &coctovigilv1.DownstreamRequest_Source{
		Address: address,
		Port:    int32(portInt),
	}
}

const defaultMaxBodySize = 32 * 1024 * 1024

func getMaxBodySize(svcCfg *corev1.Service_Spec_Config) int64 {
	if svcCfg != nil && svcCfg.GetHttp() != nil &&
		svcCfg.GetHttp().Body != nil &&
		svcCfg.GetHttp().Body.MaxRequestSize > 0 {
		configured := svcCfg.GetHttp().Body.MaxRequestSize
		if configured > 64*1024*1024 {
			return 64 * 1024 * 1024
		}
		return int64(configured)
	}
	return defaultMaxBodySize
}

func cleanRequest(req *http.Request) error {
	if req == nil {
		return errors.Errorf("Nil request")
	}

	if req.URL == nil {
		return errors.Errorf("Nil request URL")
	}

	if req.RequestURI == "*" {
		if req.Method != http.MethodOptions {
			return errors.Errorf("Asterisk-form request target requires OPTIONS")
		}
		return nil
	}

	if req.URL.Path == "" {
		return nil
	}

	if !strings.HasPrefix(req.URL.Path, "/") {
		return errors.Errorf("The request path is not absolute")
	}

	if err := checkPathChars(req.URL.Path); err != nil {
		return err
	}

	if !hasDotSegmentCandidate(req.URL.Path) {
		return nil
	}

	if hasBackslashDotSegment(req.URL.Path) {
		return errors.Errorf("The request path contains an ambiguous backslash dot-segment")
	}

	escapedPath := req.URL.EscapedPath()
	if !strings.HasPrefix(escapedPath, "/") {
		return errors.Errorf("The escaped request path is not absolute")
	}

	cleanedPath, pathChanged := removeDotSegments(req.URL.Path)

	cleanedEscapedPath, escapedPathChanged, err := removeEscapedDotSegments(escapedPath)
	if err != nil {
		return err
	}

	decodedEscapedPath, err := url.PathUnescape(cleanedEscapedPath)
	if err != nil {
		return errors.Errorf("The request path contains invalid percent-encoding")
	}

	if decodedEscapedPath != cleanedPath {
		return errors.Errorf("The request path contains ambiguous percent-encoded separators")
	}

	if !pathChanged && !escapedPathChanged {
		return nil
	}

	req.URL.Path = cleanedPath
	req.URL.RawPath = cleanedEscapedPath

	if req.URL.EscapedPath() != cleanedEscapedPath {
		return errors.Errorf("Could not preserve the escaped request path")
	}

	canonicalURL := *req.URL
	canonicalURL.RawPath = ""
	if canonicalURL.EscapedPath() == cleanedEscapedPath {
		req.URL.RawPath = ""
	}

	req.RequestURI = req.URL.RequestURI()

	return nil
}

func checkPathChars(path string) error {
	for i := range len(path) {
		c := path[i]
		if c < 0x20 || c == 0x7f {
			return errors.Errorf("The request path contains an invalid control character")
		}
	}

	return nil
}

func hasDotSegmentCandidate(path string) bool {
	return strings.Contains(path, "/.") || strings.Contains(path, "\\.")
}

func hasBackslashDotSegment(path string) bool {
	start := 0

	for i := 0; i <= len(path); i++ {
		if i != len(path) && path[i] != '/' && path[i] != '\\' {
			continue
		}

		segment := path[start:i]
		if segment == "." || segment == ".." {
			leftBackslash := start > 0 && path[start-1] == '\\'
			rightBackslash := i < len(path) && path[i] == '\\'

			if leftBackslash || rightBackslash {
				return true
			}
		}

		start = i + 1
	}

	return false
}

func removeDotSegments(path string) (string, bool) {
	segments := strings.Split(path, "/")
	out := make([]string, 1, len(segments))
	changed := false

	for i, segment := range segments[1:] {
		isLast := i == len(segments)-2

		switch segment {
		case ".":
			changed = true
			if isLast {
				out = append(out, "")
			}
		case "..":
			changed = true
			if len(out) > 1 {
				out = out[:len(out)-1]
			}
			if isLast {
				out = append(out, "")
			}
		default:
			out = append(out, segment)
		}
	}

	if !changed {
		return path, false
	}

	return strings.Join(out, "/"), true
}

func removeEscapedDotSegments(escapedPath string) (string, bool, error) {
	segments := strings.Split(escapedPath, "/")
	out := make([]string, 1, len(segments))
	changed := false

	for i, segment := range segments[1:] {
		decodedSegment, err := url.PathUnescape(segment)
		if err != nil {
			return "", false, errors.Errorf("The request path contains invalid percent-encoding")
		}

		isLast := i == len(segments)-2

		switch decodedSegment {
		case ".":
			changed = true
			if isLast {
				out = append(out, "")
			}
		case "..":
			changed = true
			if len(out) > 1 {
				out = out[:len(out)-1]
			}
			if isLast {
				out = append(out, "")
			}
		default:
			out = append(out, segment)
		}
	}

	if !changed {
		return escapedPath, false, nil
	}

	return strings.Join(out, "/"), true, nil
}
