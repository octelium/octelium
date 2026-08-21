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

package httputils

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/octelium/octelium/apis/main/corev1"
)

func NormalizeOrigin(arg string) (string, bool) {
	u, err := url.Parse(arg)
	if err != nil || u.Scheme == "" || u.Host == "" ||
		u.User != nil || u.Path != "" || u.RawQuery != "" || u.Fragment != "" {
		return "", false
	}

	scheme := strings.ToLower(u.Scheme)
	host := strings.ToLower(u.Hostname())
	if host == "" {
		return "", false
	}

	port := u.Port()
	if (scheme == "https" && port == "443") || (scheme == "http" && port == "80") {
		port = ""
	}

	if port == "" {
		return fmt.Sprintf("%s://%s", scheme, host), true
	}

	return fmt.Sprintf("%s://%s:%s", scheme, host, port), true
}

func IsSameOrigin(req *http.Request, origin string) bool {
	if req.Host == "" {
		return false
	}

	for _, scheme := range []string{"https", "http"} {
		if self, ok := NormalizeOrigin(scheme + "://" + req.Host); ok && self == origin {
			return true
		}
	}

	return false
}

func GetRequestOrigin(req *http.Request) (string, bool) {
	vals := req.Header.Values("Origin")
	if len(vals) != 1 {
		return "", false
	}

	return NormalizeOrigin(vals[0])
}

func IsCORSPreflight(req *http.Request) bool {
	if req.Method != http.MethodOptions {
		return false
	}

	if req.Header.Get("Access-Control-Request-Method") == "" {
		return false
	}

	_, ok := GetRequestOrigin(req)
	return ok
}

func IsClusterServiceOrigin(origin, domain string) bool {
	if origin == "" || domain == "" {
		return false
	}

	u, err := url.Parse(origin)
	if err != nil || u.Scheme != "https" {
		return false
	}

	host := u.Hostname()
	domain = strings.ToLower(domain)

	return host == domain || strings.HasSuffix(host, "."+domain)
}

func allowCORSCredentials(cfg *corev1.Service_Spec_Config_HTTP_CORS,
	origin, domain string) bool {

	if cfg.GetAllowCredentials() {
		return true
	}

	return cfg.GetAllowClusterServices() && IsClusterServiceOrigin(origin, domain)
}

func GetCORSOrigin(req *http.Request,
	cfg *corev1.Service_Spec_Config_HTTP_CORS, domain string) string {

	origin, ok := GetRequestOrigin(req)
	if !ok {
		return ""
	}

	if IsSameOrigin(req, origin) {
		return origin
	}

	if cfg.GetAllowClusterServices() && IsClusterServiceOrigin(origin, domain) {
		return origin
	}

	for _, item := range cfg.GetAllowOriginStringMatch() {
		if item == "*" {
			return origin
		}
		if normalized, ok := NormalizeOrigin(item); ok && normalized == origin {
			return origin
		}
	}

	return ""
}

func SetCORSResponseHeaders(hdr http.Header,
	cfg *corev1.Service_Spec_Config_HTTP_CORS, origin, domain string) {

	hdr.Add("Vary", "Origin")

	if origin == "" {
		return
	}

	hdr.Set("Access-Control-Allow-Origin", origin)

	if allowCORSCredentials(cfg, origin, domain) {
		hdr.Set("Access-Control-Allow-Credentials", "true")
	}

	if val := cfg.GetExposeHeaders(); val != "" {
		hdr.Set("Access-Control-Expose-Headers", val)
	}
}

func WriteCORSPreflight(w http.ResponseWriter, req *http.Request,
	cfg *corev1.Service_Spec_Config_HTTP_CORS, origin, domain string) {

	hdr := w.Header()

	hdr.Add("Vary", "Origin")
	hdr.Add("Vary", "Access-Control-Request-Method")
	hdr.Add("Vary", "Access-Control-Request-Headers")
	hdr.Set("Server", "octelium")

	if origin == "" {
		w.WriteHeader(http.StatusForbidden)
		return
	}

	hdr.Set("Access-Control-Allow-Origin", origin)

	if allowCORSCredentials(cfg, origin, domain) {
		hdr.Set("Access-Control-Allow-Credentials", "true")
	}

	if val := cfg.GetAllowMethods(); val != "" {
		hdr.Set("Access-Control-Allow-Methods", val)
	} else {
		hdr.Set("Access-Control-Allow-Methods",
			req.Header.Get("Access-Control-Request-Method"))
	}

	if val := cfg.GetAllowHeaders(); val != "" {
		hdr.Set("Access-Control-Allow-Headers", val)
	} else if val := req.Header.Get("Access-Control-Request-Headers"); val != "" {
		hdr.Set("Access-Control-Allow-Headers", val)
	}

	if val := cfg.GetMaxAge(); val != "" {
		hdr.Set("Access-Control-Max-Age", val)
	}

	w.WriteHeader(http.StatusNoContent)
}
