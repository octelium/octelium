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
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/PuerkitoBio/goquery"
	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/stretchr/testify/assert"
)

func TestRenderIndex(t *testing.T) {
	ctx := context.Background()

	clusterCfg := &corev1.ClusterConfig{
		Status: &corev1.ClusterConfig_Status{
			Domain: "example.com",
		},
	}

	srv, err := initServer(ctx, nil, clusterCfg)
	assert.Nil(t, err)

	req := httptest.NewRequest("GET", "http://localhost/", nil)
	w := httptest.NewRecorder()
	srv.handleIndex(w, req)
	resp := w.Result()
	defer resp.Body.Close()
	blob, err := io.ReadAll(resp.Body)
	assert.Nil(t, err)

	assert.True(t, strings.Contains(resp.Header.Get("Content-Security-Policy"), "frame-src"))

	assert.Equal(t, resp.StatusCode, http.StatusOK)
	assert.Empty(t, resp.Cookies())

	doc, err := goquery.NewDocumentFromReader(strings.NewReader(string(blob)))
	assert.Nil(t, err)
	script := doc.Find("script").FilterFunction(func(_ int, sel *goquery.Selection) bool {
		return strings.Contains(sel.Text(), "window.__OCTELIUM_GLOBALS__")
	})
	assert.Equal(t, 1, script.Length())

	nonce := script.AttrOr("nonce", "")
	assert.NotEmpty(t, nonce)
	assert.Contains(t, resp.Header.Get("Content-Security-Policy"), "'nonce-"+nonce+"'")
	_, globalsJSON, found := strings.Cut(script.Text(), " = ")
	assert.True(t, found)
	var globals templateGlobals
	assert.Nil(t, json.Unmarshal([]byte(globalsJSON), &globals))
	assert.Equal(t, clusterCfg.Status.Domain, globals.Cluster.Domain)
}
