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
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/go-resty/resty/v2"
	"go.uber.org/zap"
)

func (h *H) HTTP() *resty.Client {
	return resty.New().
		SetRetryCount(20).
		SetRetryWaitTime(500 * time.Millisecond).
		SetRetryMaxWaitTime(2 * time.Second).
		AddRetryCondition(func(r *resty.Response, err error) bool {
			return r.StatusCode() >= 500 && r.StatusCode() < 600
		}).
		AddRetryHook(func(r *resty.Response, err error) {
			zap.L().Debug("Retrying....", zap.Error(err))
		}).
		SetTimeout(40 * time.Second).
		SetLogger(zap.S())
}

func (h *H) ClusterURL() string {
	return fmt.Sprintf("https://%s", h.Domain)
}

func (h *H) PublicURL(svc string) string {
	return fmt.Sprintf("https://%s.%s", svc, h.Domain)
}

func (h *H) HTTPPublic(svc string) *resty.Client {
	return h.HTTP().SetBaseURL(h.PublicURL(svc))
}

func (h *H) HTTPPublicToken(svc, accessToken string) *resty.Client {
	return h.HTTPPublic(svc).SetAuthScheme("Bearer").SetAuthToken(accessToken)
}

func (h *H) GetStatus(t *testing.T, c *resty.Client, path string, want int) *resty.Response {
	t.Helper()

	res, err := c.R().Get(path)
	if err != nil {
		t.Fatalf("GET %s failed: %+v", path, err)
	}

	if res.StatusCode() != want {
		t.Errorf("GET %s: got status %d, want %d", path, res.StatusCode(), want)
	}

	return res
}

func (h *H) CheckPublicToken(t *testing.T, svc, accessToken string) {
	t.Helper()
	h.GetStatus(t, h.HTTPPublicToken(svc, accessToken), "/", http.StatusOK)
}
