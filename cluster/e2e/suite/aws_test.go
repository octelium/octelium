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

package suite

import (
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/octelium/octelium/cluster/e2e/harness"
	"github.com/stretchr/testify/assert"
)

func TestAWSFixtureReadinessWaitsForAPI(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodGet, r.Method)
		assert.Equal(t, "ListUsers", r.URL.Query().Get("Action"))
		assert.Equal(t, "2010-05-08", r.URL.Query().Get("Version"))
		switch calls.Add(1) {
		case 1:
			conn, _, err := w.(http.Hijacker).Hijack()
			if assert.Nil(t, err) {
				conn.Close()
			}
		case 2:
			w.WriteHeader(http.StatusServiceUnavailable)
		default:
			w.WriteHeader(http.StatusOK)
		}
	}))
	defer server.Close()
	c := &awsClient{endpoint: server.URL, service: "iam", client: server.Client(),
		credentials: &aws.Credentials{AccessKeyID: "test", SecretAccessKey: "test"}}
	c.waitRequest(t, &harness.H{}, http.MethodGet, "/?Action=ListUsers&Version=2010-05-08", http.StatusOK)
	assert.Equal(t, int32(3), calls.Load(), "a listening socket is insufficient when forwarding or the API fails")
}
