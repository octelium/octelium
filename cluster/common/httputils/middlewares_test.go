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
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGetDownstreamPublicIP(t *testing.T) {

	{
		req := httptest.NewRequest("POST", "http://localhost/", nil)
		res := GetDownstreamPublicIP(req)
		assert.Equal(t, "", res)
	}
	{
		req := httptest.NewRequest("POST", "http://localhost/", nil)
		req.Header.Set("X-Forwarded-For", "")
		res := GetDownstreamPublicIP(req)
		assert.Equal(t, "", res)
	}
	{
		req := httptest.NewRequest("POST", "http://localhost/", nil)
		req.Header.Set("X-Forwarded-For", "hello-world")
		res := GetDownstreamPublicIP(req)
		assert.Equal(t, "", res)
	}
	{
		req := httptest.NewRequest("POST", "http://localhost/", nil)
		req.Header.Set("X-Forwarded-For", "127.0.0.1")
		res := GetDownstreamPublicIP(req)
		assert.Equal(t, "", res)
	}
	{
		req := httptest.NewRequest("POST", "http://localhost/", nil)
		req.Header.Set("X-Forwarded-For", "10.0.1.1")
		res := GetDownstreamPublicIP(req)
		assert.Equal(t, "", res)
	}
	{
		req := httptest.NewRequest("POST", "http://localhost/", nil)
		req.Header.Set("X-Forwarded-For", "10.0.1.1, 192.168.0.2")
		res := GetDownstreamPublicIP(req)
		assert.Equal(t, "", res)
	}
	{
		req := httptest.NewRequest("POST", "http://localhost/", nil)
		req.Header.Set("X-Forwarded-For", "1.2.3.4")
		res := GetDownstreamPublicIP(req)
		assert.Equal(t, "1.2.3.4", res)
	}
	{
		req := httptest.NewRequest("POST", "http://localhost/", nil)
		req.Header.Set("X-Forwarded-For", "1.2.3.4, 4.5.6.7")
		res := GetDownstreamPublicIP(req)
		assert.Equal(t, "4.5.6.7", res)
	}
	{
		req := httptest.NewRequest("POST", "http://localhost/", nil)
		req.Header.Set("X-Forwarded-For", "1.2.3.4, 4.5.6.7, 172.16.1.2")
		res := GetDownstreamPublicIP(req)
		assert.Equal(t, "4.5.6.7", res)
	}
	{
		req := httptest.NewRequest("POST", "http://localhost/", nil)
		req.Header.Set("X-Forwarded-For", "hello-world, 1.2.3.4, 4.5.6.7, 172.16.1.2")
		res := GetDownstreamPublicIP(req)
		assert.Equal(t, "4.5.6.7", res)
	}
}
