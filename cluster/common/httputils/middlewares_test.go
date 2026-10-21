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
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestChain(t *testing.T) {
	var calls []string
	newMiddleware := func(name string) Constructor {
		return func(next http.Handler) (http.Handler, error) {
			return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
				calls = append(calls, name+"-before")
				next.ServeHTTP(w, req)
				calls = append(calls, name+"-after")
			}), nil
		}
	}
	base := New(newMiddleware("first"))
	chain := base.Append(newMiddleware("second")).Extend(New(newMiddleware("third")))
	handler, err := chain.ThenFunc(func(w http.ResponseWriter, req *http.Request) {
		calls = append(calls, "handler")
		w.WriteHeader(http.StatusAccepted)
	})
	assert.Nil(t, err)
	resp := httptest.NewRecorder()
	handler.ServeHTTP(resp, httptest.NewRequest(http.MethodGet, "/", nil))
	assert.Equal(t, http.StatusAccepted, resp.Code)
	assert.Equal(t, []string{"first-before", "second-before", "third-before", "handler", "third-after", "second-after", "first-after"}, calls)
	assert.Len(t, base.constructors, 1)
	assert.Len(t, chain.constructors, 3)

	handler, err = New().Then(nil)
	assert.Nil(t, err)
	assert.Equal(t, http.DefaultServeMux, handler)
	handler, err = New().ThenFunc(nil)
	assert.Nil(t, err)
	assert.Equal(t, http.DefaultServeMux, handler)
}

func TestChainConstructorError(t *testing.T) {
	wantErr := fmt.Errorf("middleware failed")
	var calls []string
	chain := New(
		func(next http.Handler) (http.Handler, error) {
			calls = append(calls, "first")
			return next, nil
		},
		func(next http.Handler) (http.Handler, error) {
			calls = append(calls, "second")
			return nil, wantErr
		},
		func(next http.Handler) (http.Handler, error) {
			calls = append(calls, "third")
			return next, nil
		},
	)
	handler, err := chain.Then(nil)
	assert.ErrorIs(t, err, wantErr)
	assert.Nil(t, handler)
	assert.Equal(t, []string{"third", "second"}, calls)
}

func TestForwardedAddressBoundaries(t *testing.T) {
	for _, tc := range []struct {
		header string
		want   string
	}{
		{"8.8.8.8, invalid, 10.0.0.1", "8.8.8.8"},
		{"8.8.8.8,  1.1.1.1 , 127.0.0.1", "1.1.1.1"},
		{"8.8.8.8, [::1], 127.0.0.1:80", "8.8.8.8"},
		{"8.8.8.8, 0.0.0.0, ::, ::1, fe80::1, fd00::1", "8.8.8.8"},
		{"fd00::1, 2606:4700:4700:0:0:0:0:1111", "2606:4700:4700::1111"},
		{" ,invalid,,", ""},
		{"10.0.0.1, 169.254.1.1, ff02::1", ""},
	} {
		assert.Equal(t, tc.want, GetDownstreamPublicIPFromXFFHeader(tc.header), tc.header)
	}
}

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
