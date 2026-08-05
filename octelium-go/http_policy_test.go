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

package octelium

import (
	"net/http"
	"testing"
)

func TestAuthorizeHTTPRequest(t *testing.T) {
	client := &Client{cfg: config{domain: "example.com"}}

	tests := []struct {
		url     string
		allowed bool
	}{
		{url: "https://example.com", allowed: true},
		{url: "https://svc.example.com/path", allowed: true},
		{url: "https://notexample.com", allowed: false},
		{url: "https://example.com.attacker.test", allowed: false},
		{url: "http://svc.example.com", allowed: false},
	}

	for _, tt := range tests {
		req, err := http.NewRequest(http.MethodGet, tt.url, nil)
		if err != nil {
			t.Fatal(err)
		}

		err = client.authorizeHTTPRequest(req)
		if tt.allowed && err != nil {
			t.Fatalf("expected %s to be allowed: %v", tt.url, err)
		}
		if !tt.allowed && err == nil {
			t.Fatalf("expected %s to be rejected", tt.url)
		}
	}
}
