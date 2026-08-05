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
	"testing"
	"time"
)

func TestNewTokenSnapshotRefreshLeeway(t *testing.T) {
	now := time.Now()
	tkn := newTokenSnapshot("access", "refresh", now, time.Minute, 30*time.Second)

	// The requested 30-second leeway is capped to 20% of a one-minute token.
	expected := now.Add(48 * time.Second)
	if !tkn.refreshAt.Equal(expected) {
		t.Fatalf("expected refreshAt %s, got %s", expected, tkn.refreshAt)
	}
}
