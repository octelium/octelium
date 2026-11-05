package suite

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/octelium/octelium/cluster/e2e/harness"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestOpenSearchRequest(t *testing.T) {
	for _, tc := range []struct {
		name   string
		status int
		want   int
	}{
		{name: "OK", status: http.StatusOK, want: http.StatusOK},
		{name: "Created", status: http.StatusCreated, want: http.StatusCreated},
		{name: "BadGateway", status: http.StatusBadGateway, want: http.StatusCreated},
		{name: "Forbidden", status: http.StatusForbidden, want: http.StatusOK},
		{name: "UnexpectedStatus", status: http.StatusOK, want: http.StatusCreated},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var requests atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				requests.Add(1)
				assert.Equal(t, http.MethodPut, r.Method)
				assert.Equal(t, "/index/_doc/1", r.URL.Path)
				assert.Equal(t, "application/json", r.Header.Get("Content-Type"))
				var doc map[string]string
				assert.Nil(t, json.NewDecoder(r.Body).Decode(&doc))
				assert.Equal(t, map[string]string{"name": "test"}, doc)
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(tc.status)
				w.Write([]byte(`{"result":"created"}`))
			}))
			defer server.Close()

			c := (&harness.H{}).HTTPNoRetry().SetBaseURL(server.URL).
				SetHeader("Content-Type", "application/json")
			t.Cleanup(c.GetClient().CloseIdleConnections)

			body, err := openSearchRequest(t.Context(), c, http.MethodPut, "/index/_doc/1",
				map[string]string{"name": "test"}, tc.want)
			if tc.status == tc.want {
				require.Nil(t, err)
				assert.JSONEq(t, `{"result":"created"}`, string(body))
			} else {
				require.ErrorContains(t, err, "OpenSearch PUT /index/_doc/1 returned status")
				assert.Contains(t, err.Error(), `{"result":"created"}`)
			}
			assert.Equal(t, int32(1), requests.Load())
		})
	}
}

func TestOpenSearchRequestDeadline(t *testing.T) {
	for _, flushed := range []bool{false, true} {
		name := "Headers"
		if flushed {
			name = "Body"
		}
		t.Run(name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if flushed {
					w.WriteHeader(http.StatusOK)
					w.(http.Flusher).Flush()
				}
				<-r.Context().Done()
			}))
			defer server.Close()

			c := (&harness.H{}).HTTPNoRetry().SetBaseURL(server.URL)
			t.Cleanup(c.GetClient().CloseIdleConnections)
			ctx, cancel := context.WithTimeout(t.Context(), 100*time.Millisecond)
			defer cancel()

			started := time.Now()
			_, err := openSearchRequest(ctx, c, http.MethodGet, "/", nil, http.StatusOK)
			require.ErrorIs(t, err, context.DeadlineExceeded)
			assert.Less(t, time.Since(started), 2*time.Second)
		})
	}
}
