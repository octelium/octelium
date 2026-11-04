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

package k8sretry

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

func TestCreateHTTPResponseLoss(t *testing.T) {
	for _, committed := range []bool{false, true} {
		t.Run(map[bool]string{false: "before-commit", true: "after-commit"}[committed], func(t *testing.T) {
			var mu sync.Mutex
			var stored *corev1.Secret
			creates, readbacks := 0, 0
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				mu.Lock()
				defer mu.Unlock()
				w.Header().Set("Content-Type", "application/json")
				switch r.Method {
				case http.MethodPost:
					creates++
					input := &corev1.Secret{}
					if !assert.NoError(t, json.NewDecoder(r.Body).Decode(input)) {
						w.WriteHeader(http.StatusBadRequest)
						return
					}
					if committed || creates > 1 {
						stored = input.DeepCopy()
						stored.UID, stored.ResourceVersion = "committed", "1"
						stored.TypeMeta = metav1.TypeMeta{Kind: "Secret", APIVersion: "v1"}
					}
					if creates == 1 {
						conn, _, err := w.(http.Hijacker).Hijack()
						if err == nil {
							conn.Close()
						}
						return
					}
					w.WriteHeader(http.StatusCreated)
					json.NewEncoder(w).Encode(stored)
				case http.MethodGet:
					readbacks++
					if stored == nil {
						w.WriteHeader(http.StatusNotFound)
						json.NewEncoder(w).Encode(&metav1.Status{TypeMeta: metav1.TypeMeta{Kind: "Status", APIVersion: "v1"}, Status: "Failure", Reason: metav1.StatusReasonNotFound, Code: http.StatusNotFound})
						return
					}
					if committed && readbacks == 1 {
						w.WriteHeader(http.StatusServiceUnavailable)
						json.NewEncoder(w).Encode(&metav1.Status{TypeMeta: metav1.TypeMeta{Kind: "Status", APIVersion: "v1"}, Status: "Failure", Reason: metav1.StatusReasonServiceUnavailable, Code: http.StatusServiceUnavailable})
						return
					}
					json.NewEncoder(w).Encode(stored)
				default:
					w.WriteHeader(http.StatusMethodNotAllowed)
				}
			}))
			t.Cleanup(server.Close)
			c, err := kubernetes.NewForConfig(&rest.Config{Host: server.URL, QPS: -1, ContentConfig: rest.ContentConfig{ContentType: "application/json"}})
			require.NoError(t, err)
			desired := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "bootstrap", Namespace: "octelium"}, Data: map[string][]byte{"data": []byte("unchanged-key-material")}}
			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			defer cancel()
			result, err := Create(ctx, desired,
				func(ctx context.Context) (*corev1.Secret, error) {
					return c.CoreV1().Secrets(desired.Namespace).Create(ctx, desired, metav1.CreateOptions{})
				},
				func(ctx context.Context) (*corev1.Secret, error) {
					return c.CoreV1().Secrets(desired.Namespace).Get(ctx, desired.Name, metav1.GetOptions{})
				})
			require.NoError(t, err)
			assert.Equal(t, desired.Data, result.Data)
			assert.Equal(t, "committed", string(result.UID))
			mu.Lock()
			defer mu.Unlock()
			if committed {
				assert.Equal(t, 1, creates)
				assert.Equal(t, 2, readbacks)
			} else {
				assert.Equal(t, 2, creates)
			}
		})
	}
}

func TestCreateRequiresStableIdentity(t *testing.T) {
	calls := 0
	_, err := Create(t.Context(), &corev1.Secret{ObjectMeta: metav1.ObjectMeta{GenerateName: "generated-"}},
		func(context.Context) (*corev1.Secret, error) { calls++; return nil, nil },
		func(context.Context) (*corev1.Secret, error) { calls++; return nil, nil })
	require.ErrorContains(t, err, "stable resource name")
	assert.Zero(t, calls)
	for _, readback := range []bool{false, true} {
		_, err := Create(t.Context(), &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "expected", Namespace: "octelium"}},
			func(context.Context) (*corev1.Secret, error) {
				if readback {
					return nil, io.ErrUnexpectedEOF
				}
				return &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "foreign"}}, nil
			},
			func(context.Context) (*corev1.Secret, error) {
				return &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "foreign"}}, nil
			})
		require.ErrorContains(t, err, "identity differs")
	}
}
