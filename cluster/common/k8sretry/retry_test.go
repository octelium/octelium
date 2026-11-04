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

package k8sretry

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	k8serr "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

func TestIsTransient(t *testing.T) {
	resource := schema.GroupResource{Resource: "secrets"}
	for _, tc := range []struct {
		err   error
		retry bool
	}{
		{io.EOF, true}, {io.ErrUnexpectedEOF, true}, {context.DeadlineExceeded, true},
		{&url.Error{Op: "Get", URL: "https://kubernetes", Err: io.ErrUnexpectedEOF}, true},
		{syscall.ECONNRESET, true}, {syscall.ECONNREFUSED, true},
		{&net.OpError{Op: "dial", Net: "tcp", Err: syscall.EHOSTUNREACH}, true},
		{&net.DNSError{Err: "DNS outage", Name: "kubernetes"}, true},
		{k8serr.NewServiceUnavailable("unavailable"), true}, {k8serr.NewInternalError(errors.New("storage outage")), true},
		{k8serr.NewServerTimeout(resource, "get", 1), true}, {k8serr.NewTimeoutError("timeout", 1), true},
		{k8serr.NewTooManyRequests("throttled", 1), true},
		{k8serr.NewForbidden(resource, "secret", errors.New("denied")), false}, {k8serr.NewUnauthorized("expired"), false},
		{k8serr.NewNotFound(resource, "missing"), false}, {k8serr.NewAlreadyExists(resource, "existing"), false},
		{k8serr.NewBadRequest("invalid"), false}, {context.Canceled, false}, {x509.UnknownAuthorityError{}, false},
		{errors.New("invalid response"), false},
	} {
		t.Run(tc.err.Error(), func(t *testing.T) {
			assert.Equal(t, tc.retry, IsTransient(errors.Join(errors.New("request failed"), tc.err)))
		})
	}
	assert.False(t, IsTransient(nil))
}

func TestRetryOutcomes(t *testing.T) {
	for _, state := range []string{"success", "temporary", "conflict", "permanent", "exhausted", "cancelled"} {
		t.Run(state, func(t *testing.T) {
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			calls := 0
			failure := io.ErrUnexpectedEOF
			if state == "permanent" {
				failure = k8serr.NewUnauthorized("expired")
			}
			err := Retry(ctx, wait.Backoff{Steps: 3, Duration: time.Millisecond}, func(ctx context.Context) error {
				calls++
				deadline, ok := ctx.Deadline()
				require.True(t, ok)
				assert.LessOrEqual(t, time.Until(deadline), 10*time.Second)
				if state == "cancelled" {
					cancel()
				}
				if state == "success" || ((state == "temporary" || state == "conflict") && calls == 3) {
					return nil
				}
				if state == "conflict" {
					return k8serr.NewConflict(schema.GroupResource{Resource: "secrets"}, "secret", failure)
				}
				return failure
			})
			switch state {
			case "success":
				require.NoError(t, err)
				assert.Equal(t, 1, calls)
			case "temporary", "conflict":
				require.NoError(t, err)
				assert.Equal(t, 3, calls)
			case "permanent":
				require.ErrorIs(t, err, failure)
				assert.Equal(t, 1, calls)
			case "exhausted":
				require.ErrorIs(t, err, failure)
				assert.Equal(t, 3, calls)
			case "cancelled":
				require.ErrorIs(t, err, context.Canceled)
				assert.Equal(t, 1, calls)
			}
		})
	}
}

func TestRetryCancellationAndServerBackoff(t *testing.T) {
	for _, poll := range []bool{false, true} {
		ctx, cancel := context.WithTimeout(t.Context(), 40*time.Millisecond)
		calls := 0
		check := func(context.Context) error {
			calls++
			return k8serr.NewTooManyRequests("retry later", 1)
		}
		var err error
		if poll {
			err = Wait(ctx, time.Millisecond, time.Second, func(ctx context.Context) (bool, error) { return false, check(ctx) })
		} else {
			err = Retry(ctx, wait.Backoff{Steps: 3, Duration: time.Millisecond}, check)
		}
		cancel()
		require.ErrorIs(t, err, context.DeadlineExceeded)
		assert.True(t, k8serr.IsTooManyRequests(err))
		assert.Equal(t, 1, calls)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	calls := 0
	require.ErrorIs(t, Do(ctx, func(context.Context) error { calls++; return nil }), context.Canceled)
	assert.Zero(t, calls)
}

func TestReadRecovers(t *testing.T) {
	calls := 0
	result, err := Read(t.Context(), func(context.Context) (string, error) {
		calls++
		if calls == 1 {
			return "", io.EOF
		}
		return "resource", nil
	})
	require.NoError(t, err)
	assert.Equal(t, "resource", result)
	assert.Equal(t, 2, calls)
}

func TestCreateReconcilesUncertainResults(t *testing.T) {
	for _, state := range []string{"success", "before-commit", "after-commit", "readback-outage", "create-race", "permanent-create", "permanent-readback"} {
		t.Run(state, func(t *testing.T) {
			var stored *corev1.Secret
			var trace []string
			creates, gets := 0, 0
			forbidden := k8serr.NewForbidden(schema.GroupResource{Resource: "secrets"}, "secret", errors.New("denied"))
			result, err := Create(t.Context(), &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "secret"}},
				func(context.Context) (*corev1.Secret, error) {
					creates++
					trace = append(trace, "create")
					if state == "permanent-create" {
						return nil, forbidden
					}
					if state == "create-race" && creates == 1 {
						return nil, k8serr.NewAlreadyExists(schema.GroupResource{Resource: "secrets"}, "secret")
					}
					if state == "before-commit" && creates == 1 {
						return nil, io.ErrUnexpectedEOF
					}
					stored = &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "secret", UID: "created"}, Data: map[string][]byte{"data": []byte("preserved")}}
					if (state == "after-commit" || state == "readback-outage" || state == "permanent-readback") && creates == 1 {
						return nil, io.ErrUnexpectedEOF
					}
					return stored, nil
				},
				func(context.Context) (*corev1.Secret, error) {
					gets++
					trace = append(trace, "get")
					if state == "permanent-readback" {
						return nil, forbidden
					}
					if state == "readback-outage" && gets == 1 {
						return nil, k8serr.NewServiceUnavailable("temporary read failure")
					}
					if stored == nil {
						return nil, k8serr.NewNotFound(schema.GroupResource{Resource: "secrets"}, "secret")
					}
					return stored, nil
				})
			if state == "permanent-create" || state == "permanent-readback" {
				require.True(t, k8serr.IsForbidden(err), "%v", err)
				assert.Equal(t, 1, creates)
				if state == "permanent-create" {
					assert.Zero(t, gets)
				} else {
					assert.ErrorIs(t, err, io.ErrUnexpectedEOF)
				}
				return
			}
			require.NoError(t, err)
			assert.Equal(t, stored, result)
			if state == "before-commit" || state == "create-race" {
				assert.Equal(t, []string{"create", "get", "create"}, trace)
			} else if state == "readback-outage" {
				assert.Equal(t, []string{"create", "get", "get"}, trace)
			} else if state == "after-commit" {
				assert.Equal(t, []string{"create", "get"}, trace)
			}
		})
	}
}

func TestDeleteReconcilesUncertainResults(t *testing.T) {
	for _, state := range []string{"success", "before-commit", "after-commit", "terminating", "replaced", "changed", "readback-outage", "permanent"} {
		t.Run(state, func(t *testing.T) {
			original := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "secret", UID: "original", ResourceVersion: "1"}}
			stored := original.DeepCopy()
			removes, gets := 0, 0
			var trace []string
			err := Delete(t.Context(), original,
				func(context.Context) (*corev1.Secret, error) {
					gets++
					trace = append(trace, "get")
					if state == "readback-outage" && gets == 1 {
						return nil, k8serr.NewServiceUnavailable("temporary read failure")
					}
					if stored == nil {
						return nil, k8serr.NewNotFound(schema.GroupResource{Resource: "secrets"}, "secret")
					}
					return stored, nil
				},
				func(_ context.Context, options metav1.DeleteOptions) error {
					removes++
					trace = append(trace, "delete")
					require.NotNil(t, options.Preconditions)
					assert.Equal(t, original.UID, *options.Preconditions.UID)
					assert.Equal(t, original.ResourceVersion, *options.Preconditions.ResourceVersion)
					if state == "permanent" {
						return k8serr.NewUnauthorized("expired")
					}
					if removes == 1 && state != "success" {
						switch state {
						case "after-commit":
							stored = nil
						case "terminating":
							stored.DeletionTimestamp = new(metav1.Now())
							stored.ResourceVersion = "2"
						case "replaced":
							stored.UID = "replacement"
						case "changed":
							stored.ResourceVersion = "2"
						}
						return io.ErrUnexpectedEOF
					}
					stored = nil
					return nil
				})
			switch state {
			case "replaced", "changed":
				require.ErrorContains(t, err, "Refusing to delete")
				assert.Equal(t, 1, removes)
				assert.NotNil(t, stored)
			case "permanent":
				require.True(t, k8serr.IsUnauthorized(err), "%v", err)
				assert.Equal(t, 1, removes)
				assert.Zero(t, gets)
			default:
				require.NoError(t, err)
			}
			if state == "readback-outage" {
				assert.Equal(t, []string{"delete", "get", "get", "delete"}, trace)
			}
		})
	}
}

func TestWaitRecoveryAndCancellation(t *testing.T) {
	for _, state := range []string{"ready", "pending", "temporary", "permanent", "cancelled", "stalled"} {
		t.Run(state, func(t *testing.T) {
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			calls := 0
			timeout := time.Second
			if state == "stalled" {
				timeout = 30 * time.Millisecond
			}
			err := Wait(ctx, time.Millisecond, timeout, func(ctx context.Context) (bool, error) {
				calls++
				switch state {
				case "pending":
					return calls > 1, nil
				case "temporary":
					if calls == 1 {
						return false, io.ErrUnexpectedEOF
					}
				case "permanent":
					return false, k8serr.NewUnauthorized("expired")
				case "cancelled":
					cancel()
					return true, nil
				case "stalled":
					<-ctx.Done()
					return false, ctx.Err()
				}
				return true, nil
			})
			switch state {
			case "permanent":
				require.True(t, k8serr.IsUnauthorized(err), "%v", err)
				assert.Equal(t, 1, calls)
			case "cancelled":
				require.ErrorIs(t, err, context.Canceled)
			case "stalled":
				require.ErrorIs(t, err, context.DeadlineExceeded)
			default:
				require.NoError(t, err)
			}
		})
	}
}

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
