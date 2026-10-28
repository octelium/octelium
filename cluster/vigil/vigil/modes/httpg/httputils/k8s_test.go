package httputils

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestKubernetesRequestVerbs(t *testing.T) {
	for _, tc := range []struct {
		name        string
		method      string
		path        string
		verb        string
		group       string
		namespace   string
		resource    string
		object      string
		subresource string
	}{
		{"List", http.MethodGet, "/api/v1/pods", "list", "", "", "pods", "", ""},
		{"Watch", http.MethodGet, "/api/v1/pods?watch=true", "watch", "", "", "pods", "", ""},
		{"WatchLegacy", http.MethodGet, "/api/v1/watch/namespaces/team/pods", "watch", "", "team", "pods", "", ""},
		{"Get", http.MethodGet, "/api/v1/namespaces/team/pods/app", "get", "", "team", "pods", "app", ""},
		{"Head", http.MethodHead, "/api/v1/namespaces/team/pods/app", "get", "", "team", "pods", "app", ""},
		{"Create", http.MethodPost, "/apis/apps/v1/namespaces/team/deployments", "create", "apps", "team", "deployments", "", ""},
		{"Update", http.MethodPut, "/api/v1/namespaces/team/pods/app", "update", "", "team", "pods", "app", ""},
		{"Patch", http.MethodPatch, "/api/v1/namespaces/team/pods/app/status", "patch", "", "team", "pods", "app", "status"},
		{"Delete", http.MethodDelete, "/api/v1/namespaces/team/pods/app", "delete", "", "team", "pods", "app", ""},
		{"DeleteCollection", http.MethodDelete, "/api/v1/namespaces/team/pods", "deletecollection", "", "team", "pods", "", ""},
		{"Exec", http.MethodPost, "/api/v1/namespaces/team/pods/app/exec", "create", "", "team", "pods", "app", "exec"},
		{"NamespaceStatus", http.MethodGet, "/api/v1/namespaces/team/status", "get", "", "team", "namespaces", "team", "status"},
		{"FieldSelector", http.MethodGet, "/api/v1/pods?fieldSelector=metadata.name%3Dapp", "list", "", "", "pods", "app", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ParseKubernetesRequest(httptest.NewRequest(tc.method, tc.path, nil))
			require.Nil(t, err)
			assert.True(t, got.IsResourceRequest)
			assert.Equal(t, tc.verb, got.Verb)
			assert.Equal(t, tc.group, got.APIGroup)
			assert.Equal(t, tc.namespace, got.Namespace)
			assert.Equal(t, tc.resource, got.Resource)
			assert.Equal(t, tc.object, got.Name)
			assert.Equal(t, tc.subresource, got.Subresource)
			assert.Equal(t, "v1", got.APIVersion)
		})
	}
}

func TestKubernetesRequestNonResourcesAndMalformed(t *testing.T) {
	for _, path := range []string{"/", "/healthz", "/version", "/api", "/api/v1", "/apis/apps/v1", "/other/v1/pods"} {
		t.Run(path, func(t *testing.T) {
			got, err := ParseKubernetesRequest(httptest.NewRequest(http.MethodGet, path, nil))
			require.Nil(t, err)
			assert.False(t, got.IsResourceRequest)
			assert.Equal(t, "get", got.Verb)
		})
	}
	for _, path := range []string{"/api/v1/watch", "/apis/apps/v1/proxy"} {
		_, err := ParseKubernetesRequest(httptest.NewRequest(http.MethodGet, path, nil))
		assert.NotNil(t, err)
	}
	for _, query := range []string{"watch=true&timeoutSeconds=invalid", "watch=unexpected"} {
		got, err := ParseKubernetesRequest(httptest.NewRequest(http.MethodGet, "/api/v1/pods?"+query, nil))
		require.Nil(t, err)
		assert.Equal(t, "watch", got.Verb)
	}
}
