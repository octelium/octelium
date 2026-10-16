package suite

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/cluster/common/k8sutils"
	"github.com/octelium/octelium/cluster/e2e/harness"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/require"
	appsv1 "k8s.io/api/apps/v1"
	k8scorev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	k8smetav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
)

const (
	awsRegion        = "us-east-1"
	awsEmulatorImage = "ghcr.io/faiscadev/fakecloud:0.50.0"
)

type awsClient struct {
	endpoint    string
	service     string
	client      *http.Client
	credentials *aws.Credentials
	headers     http.Header
}

type awsResponse struct {
	status int
	header http.Header
	body   []byte
}

func (c *awsClient) request(ctx context.Context, method, path string, body []byte,
	headers http.Header) (*awsResponse, error) {
	req, err := http.NewRequestWithContext(ctx, method, c.endpoint+path, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	for key, values := range c.headers {
		req.Header[key] = append([]string(nil), values...)
	}
	for key, values := range headers {
		req.Header[key] = append([]string(nil), values...)
	}
	if c.credentials != nil {
		hash := fmt.Sprintf("%x", sha256.Sum256(body))
		req.Header.Set("X-Amz-Content-Sha256", hash)
		err := v4.NewSigner().SignHTTP(ctx, *c.credentials, req, hash, c.service, awsRegion,
			time.Now(), func(o *v4.SignerOptions) { o.DisableURIPathEscaping = c.service == "s3" })
		if err != nil {
			return nil, err
		}
	}
	res, err := c.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	data, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, err
	}
	return &awsResponse{status: res.StatusCode, header: res.Header.Clone(), body: data}, nil
}

func (c *awsClient) mustRequest(t *testing.T, method, path string, body []byte,
	headers http.Header, status int) *awsResponse {
	t.Helper()
	res, err := c.request(t.Context(), method, path, body, headers)
	require.Nil(t, err, "%s %s: %v", method, path, err)
	require.Equal(t, status, res.status, "%s %s: %s", method, path, res.body)
	return res
}

func (c *awsClient) jsonRequest(ctx context.Context, target string, body any) (*awsResponse, error) {
	data, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}
	contentType := "application/x-amz-json-1.1"
	if c.service == "dynamodb" || c.service == "sqs" {
		contentType = "application/x-amz-json-1.0"
	}
	return c.request(ctx, http.MethodPost, "/", data, http.Header{
		"Content-Type": {contentType}, "X-Amz-Target": {target},
	})
}

func (c *awsClient) mustJSON(t *testing.T, target string, body, out any) *awsResponse {
	t.Helper()
	res, err := c.jsonRequest(t.Context(), target, body)
	require.Nil(t, err)
	require.Equal(t, http.StatusOK, res.status, "%s: %s", target, res.body)
	if out != nil {
		require.Nil(t, json.Unmarshal(res.body, out))
	}
	return res
}

func (c *awsClient) query(t *testing.T, action string, params url.Values, out any) *awsResponse {
	t.Helper()
	if params == nil {
		params = url.Values{}
	}
	params.Set("Action", action)
	params.Set("Version", "2010-05-08")
	if c.service == "sns" {
		params.Set("Version", "2010-03-31")
	}
	res := c.mustRequest(t, http.MethodPost, "/", []byte(params.Encode()),
		http.Header{"Content-Type": {"application/x-www-form-urlencoded"}}, http.StatusOK)
	if out != nil {
		require.Nil(t, xml.Unmarshal(res.body, out))
	}
	return res
}

type awsFixture struct {
	h         *harness.H
	namespace string
	upstream  string
	admin     *awsClient
}

func newAWSFixture(t *testing.T, h *harness.H) *awsFixture {
	t.Helper()
	namespace := "e2e-aws-" + h.Name()
	kc := h.K8sC()
	_, err := kc.CoreV1().Namespaces().Create(t.Context(), &k8scorev1.Namespace{
		ObjectMeta: k8smetav1.ObjectMeta{Name: namespace},
	}, k8smetav1.CreateOptions{})
	require.Nil(t, err)
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
		defer cancel()
		if t.Failed() {
			pods, err := kc.CoreV1().Pods(namespace).List(ctx, k8smetav1.ListOptions{})
			if err == nil {
				for _, pod := range pods.Items {
					t.Logf("AWS pod %s: phase=%s, containers=%+v, init=%+v", pod.Name,
						pod.Status.Phase, pod.Status.ContainerStatuses, pod.Status.InitContainerStatuses)
					for _, container := range pod.Spec.Containers {
						lines := int64(80)
						data, err := kc.CoreV1().Pods(namespace).GetLogs(pod.Name,
							&k8scorev1.PodLogOptions{Container: container.Name, TailLines: &lines}).DoRaw(ctx)
						if err == nil {
							t.Logf("AWS logs %s/%s: %s", pod.Name, container.Name, data)
						}
					}
				}
			}
		}
		require.Nil(t, kc.CoreV1().Namespaces().Delete(ctx, namespace, k8smetav1.DeleteOptions{}))
	})
	_, err = kc.CoreV1().ServiceAccounts(namespace).Create(t.Context(), &k8scorev1.ServiceAccount{
		ObjectMeta: k8smetav1.ObjectMeta{Name: "fakecloud"},
	}, k8smetav1.CreateOptions{})
	require.Nil(t, err)
	_, err = kc.RbacV1().Roles(namespace).Create(t.Context(), &rbacv1.Role{
		ObjectMeta: k8smetav1.ObjectMeta{Name: "fakecloud"},
		Rules: []rbacv1.PolicyRule{
			{APIGroups: []string{""}, Resources: []string{"pods"}, Verbs: []string{"create", "get", "list", "watch", "delete"}},
			{APIGroups: []string{""}, Resources: []string{"secrets"}, Verbs: []string{"create", "patch", "delete"}},
		},
	}, k8smetav1.CreateOptions{})
	require.Nil(t, err)
	_, err = kc.RbacV1().RoleBindings(namespace).Create(t.Context(), &rbacv1.RoleBinding{
		ObjectMeta: k8smetav1.ObjectMeta{Name: "fakecloud"},
		Subjects:   []rbacv1.Subject{{Kind: "ServiceAccount", Name: "fakecloud", Namespace: namespace}},
		RoleRef:    rbacv1.RoleRef{APIGroup: rbacv1.GroupName, Kind: "Role", Name: "fakecloud"},
	}, k8smetav1.CreateOptions{})
	require.Nil(t, err)
	upstream := fmt.Sprintf("http://fakecloud.%s.svc:4566", namespace)
	labels := map[string]string{"app": "fakecloud"}
	replicas := int32(1)
	_, err = kc.AppsV1().Deployments(namespace).Create(t.Context(), &appsv1.Deployment{
		ObjectMeta: k8smetav1.ObjectMeta{Name: "fakecloud"},
		Spec: appsv1.DeploymentSpec{
			Replicas: &replicas,
			Selector: &k8smetav1.LabelSelector{MatchLabels: labels},
			Template: k8scorev1.PodTemplateSpec{
				ObjectMeta: k8smetav1.ObjectMeta{Labels: labels},
				Spec: k8scorev1.PodSpec{
					ServiceAccountName: "fakecloud",
					Containers: []k8scorev1.Container{{
						Name: "fakecloud", Image: awsEmulatorImage,
						Args:  []string{"--verify-sigv4", "--iam", "strict"},
						Ports: []k8scorev1.ContainerPort{{ContainerPort: 4566}},
						Env: []k8scorev1.EnvVar{
							{Name: "FAKECLOUD_REGION", Value: awsRegion},
							{Name: "FAKECLOUD_LAMBDA_BACKEND", Value: "k8s"},
							{Name: "FAKECLOUD_K8S_SELF_URL", Value: upstream},
							{Name: "FAKECLOUD_K8S_NAMESPACE", Value: namespace},
						},
						ReadinessProbe: &k8scorev1.Probe{
							ProbeHandler:  k8scorev1.ProbeHandler{TCPSocket: &k8scorev1.TCPSocketAction{Port: intstr.FromInt32(4566)}},
							PeriodSeconds: 1,
						},
					}},
				},
			},
		},
	}, k8smetav1.CreateOptions{})
	require.Nil(t, err)
	_, err = kc.CoreV1().Services(namespace).Create(t.Context(), &k8scorev1.Service{
		ObjectMeta: k8smetav1.ObjectMeta{Name: "fakecloud"},
		Spec: k8scorev1.ServiceSpec{Selector: labels,
			Ports: []k8scorev1.ServicePort{{Name: "http", Port: 4566, TargetPort: intstr.FromInt32(4566)}},
		},
	}, k8smetav1.CreateOptions{})
	require.Nil(t, err)
	h.Eventually(t, "the AWS emulator to become ready", harness.DeploymentBudget,
		func(ctx context.Context) error {
			return k8sutils.WaitReadinessDeploymentWithNS(ctx, kc, "fakecloud", namespace)
		})
	port := h.Port()
	h.StartBackground(t, fmt.Sprintf("exec kubectl -n %s port-forward --address 127.0.0.1 svc/fakecloud %d:4566", namespace, port))
	client := h.HTTPNoRetry().GetClient()
	t.Cleanup(client.CloseIdleConnections)
	admin := &awsClient{endpoint: fmt.Sprintf("http://127.0.0.1:%d", port), service: "iam",
		client: client, credentials: &aws.Credentials{AccessKeyID: "test", SecretAccessKey: "test"}}
	admin.waitRequest(t, h, http.MethodGet, "/?Action=ListUsers&Version=2010-05-08", http.StatusOK)
	return &awsFixture{h: h, namespace: namespace, upstream: upstream, admin: admin}
}

func (a *awsFixture) identity(t *testing.T, policy string) aws.Credentials {
	t.Helper()
	name := a.h.Name()
	a.admin.query(t, "CreateUser", url.Values{"UserName": {name}}, nil)
	a.admin.query(t, "PutUserPolicy", url.Values{
		"UserName": {name}, "PolicyName": {"access"}, "PolicyDocument": {policy},
	}, nil)
	var result struct {
		Key struct {
			ID     string `xml:"AccessKeyId"`
			Secret string `xml:"SecretAccessKey"`
		} `xml:"CreateAccessKeyResult>AccessKey"`
	}
	a.admin.query(t, "CreateAccessKey", url.Values{"UserName": {name}}, &result)
	require.NotEmpty(t, result.Key.ID)
	require.NotEmpty(t, result.Key.Secret)
	require.False(t, strings.HasPrefix(result.Key.ID, "test"))
	return aws.Credentials{AccessKeyID: result.Key.ID, SecretAccessKey: result.Key.Secret}
}

func awsHTTPConfig(service string, key aws.Credentials, secret string) *corev1.Service_Spec_Config_HTTP {
	return &corev1.Service_Spec_Config_HTTP{
		EnableRequestBuffering: true,
		Body:                   &corev1.Service_Spec_Config_HTTP_Body{MaxRequestSize: 16 << 20},
		Auth: &corev1.Service_Spec_Config_HTTP_Auth{
			Type: &corev1.Service_Spec_Config_HTTP_Auth_Sigv4_{
				Sigv4: &corev1.Service_Spec_Config_HTTP_Auth_Sigv4{
					AccessKeyID: key.AccessKeyID, Region: awsRegion, Service: service,
					SecretAccessKey: &corev1.Service_Spec_Config_HTTP_Auth_Sigv4_SecretAccessKey{
						Type: &corev1.Service_Spec_Config_HTTP_Auth_Sigv4_SecretAccessKey_FromSecret{FromSecret: secret},
					},
				},
			},
		},
	}
}

func (a *awsFixture) service(t *testing.T, service string, key aws.Credentials, anonymous bool) (*corev1.Service, *awsClient) {
	t.Helper()
	secret := a.h.CreateSecret(t, "", key.SecretAccessKey)
	svc := a.h.CreateService(t, &corev1.Service{
		Spec: &corev1.Service_Spec{
			Mode: corev1.Service_Spec_HTTP, IsPublic: true, IsAnonymous: anonymous,
			Config: &corev1.Service_Spec_Config{
				Upstream: &corev1.Service_Spec_Config_Upstream{Type: &corev1.Service_Spec_Config_Upstream_Url{Url: a.upstream}},
				Type:     &corev1.Service_Spec_Config_Http{Http: awsHTTPConfig(service, key, secret.Metadata.Name)},
			},
		},
	})
	a.h.MustWaitService(t, svc.Metadata.Name)
	client := a.h.HTTPNoRetry().GetClient()
	t.Cleanup(client.CloseIdleConnections)
	return svc, &awsClient{endpoint: a.h.ServiceURL(svc), service: service, client: client}
}

func (c *awsClient) waitJSON(t *testing.T, h *harness.H, target string, body any) {
	t.Helper()
	h.Eventually(t, target+" to succeed through the public Service", harness.DecisionBudget,
		func(ctx context.Context) error {
			res, err := c.jsonRequest(ctx, target, body)
			if err != nil {
				return err
			}
			if res.status != http.StatusOK {
				return errors.Errorf("%s: status %d: %s", target, res.status, res.body)
			}
			return nil
		})
}

func testVigilAWS(t *testing.T, h *harness.H) {
	a := newAWSFixture(t, h)
	key := a.identity(t, `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}`)
	for _, tt := range []struct {
		name string
		run  func(*testing.T, *awsFixture, aws.Credentials)
	}{
		{"SignatureVerification", testAWSSignatureVerification},
		{"S3", testAWSS3},
		{"KMS", testAWSKMS},
		{"DynamoDB", testAWSDynamoDB},
		{"Messaging", testAWSMessaging},
		{"SecretsManager", testAWSSecretsManager},
		{"Lambda", testAWSLambda},
		{"Access", testAWSAccess},
		{"DynamicCredentials", testAWSDynamicCredentials},
	} {
		t.Run(tt.name, func(t *testing.T) { tt.run(t, a, key) })
	}
}
