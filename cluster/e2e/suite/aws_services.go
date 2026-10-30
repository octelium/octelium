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
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/octelium/octelium/cluster/e2e/harness"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	k8smetav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func testAWSMessaging(t *testing.T, a *awsFixture, key aws.Credentials) {
	_, queue := a.service(t, "sqs", key, true)
	queue.waitJSON(t, a.h, "AmazonSQS.ListQueues", map[string]any{})
	_, topic := a.service(t, "sns", key, true)
	topic.waitRequest(t, a.h, http.MethodGet, "/?Action=ListTopics&Version=2010-03-31", http.StatusOK)
	var createdQueue struct{ QueueUrl string }
	queue.mustJSON(t, "AmazonSQS.CreateQueue", map[string]any{"QueueName": "events-" + a.h.Name()}, &createdQueue)
	require.NotEmpty(t, createdQueue.QueueUrl)
	var attributes struct{ Attributes map[string]string }
	queue.mustJSON(t, "AmazonSQS.GetQueueAttributes", map[string]any{
		"QueueUrl": createdQueue.QueueUrl, "AttributeNames": []string{"QueueArn"},
	}, &attributes)
	queueARN := attributes.Attributes["QueueArn"]
	require.NotEmpty(t, queueARN)
	var createdTopic struct {
		ARN string `xml:"CreateTopicResult>TopicArn"`
	}
	topic.query(t, "CreateTopic", url.Values{"Name": {"events-" + a.h.Name()}}, &createdTopic)
	require.NotEmpty(t, createdTopic.ARN)
	policy, err := json.Marshal(map[string]any{
		"Version": "2012-10-17", "Statement": []any{map[string]any{
			"Effect": "Allow", "Principal": map[string]string{"Service": "sns.amazonaws.com"},
			"Action": "sqs:SendMessage", "Resource": queueARN,
			"Condition": map[string]any{"ArnEquals": map[string]string{"aws:SourceArn": createdTopic.ARN}},
		}},
	})
	require.Nil(t, err)
	queue.mustJSON(t, "AmazonSQS.SetQueueAttributes", map[string]any{
		"QueueUrl": createdQueue.QueueUrl, "Attributes": map[string]string{"Policy": string(policy)},
	}, nil)
	var subscribed struct {
		ARN string `xml:"SubscribeResult>SubscriptionArn"`
	}
	topic.query(t, "Subscribe", url.Values{
		"TopicArn": {createdTopic.ARN}, "Protocol": {"sqs"}, "Endpoint": {queueARN},
		"Attributes.entry.1.key": {"RawMessageDelivery"}, "Attributes.entry.1.value": {"true"},
	}, &subscribed)
	require.NotEmpty(t, subscribed.ARN)
	message := fmt.Sprintf(`{"id":%q,"event":"order paid","note":"a+b & café"}`, a.h.Name())
	topic.query(t, "Publish", url.Values{"TopicArn": {createdTopic.ARN}, "Message": {message}}, nil)
	var receipt string
	a.h.Eventually(t, "the SNS publication to arrive in SQS", harness.DecisionBudget, func(ctx context.Context) error {
		res, err := queue.jsonRequest(ctx, "AmazonSQS.ReceiveMessage", map[string]any{
			"QueueUrl": createdQueue.QueueUrl, "MaxNumberOfMessages": 1, "WaitTimeSeconds": 1,
		})
		if err != nil {
			return err
		}
		if res.status != http.StatusOK {
			return errors.Errorf("ReceiveMessage: status %d: %s", res.status, res.body)
		}
		var received struct {
			Messages []struct {
				Body          string
				ReceiptHandle string
			}
		}
		if err := json.Unmarshal(res.body, &received); err != nil {
			return err
		}
		if len(received.Messages) != 1 {
			return errors.New("no message has arrived")
		}
		if received.Messages[0].Body != message {
			return errors.Errorf("unexpected message body: %s", received.Messages[0].Body)
		}
		receipt = received.Messages[0].ReceiptHandle
		return nil
	})
	require.NotEmpty(t, receipt)
	queue.mustJSON(t, "AmazonSQS.DeleteMessage", map[string]any{"QueueUrl": createdQueue.QueueUrl, "ReceiptHandle": receipt}, nil)
	var empty struct{ Messages []json.RawMessage }
	queue.mustJSON(t, "AmazonSQS.ReceiveMessage", map[string]any{"QueueUrl": createdQueue.QueueUrl, "WaitTimeSeconds": 1}, &empty)
	assert.Empty(t, empty.Messages)
	topic.query(t, "Unsubscribe", url.Values{"SubscriptionArn": {subscribed.ARN}}, nil)
	topic.query(t, "DeleteTopic", url.Values{"TopicArn": {createdTopic.ARN}}, nil)
	queue.mustJSON(t, "AmazonSQS.DeleteQueue", map[string]any{"QueueUrl": createdQueue.QueueUrl}, nil)
}

func testAWSSecretsManager(t *testing.T, a *awsFixture, key aws.Credentials) {
	_, c := a.service(t, "secretsmanager", key, true)
	c.waitJSON(t, a.h, "secretsmanager.ListSecrets", map[string]any{})
	name := "applications/" + a.h.Name()
	initial := fmt.Sprintf(`{"username":"app","password":%q}`, a.h.Name())
	var created struct {
		ARN       string
		VersionId string
	}
	c.mustJSON(t, "secretsmanager.CreateSecret", map[string]any{"Name": name, "SecretString": initial}, &created)
	require.NotEmpty(t, created.ARN)
	require.NotEmpty(t, created.VersionId)
	rotated := fmt.Sprintf(`{"username":"app","password":%q}`, a.h.Name())
	var version struct{ VersionId string }
	c.mustJSON(t, "secretsmanager.PutSecretValue", map[string]any{
		"SecretId": created.ARN, "SecretString": rotated,
	}, &version)
	require.NotEmpty(t, version.VersionId)
	require.NotEqual(t, created.VersionId, version.VersionId)
	for _, tt := range []struct{ stage, value, version string }{
		{"AWSCURRENT", rotated, version.VersionId}, {"AWSPREVIOUS", initial, created.VersionId},
	} {
		var got struct {
			SecretString  string
			VersionId     string
			VersionStages []string
		}
		c.mustJSON(t, "secretsmanager.GetSecretValue", map[string]any{"SecretId": created.ARN, "VersionStage": tt.stage}, &got)
		assert.Equal(t, tt.value, got.SecretString)
		assert.Equal(t, tt.version, got.VersionId)
		assert.Contains(t, got.VersionStages, tt.stage)
	}
	c.mustJSON(t, "secretsmanager.DeleteSecret", map[string]any{"SecretId": created.ARN, "ForceDeleteWithoutRecovery": true}, nil)
	res, err := c.jsonRequest(t.Context(), "secretsmanager.GetSecretValue", map[string]any{"SecretId": created.ARN})
	require.Nil(t, err)
	require.Equal(t, http.StatusBadRequest, res.status, "%s", res.body)
	assert.Contains(t, string(res.body), "ResourceNotFoundException")
}

func awsLambdaArchive(t *testing.T) string {
	t.Helper()
	var buf bytes.Buffer
	w := zip.NewWriter(&buf)
	f, err := w.Create("handler.py")
	require.Nil(t, err)
	_, err = f.Write([]byte(`import base64
import hashlib
import os

def handle(event, context):
    if event.get("fail"):
        raise ValueError("e2e-function-error")
    payload = base64.b64decode(event["payload"])
    return {
        "sha256": hashlib.sha256(payload).hexdigest(),
        "size": len(payload),
        "revision": os.environ["REVISION"],
        "requestID": context.aws_request_id,
    }
`))
	require.Nil(t, err)
	require.Nil(t, w.Close())
	return base64.StdEncoding.EncodeToString(buf.Bytes())
}

func testAWSLambda(t *testing.T, a *awsFixture, key aws.Credentials) {
	_, c := a.service(t, "lambda", key, true)
	c.client.Timeout = 3 * time.Minute
	c.waitRequest(t, a.h, http.MethodGet, "/2015-03-31/functions/", http.StatusOK)
	var role struct {
		ARN string `xml:"CreateRoleResult>Role>Arn"`
	}
	a.admin.query(t, "CreateRole", url.Values{
		"RoleName": {a.h.Name()}, "AssumeRolePolicyDocument": {`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"lambda.amazonaws.com"},"Action":"sts:AssumeRole"}]}`},
	}, &role)
	require.NotEmpty(t, role.ARN)
	name := "handler-" + a.h.Name()
	config := map[string]any{
		"FunctionName": name, "Runtime": "python3.12", "Handler": "handler.handle",
		"Role": role.ARN, "MemorySize": 256, "Timeout": 30,
		"Code":        map[string]string{"ZipFile": awsLambdaArchive(t)},
		"Environment": map[string]any{"Variables": map[string]string{"REVISION": "one"}},
	}
	body, err := json.Marshal(config)
	require.Nil(t, err)
	c.mustRequest(t, http.MethodPost, "/2015-03-31/functions", body,
		http.Header{"Content-Type": {"application/json"}}, http.StatusCreated)
	path := "/2015-03-31/functions/" + name
	payload := bytes.Repeat([]byte("lambda payload\x00a+b"), 8192)
	invokeBody, err := json.Marshal(map[string]string{"payload": base64.StdEncoding.EncodeToString(payload)})
	require.Nil(t, err)
	var firstID string
	a.h.Eventually(t, "Lambda to execute the uploaded code in a Kubernetes pod", harness.DeploymentBudget,
		func(ctx context.Context) error {
			res, err := c.request(ctx, http.MethodPost, path+"/invocations?Qualifier=%24LATEST", invokeBody,
				http.Header{"Content-Type": {"application/json"}, "X-Amz-Invocation-Type": {"RequestResponse"}})
			if err != nil {
				return err
			}
			if res.status != http.StatusOK || res.header.Get("X-Amz-Function-Error") != "" {
				return errors.Errorf("Lambda invocation failed: status %d: %s", res.status, res.body)
			}
			var got struct {
				SHA256    string
				Size      int
				Revision  string
				RequestID string
			}
			if err := json.Unmarshal(res.body, &got); err != nil {
				return err
			}
			if got.SHA256 != fmt.Sprintf("%x", sha256.Sum256(payload)) || got.Size != len(payload) || got.Revision != "one" || got.RequestID == "" {
				return errors.Errorf("Lambda returned an unexpected result: %s", res.body)
			}
			firstID = got.RequestID
			return nil
		})
	workers, err := a.h.K8sC().CoreV1().Pods(a.namespace).List(t.Context(), k8smetav1.ListOptions{
		LabelSelector: "fakecloud-lambda=" + name,
	})
	require.Nil(t, err)
	require.NotEmpty(t, workers.Items, "Lambda must execute in Kubernetes")
	workerIDs := map[string]bool{}
	for _, pod := range workers.Items {
		workerIDs[string(pod.UID)] = true
	}
	res := c.mustRequest(t, http.MethodPost, path+"/invocations", invokeBody,
		http.Header{"Content-Type": {"application/json"}}, http.StatusOK)
	assert.Empty(t, res.header.Get("X-Amz-Function-Error"))
	var warm struct {
		SHA256    string
		RequestID string
	}
	require.Nil(t, json.Unmarshal(res.body, &warm))
	assert.Equal(t, fmt.Sprintf("%x", sha256.Sum256(payload)), warm.SHA256)
	assert.NotEmpty(t, warm.RequestID)
	assert.NotEqual(t, firstID, warm.RequestID)
	res = c.mustRequest(t, http.MethodPost, path+"/invocations", []byte(`{"fail":true}`),
		http.Header{"Content-Type": {"application/json"}}, http.StatusOK)
	assert.Contains(t, []string{"Handled", "Unhandled"}, res.header.Get("X-Amz-Function-Error"))
	assert.Contains(t, string(res.body), "e2e-function-error")
	pods, err := a.h.K8sC().CoreV1().Pods(a.namespace).List(t.Context(), k8smetav1.ListOptions{
		LabelSelector: "fakecloud-lambda=" + name,
	})
	require.Nil(t, err)
	require.Len(t, pods.Items, len(workers.Items))
	for _, pod := range pods.Items {
		assert.True(t, workerIDs[string(pod.UID)], "warm invocations must reuse the Lambda worker")
	}
	c.mustRequest(t, http.MethodDelete, path, nil, nil, http.StatusNoContent)
}
