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
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/cluster/e2e/harness"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func (a *awsFixture) direct(service string, key aws.Credentials) *awsClient {
	return &awsClient{endpoint: a.admin.endpoint, client: a.admin.client, service: service, credentials: &key}
}

func (c *awsClient) waitRequest(t *testing.T, h *harness.H, method, path string, want int) {
	t.Helper()
	h.Eventually(t, fmt.Sprintf("%s %s to return %d", method, path, want),
		harness.DecisionBudget, func(ctx context.Context) error {
			res, err := c.request(ctx, method, path, nil, nil)
			if err != nil {
				return err
			}
			if res.status != want {
				return errors.Errorf("got status %d, want %d: %s", res.status, want, res.body)
			}
			return nil
		})
}

func testAWSS3(t *testing.T, a *awsFixture, key aws.Credentials) {
	svc, c := a.service(t, "s3", key, true)
	c.waitRequest(t, a.h, http.MethodGet, "/", http.StatusOK)
	bucket := "objects-" + a.h.Name()
	base := "/" + bucket
	objectPath := func(name string) string {
		return base + "/" + strings.ReplaceAll(strings.ReplaceAll(url.QueryEscape(name), "+", "%20"), "%2F", "/")
	}
	c.mustRequest(t, http.MethodPut, base, nil, nil, http.StatusOK)

	t.Run("ObjectsAndPagination", func(t *testing.T) {
		keys := []string{"reports/2026 Q4/a+b%.bin", "reports/2026 Q4/café.json", "reports/2026 Q4/last.bin"}
		payload := make([]byte, 512*1024+31)
		_, err := rand.Read(payload)
		require.Nil(t, err)
		for _, name := range keys {
			path := objectPath(name)
			put := c.mustRequest(t, http.MethodPut, path, payload,
				http.Header{"Content-Type": {"application/octet-stream"}, "X-Amz-Meta-Report": {"quarterly"}}, http.StatusOK)
			require.NotEmpty(t, put.header.Get("ETag"))
			head := c.mustRequest(t, http.MethodHead, path, nil, nil, http.StatusOK)
			assert.Equal(t, fmt.Sprint(len(payload)), head.header.Get("Content-Length"))
			assert.Equal(t, "quarterly", head.header.Get("X-Amz-Meta-Report"))
			get := c.mustRequest(t, http.MethodGet, path, nil, nil, http.StatusOK)
			assert.Equal(t, sha256.Sum256(payload), sha256.Sum256(get.body))
			part := c.mustRequest(t, http.MethodGet, path, nil,
				http.Header{"Range": {"bytes=17-1040"}}, http.StatusPartialContent)
			assert.Equal(t, payload[17:1041], part.body)
			assert.Equal(t, fmt.Sprintf("bytes 17-1040/%d", len(payload)), part.header.Get("Content-Range"))
		}
		var found []string
		token := ""
		for range 4 {
			query := url.Values{"list-type": {"2"}, "prefix": {"reports/2026 Q4/"}, "max-keys": {"1"}}
			if token != "" {
				query.Set("continuation-token", token)
			}
			res := c.mustRequest(t, http.MethodGet, base+"?"+query.Encode(), nil, nil, http.StatusOK)
			var page struct {
				Contents  []struct{ Key string } `xml:"Contents"`
				Truncated bool                   `xml:"IsTruncated"`
				Next      string                 `xml:"NextContinuationToken"`
			}
			require.Nil(t, xml.Unmarshal(res.body, &page))
			for _, item := range page.Contents {
				found = append(found, item.Key)
			}
			if !page.Truncated {
				break
			}
			require.NotEmpty(t, page.Next)
			require.NotEqual(t, token, page.Next)
			token = page.Next
		}
		assert.ElementsMatch(t, keys, found)
		for _, name := range keys {
			path := objectPath(name)
			c.mustRequest(t, http.MethodDelete, path, nil, nil, http.StatusNoContent)
			res := c.mustRequest(t, http.MethodGet, path, nil, nil, http.StatusNotFound)
			assert.Contains(t, string(res.body), "NoSuchKey")
		}
	})

	t.Run("MultipartUpload", func(t *testing.T) {
		path := base + "/multipart.bin"
		res := c.mustRequest(t, http.MethodPost, path+"?uploads=", nil, nil, http.StatusOK)
		var upload struct {
			ID string `xml:"UploadId"`
		}
		require.Nil(t, xml.Unmarshal(res.body, &upload))
		require.NotEmpty(t, upload.ID)
		payloads := [][]byte{bytes.Repeat([]byte{0, 1, 127, 255}, (5*1024*1024)/4), bytes.Repeat([]byte("tail"), 8193)}
		type part struct {
			Number int    `xml:"PartNumber"`
			ETag   string `xml:"ETag"`
		}
		complete := struct {
			XMLName xml.Name `xml:"CompleteMultipartUpload"`
			Parts   []part   `xml:"Part"`
		}{}
		for idx, payload := range payloads {
			query := url.Values{"partNumber": {fmt.Sprint(idx + 1)}, "uploadId": {upload.ID}}
			res := c.mustRequest(t, http.MethodPut, path+"?"+query.Encode(), payload, nil, http.StatusOK)
			require.NotEmpty(t, res.header.Get("ETag"))
			complete.Parts = append(complete.Parts, part{Number: idx + 1, ETag: res.header.Get("ETag")})
		}
		body, err := xml.Marshal(complete)
		require.Nil(t, err)
		c.mustRequest(t, http.MethodPost, path+"?"+url.Values{"uploadId": {upload.ID}}.Encode(), body,
			http.Header{"Content-Type": {"application/xml"}}, http.StatusOK)
		get := c.mustRequest(t, http.MethodGet, path, nil, nil, http.StatusOK)
		assert.Equal(t, sha256.Sum256(bytes.Join(payloads, nil)), sha256.Sum256(get.body))
		c.mustRequest(t, http.MethodDelete, path, nil, nil, http.StatusNoContent)
	})

	t.Run("HostAndPathRewrite", func(t *testing.T) {
		path := "/rewritten%20a%2Bb%25.txt"
		c.mustRequest(t, http.MethodPut, base+path, []byte("rewritten-object"), nil, http.StatusOK)
		svc.Spec.Config.GetHttp().Path = &corev1.Service_Spec_Config_HTTP_Path{RemovePrefix: "/files", AddPrefix: base}
		svc.Spec.Config.GetHttp().Header = &corev1.Service_Spec_Config_HTTP_Header{
			Host: &corev1.Service_Spec_Config_HTTP_Header_Host{
				Type: &corev1.Service_Spec_Config_HTTP_Header_Host_Value{Value: "s3.us-east-1.amazonaws.com"},
			},
		}
		svc = a.h.UpdateService(t, svc)
		c.waitRequest(t, a.h, http.MethodGet, "/files"+path, http.StatusOK)
		res := c.mustRequest(t, http.MethodGet, "/files"+path, nil, nil, http.StatusOK)
		assert.Equal(t, "rewritten-object", string(res.body))
		svc.Spec.Config.GetHttp().Path = nil
		svc.Spec.Config.GetHttp().Header = nil
		svc = a.h.UpdateService(t, svc)
		c.waitRequest(t, a.h, http.MethodGet, base+path, http.StatusOK)
		c.mustRequest(t, http.MethodDelete, base+path, nil, nil, http.StatusNoContent)
	})
	c.mustRequest(t, http.MethodDelete, base, nil, nil, http.StatusNoContent)
}

func testAWSKMS(t *testing.T, a *awsFixture, key aws.Credentials) {
	_, c := a.service(t, "kms", key, true)
	c.waitJSON(t, a.h, "TrentService.ListKeys", map[string]any{})
	var created struct {
		Metadata struct {
			ID string `json:"KeyId"`
		} `json:"KeyMetadata"`
	}
	c.mustJSON(t, "TrentService.CreateKey", map[string]any{"KeyUsage": "ENCRYPT_DECRYPT", "KeySpec": "SYMMETRIC_DEFAULT"}, &created)
	require.NotEmpty(t, created.Metadata.ID)
	encryptionContext := map[string]string{"tenant": a.h.Name(), "purpose": "e2e-envelope"}
	var dataKey struct {
		Plaintext      string
		CiphertextBlob string
	}
	c.mustJSON(t, "TrentService.GenerateDataKey", map[string]any{
		"KeyId": created.Metadata.ID, "KeySpec": "AES_256", "EncryptionContext": encryptionContext,
	}, &dataKey)
	plainKey, err := base64.StdEncoding.DecodeString(dataKey.Plaintext)
	require.Nil(t, err)
	require.Len(t, plainKey, 32)
	block, err := aes.NewCipher(plainKey)
	require.Nil(t, err)
	gcm, err := cipher.NewGCM(block)
	require.Nil(t, err)
	nonce := make([]byte, gcm.NonceSize())
	_, err = rand.Read(nonce)
	require.Nil(t, err)
	plaintext := bytes.Repeat([]byte("confidential report\x00"), 4096)
	ciphertext := gcm.Seal(nil, nonce, plaintext, nil)

	_, storage := a.service(t, "s3", key, true)
	storage.waitRequest(t, a.h, http.MethodGet, "/", http.StatusOK)
	bucket := "/envelopes-" + a.h.Name()
	storage.mustRequest(t, http.MethodPut, bucket, nil, nil, http.StatusOK)
	envelope, err := json.Marshal(map[string]any{"key": dataKey.CiphertextBlob, "nonce": nonce, "ciphertext": ciphertext})
	require.Nil(t, err)
	storage.mustRequest(t, http.MethodPut, bucket+"/report.json", envelope, nil, http.StatusOK)
	get := storage.mustRequest(t, http.MethodGet, bucket+"/report.json", nil, nil, http.StatusOK)
	var stored struct {
		Key        string
		Nonce      []byte
		Ciphertext []byte
	}
	require.Nil(t, json.Unmarshal(get.body, &stored))
	res, err := c.jsonRequest(t.Context(), "TrentService.Decrypt", map[string]any{
		"CiphertextBlob": stored.Key, "EncryptionContext": map[string]string{"tenant": "wrong"},
	})
	require.Nil(t, err)
	require.Equal(t, http.StatusBadRequest, res.status, "%s", res.body)
	assert.Contains(t, string(res.body), "InvalidCiphertextException")
	var decrypted struct{ Plaintext string }
	c.mustJSON(t, "TrentService.Decrypt", map[string]any{
		"CiphertextBlob": stored.Key, "EncryptionContext": encryptionContext,
	}, &decrypted)
	recoveredKey, err := base64.StdEncoding.DecodeString(decrypted.Plaintext)
	require.Nil(t, err)
	assert.Equal(t, plainKey, recoveredKey)
	block, err = aes.NewCipher(recoveredKey)
	require.Nil(t, err)
	gcm, err = cipher.NewGCM(block)
	require.Nil(t, err)
	recovered, err := gcm.Open(nil, stored.Nonce, stored.Ciphertext, nil)
	require.Nil(t, err)
	assert.Equal(t, plaintext, recovered)
	storage.mustRequest(t, http.MethodDelete, bucket+"/report.json", nil, nil, http.StatusNoContent)
	storage.mustRequest(t, http.MethodDelete, bucket, nil, nil, http.StatusNoContent)
}

func testAWSDynamoDB(t *testing.T, a *awsFixture, key aws.Credentials) {
	_, c := a.service(t, "dynamodb", key, true)
	c.waitJSON(t, a.h, "DynamoDB_20120810.ListTables", map[string]any{})
	table := "orders-" + a.h.Name()
	c.mustJSON(t, "DynamoDB_20120810.CreateTable", map[string]any{
		"TableName": table, "BillingMode": "PAY_PER_REQUEST",
		"AttributeDefinitions": []any{map[string]any{"AttributeName": "tenant", "AttributeType": "S"}, map[string]any{"AttributeName": "order", "AttributeType": "S"}},
		"KeySchema":            []any{map[string]any{"AttributeName": "tenant", "KeyType": "HASH"}, map[string]any{"AttributeName": "order", "KeyType": "RANGE"}},
	}, nil)
	a.h.Eventually(t, "the DynamoDB table to become active", harness.DecisionBudget, func(ctx context.Context) error {
		res, err := c.jsonRequest(ctx, "DynamoDB_20120810.DescribeTable", map[string]any{"TableName": table})
		if err != nil {
			return err
		}
		var got struct {
			Table struct {
				Status string `json:"TableStatus"`
			}
		}
		if err := json.Unmarshal(res.body, &got); err != nil {
			return err
		}
		if got.Table.Status != "ACTIVE" {
			return errors.Errorf("table status is %s: %s", got.Table.Status, res.body)
		}
		return nil
	})
	tenant := a.h.Name()
	stringAttr := func(s string) map[string]string { return map[string]string{"S": s} }
	itemKey := map[string]any{"tenant": stringAttr(tenant), "order": stringAttr("001")}
	item := map[string]any{"tenant": stringAttr(tenant), "order": stringAttr("001"), "version": map[string]string{"N": "1"}, "status": stringAttr("pending")}
	c.mustJSON(t, "DynamoDB_20120810.PutItem", map[string]any{
		"TableName": table, "Item": item, "ConditionExpression": "attribute_not_exists(tenant)",
	}, nil)
	update := map[string]any{
		"TableName": table, "Key": itemKey, "UpdateExpression": "SET #state = :state, version = :next",
		"ConditionExpression": "version = :expected", "ExpressionAttributeNames": map[string]string{"#state": "status"},
		"ExpressionAttributeValues": map[string]any{":state": stringAttr("paid"), ":next": map[string]string{"N": "2"}, ":expected": map[string]string{"N": "1"}},
		"ReturnValues":              "ALL_NEW",
	}
	var updated struct{ Attributes map[string]map[string]string }
	c.mustJSON(t, "DynamoDB_20120810.UpdateItem", update, &updated)
	assert.Equal(t, "paid", updated.Attributes["status"]["S"])
	res, err := c.jsonRequest(t.Context(), "DynamoDB_20120810.UpdateItem", update)
	require.Nil(t, err)
	require.Equal(t, http.StatusBadRequest, res.status, "%s", res.body)
	assert.Contains(t, string(res.body), "ConditionalCheckFailedException")
	var current struct{ Item map[string]map[string]string }
	c.mustJSON(t, "DynamoDB_20120810.GetItem", map[string]any{"TableName": table, "Key": itemKey, "ConsistentRead": true}, &current)
	assert.Equal(t, "2", current.Item["version"]["N"])
	assert.Equal(t, "paid", current.Item["status"]["S"])
	for _, order := range []string{"002", "003"} {
		c.mustJSON(t, "DynamoDB_20120810.PutItem", map[string]any{
			"TableName": table, "Item": map[string]any{"tenant": stringAttr(tenant), "order": stringAttr(order)},
		}, nil)
	}
	query := map[string]any{"TableName": table, "KeyConditionExpression": "tenant = :tenant",
		"ExpressionAttributeValues": map[string]any{":tenant": stringAttr(tenant)}, "ConsistentRead": true, "Limit": 1}
	var orders []string
	for range 4 {
		var page struct {
			Items            []map[string]map[string]string
			LastEvaluatedKey map[string]map[string]string
		}
		c.mustJSON(t, "DynamoDB_20120810.Query", query, &page)
		for _, row := range page.Items {
			orders = append(orders, row["order"]["S"])
		}
		if len(page.LastEvaluatedKey) == 0 {
			break
		}
		query["ExclusiveStartKey"] = page.LastEvaluatedKey
	}
	assert.Equal(t, []string{"001", "002", "003"}, orders)
	c.mustJSON(t, "DynamoDB_20120810.DeleteTable", map[string]any{"TableName": table}, nil)
}
