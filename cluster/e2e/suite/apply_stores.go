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
	"encoding/json"
	"fmt"
	"math"
	"os"
	"os/exec"
	"path"
	"testing"
	"time"

	"github.com/ClickHouse/clickhouse-go/v2"
	"github.com/elastic/go-elasticsearch/v9"
	"github.com/go-redis/redis/v8"
	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
	"github.com/nats-io/nats.go"
	"github.com/octelium/octelium/pkg/utils"
	"github.com/octelium/octelium/pkg/utils/utilrand"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
	"go.uber.org/zap"
)

func applyRedis(t *testing.T, a *applyCtx) {
	a.h.MustWaitServiceUpstream(t, "redis")

	redisC := redis.NewClient(&redis.Options{Addr: a.addr("redis")})
	t.Cleanup(func() { redisC.Close() })

	ctx := t.Context()

	key := utilrand.GetRandomStringCanonical(32)
	val := utilrand.GetRandomStringCanonical(32)

	require.Nil(t, redisC.Set(ctx, key, val, 3*time.Second).Err())
	time.Sleep(1 * time.Second)

	ret, err := redisC.Get(ctx, key).Result()
	require.Nil(t, err)
	assert.Equal(t, val, ret)

	time.Sleep(3 * time.Second)

	_, err = redisC.Get(ctx, key).Result()
	assert.NotNil(t, err)
	assert.Equal(t, redis.Nil, err)

	assert.Nil(t, redisC.Set(ctx,
		utilrand.GetRandomStringCanonical(32),
		utilrand.GetRandomStringCanonical(12*1024*1024), 3*time.Second).Err())
}

func applyNATS(t *testing.T, a *applyCtx) {
	a.h.MustWaitServiceUpstream(t, "nats")

	nc, err := nats.Connect(fmt.Sprintf("nats://%s", a.addr("nats")),
		nats.RetryOnFailedConnect(true),
		nats.ReconnectWait(3*time.Second))
	require.Nil(t, err)
	defer nc.Drain()

	subj := utilrand.GetRandomStringCanonical(32)

	var dataList [][]byte
	for range 12 {
		dataList = append(dataList, utilrand.GetRandomBytesMust(32))
	}

	curIdx := 0
	_, err = nc.Subscribe(subj, func(m *nats.Msg) {
		assert.True(t, utils.SecureBytesEqual(dataList[curIdx], m.Data))
		curIdx++
		zap.L().Debug("Cur nats idx", zap.Int("idx", curIdx))
	})
	require.Nil(t, err)

	for i := range dataList {
		assert.Nil(t, nc.Publish(subj, dataList[i]))
		time.Sleep(500 * time.Millisecond)
	}
}

func applyOpenSearch(t *testing.T, a *applyCtx) {
	a.h.MustWaitServiceUpstream(t, "opensearch")

	c, err := elasticsearch.NewClient(elasticsearch.Config{
		Addresses:  []string{a.url("opensearch")},
		Username:   "admin",
		Password:   "Password_123456",
		MaxRetries: 20,
	})
	require.Nil(t, err)

	resI, err := c.Info()
	require.Nil(t, err)
	defer resI.Body.Close()

	zap.L().Debug("OpenSearch info", zap.String("info", drainBody(t, resI.Body)))

	const idx = "octelium-index"
	_, err = c.Indices.Create(idx)
	assert.Nil(t, err)

	type myDoc struct {
		ID    int    `json:"id"`
		Name  string `json:"name"`
		Price int    `json:"price"`
	}

	for range 50 {
		doc := &myDoc{
			ID:    utilrand.GetRandomRangeMath(1, math.MaxInt32),
			Name:  utilrand.GetRandomString(10 * 1000),
			Price: utilrand.GetRandomRangeMath(1, 4000),
		}

		docJSON, err := json.Marshal(doc)
		require.Nil(t, err)

		_, err = c.Index(idx, bytes.NewReader(docJSON), c.Index.WithContext(t.Context()))
		assert.Nil(t, err)
	}

	a.h.MustRun(t, "octeliumctl del svc opensearch")
}

func applyClickHouse(t *testing.T, a *applyCtx) {
	h := a.h

	h.MustWaitServiceUpstream(t, "clickhouse")
	h.MustWaitService(t, "clickhouse")

	conn := clickhouse.OpenDB(&clickhouse.Options{
		Addr: []string{a.addr("clickhouse")},
		Auth: clickhouse.Auth{
			Username: "octelium",
			Password: "password",
		},
	})
	t.Cleanup(func() { conn.Close() })

	require.Nil(t, conn.Ping())

	conn.Exec(`DROP TABLE IF EXISTS example`)

	_, err := conn.Exec(`CREATE TABLE IF NOT EXISTS example (Col1 UInt8, Col2 String) engine=Memory`)
	require.Nil(t, err)

	arg := utilrand.GetRandomString(32)
	_, err = conn.Exec(fmt.Sprintf("INSERT INTO example VALUES (1, '%s')", arg))
	require.Nil(t, err)

	time.Sleep(3 * time.Second)

	var col1 uint8
	var col2 string
	require.Nil(t, conn.QueryRow("SELECT * FROM example").Scan(&col1, &col2))
	assert.Equal(t, 1, int(col1))
	assert.Equal(t, arg, col2)

	h.MustRun(t, "octeliumctl del svc clickhouse")
	h.MustFail(t, "octeliumctl del svc clickhouse")
}

func applyS3(t *testing.T, a *applyCtx) {
	h := a.h
	ctx := t.Context()

	tmpDir, err := os.MkdirTemp("", "octelium-e2e-s3-*")
	require.Nil(t, err)
	t.Cleanup(func() { os.RemoveAll(tmpDir) })

	h.MustWaitServiceUpstream(t, "s3")
	h.MustWaitService(t, "s3")
	h.StartLogStream(ctx, "-l octelium.com/component=svc-k8s-upstream,octelium.com/svc=s3.default")

	c, err := minio.New(a.addr("s3"), &minio.Options{
		Creds:  credentials.NewStaticV4("wrong", "identity", ""),
		Secure: false,
		Region: "us-east-1",
	})
	require.Nil(t, err)

	bucketName := utilrand.GetRandomStringCanonical(6)

	require.Nil(t, c.MakeBucket(ctx, bucketName, minio.MakeBucketOptions{Region: "us-east-1"}))
	zap.L().Debug("Successfully created bucket", zap.String("bucket", bucketName))

	roundTrip := func(pth string) {
		name := utilrand.GetRandomStringCanonical(8)
		downloadPath := path.Join(tmpDir, name)

		info, err := c.FPutObject(ctx, bucketName, name, pth, minio.PutObjectOptions{
			ContentType: "application/octet-stream",
		})
		assert.Nil(t, err)
		zap.L().Debug("fputObject", zap.String("path", pth), zap.Any("info", info))

		stat, err := c.StatObject(ctx, bucketName, name, minio.StatObjectOptions{})
		assert.Nil(t, err)
		zap.L().Debug("object stat", zap.String("path", pth), zap.Any("info", stat))

		err = c.FGetObject(ctx, bucketName, name, downloadPath, minio.GetObjectOptions{})
		assert.Nil(t, err)
		zap.L().Debug("fgetObject done", zap.String("path", pth))
	}

	files := []string{h.State.KubeconfigPath}
	for _, bin := range []string{"octelium", "octops"} {
		if pth, err := exec.LookPath(bin); err == nil {
			files = append(files, pth)
		}
	}

	for _, f := range files {
		roundTrip(f)
	}

	h.MustRun(t, "octeliumctl del svc s3")
	h.MustFail(t, "octeliumctl del svc s3")
}

func applyMongo(t *testing.T, a *applyCtx) {
	h := a.h
	ctx := t.Context()

	h.MustWaitServiceUpstream(t, "mongo")
	h.MustWaitService(t, "mongo")

	type mongoUser struct {
		Name      string    `bson:"name"`
		Email     string    `bson:"email"`
		Age       int       `bson:"age"`
		CreatedAt time.Time `bson:"created_at"`
	}

	uri := fmt.Sprintf("mongodb://octelium:password@%s", a.addr("mongo"))

	client, err := mongo.Connect(options.Client().ApplyURI(uri))
	require.Nil(t, err)

	require.Nil(t, client.Ping(ctx, nil))

	collection := client.Database("testdb").Collection("users")

	usr := &mongoUser{
		Name:      utilrand.GetRandomStringCanonical(8),
		Email:     fmt.Sprintf("%s@example.com", utilrand.GetRandomStringCanonical(8)),
		CreatedAt: time.Now(),
		Age:       21,
	}

	_, err = collection.InsertOne(ctx, usr)
	require.Nil(t, err)

	var foundUser mongoUser
	require.Nil(t, collection.FindOne(ctx, bson.M{"email": usr.Email}).Decode(&foundUser))

	assert.Equal(t, usr.Name, foundUser.Name)
	assert.Equal(t, usr.Email, foundUser.Email)
	assert.Equal(t, usr.Age, foundUser.Age)

	assert.Nil(t, client.Disconnect(ctx))
}
