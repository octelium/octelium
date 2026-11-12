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

package postgres

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"context"

	"github.com/jackc/pgx/v5/pgproto3"
	"github.com/octelium/octelium/apis/cluster/coctovigilv1"
	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/apis/main/metav1"
	"github.com/octelium/octelium/apis/rsc/rmetav1"
	"github.com/octelium/octelium/cluster/apiserver/apiserver/admin"
	"github.com/octelium/octelium/cluster/apiserver/apiserver/user"
	"github.com/octelium/octelium/cluster/common/tests"
	"github.com/octelium/octelium/cluster/common/tests/tstuser"
	"github.com/octelium/octelium/cluster/vigil/vigil/loadbalancer"
	"github.com/octelium/octelium/cluster/vigil/vigil/modes"
	"github.com/octelium/octelium/cluster/vigil/vigil/octovigilc"
	"github.com/octelium/octelium/cluster/vigil/vigil/secretman"
	"github.com/octelium/octelium/cluster/vigil/vigil/vcache"
	"github.com/octelium/octelium/pkg/common/pbutils"
	"github.com/octelium/octelium/pkg/utils/utilrand"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
	"go.uber.org/zap"

	"database/sql"

	_ "github.com/lib/pq"
)

func setTestMeterProvider(t *testing.T) *sdkmetric.ManualReader {
	prevProvider := otel.GetMeterProvider()
	t.Cleanup(func() {
		otel.SetMeterProvider(prevProvider)
	})

	reader := sdkmetric.NewManualReader()
	otel.SetMeterProvider(sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader)))

	return reader
}

func TestStartupMalformed(t *testing.T) {
	packet := func(code uint32, body []byte) []byte {
		ret := binary.BigEndian.AppendUint32(nil, uint32(8+len(body)))
		ret = binary.BigEndian.AppendUint32(ret, code)
		return append(ret, body...)
	}
	for _, tc := range []struct {
		name string
		data []byte
	}{
		{"empty", nil},
		{"short length", []byte{0, 0, 0}},
		{"zero length", []byte{0, 0, 0, 0}},
		{"negative length", []byte{255, 255, 255, 255}},
		{"short message", []byte{0, 0, 0, 7}},
		{"large length", binary.BigEndian.AppendUint32(nil, 10005)},
		{"unknown version", packet(123, nil)},
		{"incomplete parameter", packet(pgproto3.ProtocolVersion30, []byte("user\x00root"))},
		{"missing parameter value", packet(pgproto3.ProtocolVersion30, []byte("user\x00"))},
		{"GSS request", packet(80877104, nil)},
		{"short cancel", packet(80877102, []byte{1})},
	} {
		t.Run(tc.name, func(t *testing.T) {
			client, server := net.Pipe()
			defer server.Close()
			require.Nil(t, server.SetDeadline(time.Now().Add(2*time.Second)))
			done := make(chan struct{})
			go func() {
				defer close(done)
				defer client.Close()
				_, _ = client.Write(tc.data)
			}()
			msg, backend, isCancel, err := (&Server{}).getStartupMessage(t.Context(),
				&corev1.Service{Spec: &corev1.Service_Spec{}}, server)
			assert.NotNil(t, err)
			assert.Nil(t, msg)
			assert.Nil(t, backend)
			assert.False(t, isCancel)
			assert.False(t, isTimeoutErr(err))
			server.Close()
			<-done
		})
	}
}

func TestStartupFragmented(t *testing.T) {
	for _, username := range []string{"", "user", "user' host=attacker sslmode=disable", strings.Repeat("u", 9000)} {
		client, server := net.Pipe()
		require.Nil(t, server.SetDeadline(time.Now().Add(5*time.Second)))
		startup, err := (&pgproto3.StartupMessage{
			ProtocolVersion: pgproto3.ProtocolVersion30,
			Parameters:      map[string]string{"user": username, "database": "database"},
		}).Encode(nil)
		require.Nil(t, err)
		query, err := (&pgproto3.Query{String: "SELECT 1"}).Encode(nil)
		require.Nil(t, err)
		done := make(chan struct{})
		go func() {
			defer close(done)
			defer client.Close()
			for _, b := range append(startup, query...) {
				if _, err := client.Write([]byte{b}); err != nil {
					return
				}
			}
		}()
		msg, backend, isCancel, err := (&Server{}).getStartupMessage(t.Context(),
			&corev1.Service{Spec: &corev1.Service_Spec{}}, server)
		require.Nil(t, err)
		require.NotNil(t, msg)
		assert.False(t, isCancel)
		assert.Equal(t, username, msg.Parameters["user"])
		request := (&Server{}).getDownstreamReq(t.Context(), server, msg)
		assert.Equal(t, username, request.Request.GetPostgres().GetConnect().User)
		next, err := backend.Receive()
		require.Nil(t, err)
		assert.Equal(t, &pgproto3.Query{String: "SELECT 1"}, next)
		server.Close()
		<-done
	}
}

func TestStartupSSLRequestLimit(t *testing.T) {
	client, server := net.Pipe()
	defer server.Close()
	require.Nil(t, server.SetDeadline(time.Now().Add(3*time.Second)))
	sslRequest, err := (&pgproto3.SSLRequest{}).Encode(nil)
	require.Nil(t, err)
	done := make(chan int, 1)
	go func() {
		defer client.Close()
		var accepted int
		defer func() { done <- accepted }()
		for range 11 {
			if _, err := client.Write(sslRequest); err != nil {
				return
			}
			var response [1]byte
			if _, err := io.ReadFull(client, response[:]); err != nil {
				return
			}
			assert.Equal(t, byte('N'), response[0])
			accepted++
		}
	}()
	msg, backend, isCancel, err := (&Server{}).getStartupMessage(t.Context(),
		&corev1.Service{Spec: &corev1.Service_Spec{}}, server)
	require.NotNil(t, err)
	assert.Contains(t, err.Error(), "Too many ssl requests")
	assert.Nil(t, msg)
	assert.Nil(t, backend)
	assert.False(t, isCancel)
	server.Close()
	assert.Equal(t, 10, <-done)
}

func TestStartupCanceled(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	msg, backend, isCancel, err := (&Server{}).getStartupMessage(ctx,
		&corev1.Service{Spec: &corev1.Service_Spec{}}, server)
	assert.Nil(t, err)
	assert.Nil(t, msg)
	assert.Nil(t, backend)
	assert.False(t, isCancel)
}

func TestCancelKeyStoreConcurrent(t *testing.T) {
	store := newCancelKeyStore()
	var wg sync.WaitGroup
	for i := range 64 {
		wg.Go(func() {
			key := cancelKey{processID: 1, secretKey: fmt.Sprintf("secret-%d", i)}
			target := &cancelTarget{addr: fmt.Sprintf("127.0.0.1:%d", i+1)}
			for range 32 {
				store.set(key, target)
				assert.Equal(t, target, store.get(key))
				assert.Nil(t, store.get(cancelKey{processID: 2, secretKey: key.secretKey}))
				store.delete(key)
				assert.Nil(t, store.get(key))
			}
		})
	}
	wg.Wait()
	assert.Empty(t, store.targets)
}

func TestConcurrentConnections(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
	defer cancel()
	tst, err := tests.Initialize(nil)
	require.Nil(t, err)
	t.Cleanup(func() { tst.Destroy() })
	s := newTestPostgresServer(t, ctx, tst, []*corev1.Policy_Spec_Rule{
		{Effect: corev1.Policy_Spec_Rule_ALLOW, Condition: &corev1.Condition{
			Type: &corev1.Condition_MatchAny{MatchAny: true},
		}},
	}, &corev1.Service_Spec_Config_Postgres_Authorization{Mode: corev1.Service_Spec_Config_Postgres_Authorization_ALL})

	var wg sync.WaitGroup
	for i := range 16 {
		wg.Go(func() {
			db, err := sql.Open("postgres", fmt.Sprintf("postgres://downstream:ignored@127.0.0.1:%d/ignored?sslmode=disable&connect_timeout=5", s.port))
			if !assert.Nil(t, err) {
				return
			}
			defer db.Close()
			db.SetMaxOpenConns(1)
			payload := fmt.Sprintf("request-%d-", i) + strings.Repeat("'\\;\n", 16*1024)
			for range 4 {
				var got string
				err := db.QueryRowContext(ctx, "SELECT $1::text", payload).Scan(&got)
				if !assert.Nil(t, err) {
					return
				}
				assert.Equal(t, payload, got)
			}
		})
	}
	wg.Wait()
	require.Eventually(t, func() bool {
		s.srv.dctxMap.mu.Lock()
		defer s.srv.dctxMap.mu.Unlock()
		return len(s.srv.dctxMap.dctxMap) == 0
	}, 3*time.Second, 10*time.Millisecond)
}

func findSumDataPointByState(t *testing.T, rm *metricdata.ResourceMetrics, name, state string) (metricdata.DataPoint[int64], bool) {
	for _, sm := range rm.ScopeMetrics {
		for _, m := range sm.Metrics {
			if m.Name != name {
				continue
			}
			sum, ok := m.Data.(metricdata.Sum[int64])
			assert.True(t, ok, name)
			for _, dp := range sum.DataPoints {
				stateVal, ok := dp.Attributes.Value("state")
				if ok && stateVal.AsString() == state {
					return dp, true
				}
			}
		}
	}
	return metricdata.DataPoint[int64]{}, false
}

func findSumDataPoint(t *testing.T, rm *metricdata.ResourceMetrics, name string) metricdata.DataPoint[int64] {
	for _, sm := range rm.ScopeMetrics {
		for _, m := range sm.Metrics {
			if m.Name != name {
				continue
			}
			sum, ok := m.Data.(metricdata.Sum[int64])
			assert.True(t, ok, name)
			assert.Len(t, sum.DataPoints, 1)
			return sum.DataPoints[0]
		}
	}
	t.Fatalf("metric %s not found", name)
	return metricdata.DataPoint[int64]{}
}

func TestServer(t *testing.T) {
	ctx := context.Background()

	tst, err := tests.Initialize(nil)
	assert.Nil(t, err, "%+v", err)
	t.Cleanup(func() {
		tst.Destroy()
	})
	fakeC := tst.C
	{
		cc, err := fakeC.OcteliumC.CoreV1Utils().GetClusterConfig(ctx)
		assert.Nil(t, err)

		cc.Status.Network.ClusterNetwork = &metav1.DualStackNetwork{
			V4: "127.0.0.0/8",
			V6: "::1/128",
		}
		_, err = fakeC.OcteliumC.CoreC().UpdateClusterConfig(ctx, cc)
		assert.Nil(t, err)
	}

	adminSrv := admin.NewServer(&admin.Opts{
		OcteliumC:  fakeC.OcteliumC,
		IsEmbedded: true,
	})
	usrSrv := user.NewServer(fakeC.OcteliumC)

	upstreamPort := 5432

	sec, err := adminSrv.CreateSecret(ctx, &corev1.Secret{
		Metadata: &metav1.Metadata{
			Name: utilrand.GetRandomStringCanonical(6),
		},
		Spec: &corev1.Secret_Spec{},
		Data: &corev1.Secret_Data{
			Type: &corev1.Secret_Data_Value{
				Value: "postgres",
			},
		},
	})
	assert.Nil(t, err)

	svc, err := adminSrv.CreateService(ctx, &corev1.Service{
		Metadata: &metav1.Metadata{
			Name: utilrand.GetRandomStringCanonical(6),
		},
		Spec: &corev1.Service_Spec{
			Port: 5433,
			Mode: corev1.Service_Spec_POSTGRES,

			Authorization: &corev1.Service_Spec_Authorization{
				InlinePolicies: []*corev1.InlinePolicy{
					{
						Spec: &corev1.Policy_Spec{
							Rules: []*corev1.Policy_Spec_Rule{
								{
									Effect: corev1.Policy_Spec_Rule_ALLOW,
									Condition: &corev1.Condition{
										Type: &corev1.Condition_MatchAny{
											MatchAny: true,
										},
									},
								},
							},
						},
					},
				},
			},
			Config: &corev1.Service_Spec_Config{
				Upstream: &corev1.Service_Spec_Config_Upstream{
					Type: &corev1.Service_Spec_Config_Upstream_Url{
						Url: fmt.Sprintf("postgres://localhost:%d", upstreamPort),
					},
				},
				Type: &corev1.Service_Spec_Config_Postgres_{
					Postgres: &corev1.Service_Spec_Config_Postgres{
						User:     "postgres",
						Database: "postgres",
						Auth: &corev1.Service_Spec_Config_Postgres_Auth{
							Type: &corev1.Service_Spec_Config_Postgres_Auth_Password_{
								Password: &corev1.Service_Spec_Config_Postgres_Auth_Password{
									Type: &corev1.Service_Spec_Config_Postgres_Auth_Password_FromSecret{
										FromSecret: sec.Metadata.Name,
									},
								},
							},
						},
					},
				},
			},
		},
	})
	assert.Nil(t, err, "")
	svcV, err := fakeC.OcteliumC.CoreC().GetService(ctx, &rmetav1.GetOptions{Uid: svc.Metadata.Uid})
	assert.Nil(t, err)

	vCache, err := vcache.NewCache(ctx)
	assert.Nil(t, err)
	vCache.SetService(svcV)

	octovigilC, err := octovigilc.NewClient(ctx, &octovigilc.Opts{
		VCache:    vCache,
		OcteliumC: fakeC.OcteliumC,
	})
	assert.Nil(t, err)

	secretMan, err := secretman.New(ctx, fakeC.OcteliumC, vCache)
	assert.Nil(t, err)

	secretMan.Set(sec)

	metricsReader := setTestMeterProvider(t)

	srv, err := New(ctx, &modes.Opts{
		OcteliumC:  fakeC.OcteliumC,
		VCache:     vCache,
		OctovigilC: octovigilC,
		SecretMan:  secretMan,
		LBManager:  loadbalancer.NewLbManager(fakeC.OcteliumC, vCache),
	})
	assert.Nil(t, err)
	err = srv.Run(ctx)
	assert.Nil(t, err)

	{
		time.Sleep(1 * time.Second)
		db, err := sql.Open("postgres", fmt.Sprintf("postgres://postgres:postgres@localhost:%d/postgres?sslmode=disable", svc.Spec.Port))
		assert.Nil(t, err)

		_, err = db.Exec("SELECT datname FROM pg_database LIMIT 5;")
		assert.NotNil(t, err)

	}

	{
		var rm metricdata.ResourceMetrics
		assert.Nil(t, metricsReader.Collect(ctx, &rm))

		dp, found := findSumDataPointByState(t, &rm, "req.total", "DENIED")
		assert.True(t, found)
		assert.True(t, dp.Value > 0)
	}

	usr, err := tstuser.NewUser(fakeC.OcteliumC, adminSrv, usrSrv, nil)
	assert.Nil(t, err)
	err = usr.Connect()
	assert.Nil(t, err, "%+v", err)

	usr.Session.Status.Connection = &corev1.Session_Status_Connection{
		Addresses: []*metav1.DualStackNetwork{
			{
				V4: "127.0.0.1/32",
				V6: "::1/128",
			},
		},
		Type:   corev1.Session_Status_Connection_WIREGUARD,
		L3Mode: corev1.Session_Status_Connection_V4,
	}

	usr.Session, err = fakeC.OcteliumC.CoreC().UpdateSession(ctx, usr.Session)
	assert.Nil(t, err)
	usr.Resync()

	srv.octovigilC.GetCache().SetSession(usr.Session)
	usr.Resync()

	time.Sleep(1 * time.Second)

	db, err := sql.Open("postgres", fmt.Sprintf("postgres://postgres:postgres@localhost:%d/postgres?sslmode=disable", svc.Spec.Port))
	assert.Nil(t, err)

	{
		_, err := db.Exec("SELECT datname FROM pg_database LIMIT 5;")
		assert.Nil(t, err)
	}

	{
		_, err := db.Exec(`
		CREATE OR REPLACE FUNCTION helloWorld(name text) RETURNS void AS $helloWorld$
		DECLARE
		BEGIN
				RAISE LOG 'Hello, %', name;
		END;
		$helloWorld$ LANGUAGE plpgsql;
		`)
		assert.Nil(t, err)
	}

	{
		_, err := db.Exec(`
		SELECT "helloworld"('myname');
		`)
		assert.Nil(t, err)
	}

	{
		res, err := db.Prepare(`
		SELECT "helloworld"('myname');
		`)
		assert.Nil(t, err)

		_, err = res.Exec()
		assert.Nil(t, err)

		err = res.Close()
		assert.Nil(t, err)
	}

	{
		tx, err := db.BeginTx(ctx, &sql.TxOptions{
			ReadOnly: true,
		})
		assert.Nil(t, err)
		_, err = tx.Exec("SELECT datname FROM pg_database LIMIT 5;")
		assert.Nil(t, err)

		err = tx.Commit()
		assert.Nil(t, err)
	}

	{
		err := db.Ping()
		assert.Nil(t, err)
	}

	{
		_, err = db.Exec("SELECT current_database();")
		assert.Nil(t, err)

		table := fmt.Sprintf("users%s", utilrand.GetRandomStringCanonical(6))

		createTableSQL := fmt.Sprintf(`
	CREATE TABLE %s (
		id SERIAL PRIMARY KEY,
		name VARCHAR(100) NOT NULL,
		status VARCHAR(50) NOT NULL
	);`, table)
		_, err = db.Exec(createTableSQL)
		assert.Nil(t, err)

		var insertedID int
		insertSQL := fmt.Sprintf("INSERT INTO %s (name, status) VALUES ($1, $2) RETURNING id", table)
		err = db.QueryRow(insertSQL, "john doe", "active").Scan(&insertedID)
		assert.Nil(t, err)
		assert.True(t, insertedID > 0)

		var name, status string
		querySQL := fmt.Sprintf("SELECT name, status FROM %s WHERE id = $1", table)

		err = db.QueryRow(querySQL, insertedID).Scan(&name, &status)
		assert.Nil(t, err)
		assert.Equal(t, "john doe", name)
		assert.Equal(t, "active", status)

		updateSQL := fmt.Sprintf("UPDATE %s SET status = $1 WHERE id = $2", table)
		res, err := db.Exec(updateSQL, "inactive", insertedID)
		assert.Nil(t, err)

		rowsAffected, err := res.RowsAffected()
		assert.Nil(t, err)
		assert.Equal(t, int64(1), rowsAffected)

		deleteSQL := fmt.Sprintf("DELETE FROM %s WHERE id = $1", table)
		res, err = db.Exec(deleteSQL, insertedID)
		assert.Nil(t, err)

		rowsAffected, err = res.RowsAffected()
		assert.Nil(t, err)
		assert.Equal(t, int64(1), rowsAffected)

		err = db.QueryRow(querySQL, insertedID).Scan(&name, &status)
		assert.ErrorIs(t, err, sql.ErrNoRows)

		{
			svc.Spec.Config.GetPostgres().Authorization = &corev1.Service_Spec_Config_Postgres_Authorization{
				Mode: corev1.Service_Spec_Config_Postgres_Authorization_ALL,
			}
			svc.Spec.Authorization = &corev1.Service_Spec_Authorization{
				InlinePolicies: []*corev1.InlinePolicy{
					{
						Spec: &corev1.Policy_Spec{
							Rules: []*corev1.Policy_Spec_Rule{
								{
									Condition: &corev1.Condition{
										Type: &corev1.Condition_Match{
											Match: `ctx.request.postgres.parse.query.startsWith("UPDATE")`,
										},
									},
									Effect: corev1.Policy_Spec_Rule_DENY,
								},
								{
									Effect: corev1.Policy_Spec_Rule_ALLOW,
									Condition: &corev1.Condition{
										Type: &corev1.Condition_MatchAny{
											MatchAny: true,
										},
									},
								},
							},
						},
					},
				},
			}

			svc, err = fakeC.OcteliumC.CoreC().UpdateService(ctx, svc)
			assert.Nil(t, err)

			vCache.SetService(svc)

			err = db.Close()
			assert.Nil(t, err)
			time.Sleep(2 * time.Second)

			{
				var rm metricdata.ResourceMetrics
				assert.Nil(t, metricsReader.Collect(ctx, &rm))

				dp, found := findSumDataPointByState(t, &rm, "req.total", "ALLOWED")
				assert.True(t, found)
				assert.Equal(t, int64(1), dp.Value)

				sentDP := findSumDataPoint(t, &rm, "req.bytes_sent")
				assert.True(t, sentDP.Value > 0)

				receivedDP := findSumDataPoint(t, &rm, "req.bytes_received")
				assert.True(t, receivedDP.Value > 0)
			}

			{
				db, err := sql.Open("postgres", fmt.Sprintf("postgres://postgres:postgres@localhost:%d/postgres?sslmode=disable", svc.Spec.Port))
				assert.Nil(t, err)

				{
					err := db.Ping()
					assert.Nil(t, err)
				}

				var insertedID int
				insertSQL := fmt.Sprintf("INSERT INTO %s (name, status) VALUES ($1, $2) RETURNING id", table)
				err = db.QueryRow(insertSQL, "linus torvalds", "active").Scan(&insertedID)
				assert.Nil(t, err, "%+v", err)
				assert.True(t, insertedID > 0)

				var name, status string
				querySQL := fmt.Sprintf("SELECT name, status FROM %s WHERE id = $1", table)

				err = db.QueryRow(querySQL, insertedID).Scan(&name, &status)
				assert.Nil(t, err)
				assert.Equal(t, "linus torvalds", name)
				assert.Equal(t, "active", status)

				updateSQL := fmt.Sprintf("UPDATE %s SET status = $1 WHERE id = $2", table)
				_, err = db.Exec(updateSQL, "inactive", insertedID)
				assert.NotNil(t, err)

				deleteSQL := fmt.Sprintf("DELETE FROM %s WHERE id = $1", table)
				res, err = db.Exec(deleteSQL, insertedID)
				assert.Nil(t, err, "%+v", err)
			}
		}

		{
			svc.Spec.Config.GetPostgres().Authorization = nil
			svc.Spec.Authorization = &corev1.Service_Spec_Authorization{
				InlinePolicies: []*corev1.InlinePolicy{
					{
						Spec: &corev1.Policy_Spec{
							Rules: []*corev1.Policy_Spec_Rule{
								{
									Condition: &corev1.Condition{
										Type: &corev1.Condition_Match{
											Match: `ctx.request.postgres.parse.query.startsWith("UPDATE")`,
										},
									},
									Effect: corev1.Policy_Spec_Rule_DENY,
								},
								{
									Effect: corev1.Policy_Spec_Rule_ALLOW,
									Condition: &corev1.Condition{
										Type: &corev1.Condition_MatchAny{
											MatchAny: true,
										},
									},
								},
							},
						},
					},
				},
			}

			svc, err = fakeC.OcteliumC.CoreC().UpdateService(ctx, svc)
			assert.Nil(t, err)

			vCache.SetService(svc)

			err = db.Close()
			assert.Nil(t, err)
			time.Sleep(2 * time.Second)
			{
				db, err := sql.Open("postgres", fmt.Sprintf("postgres://postgres:postgres@localhost:%d/postgres?sslmode=disable", svc.Spec.Port))
				assert.Nil(t, err)

				{
					err := db.Ping()
					assert.Nil(t, err)
				}

				var insertedID int
				insertSQL := fmt.Sprintf("INSERT INTO %s (name, status) VALUES ($1, $2) RETURNING id", table)
				err = db.QueryRow(insertSQL, "linus torvalds 2", "active").Scan(&insertedID)
				assert.Nil(t, err, "%+v", err)
				assert.True(t, insertedID > 0)

				var name, status string
				querySQL := fmt.Sprintf("SELECT name, status FROM %s WHERE id = $1", table)

				err = db.QueryRow(querySQL, insertedID).Scan(&name, &status)
				assert.Nil(t, err)
				assert.Equal(t, "linus torvalds 2", name)
				assert.Equal(t, "active", status)

				updateSQL := fmt.Sprintf("UPDATE %s SET status = $1 WHERE id = $2", table)
				_, err = db.Exec(updateSQL, "inactive", insertedID)
				assert.Nil(t, err)

				deleteSQL := fmt.Sprintf("DELETE FROM %s WHERE id = $1", table)
				res, err = db.Exec(deleteSQL, insertedID)
				assert.Nil(t, err, "%+v", err)
			}
		}
	}

	err = srv.Close()
	zap.L().Debug("close err", zap.Error(err))
}

func assertClosedByDeadline(t *testing.T, c net.Conn, timeout time.Duration) {
	t.Helper()

	if err := c.SetReadDeadline(time.Now().Add(timeout + 8*time.Second)); err != nil {
		t.Fatal(err)
	}

	startedAt := time.Now()
	_, err := io.Copy(io.Discard, c)
	elapsed := time.Since(startedAt)

	assert.False(t, isTimeoutErr(err), "the server never closed the idle conn: %+v", err)
	assert.Less(t, elapsed, timeout+8*time.Second)
	assert.Greater(t, elapsed, timeout/2)
}

func isTimeoutErr(err error) bool {
	var netErr net.Error
	return errors.As(err, &netErr) && netErr.Timeout()
}

func TestStartupDeadline(t *testing.T) {
	ctx := context.Background()

	tst, err := tests.Initialize(nil)
	assert.Nil(t, err, "%+v", err)
	t.Cleanup(func() {
		tst.Destroy()
	})
	fakeC := tst.C

	adminSrv := admin.NewServer(&admin.Opts{
		OcteliumC:  fakeC.OcteliumC,
		IsEmbedded: true,
	})

	port := tests.GetPort()

	svc, err := adminSrv.CreateService(ctx, &corev1.Service{
		Metadata: &metav1.Metadata{
			Name: utilrand.GetRandomStringCanonical(6),
		},
		Spec: &corev1.Service_Spec{
			Port: uint32(port),
			Mode: corev1.Service_Spec_POSTGRES,
			Config: &corev1.Service_Spec_Config{
				Upstream: &corev1.Service_Spec_Config_Upstream{
					Type: &corev1.Service_Spec_Config_Upstream_Url{
						Url: "postgres://localhost:5432",
					},
				},
			},
		},
	})
	assert.Nil(t, err, "%+v", err)

	svcV, err := fakeC.OcteliumC.CoreC().GetService(ctx, &rmetav1.GetOptions{Uid: svc.Metadata.Uid})
	assert.Nil(t, err)

	vCache, err := vcache.NewCache(ctx)
	assert.Nil(t, err)
	vCache.SetService(svcV)

	octovigilC, err := octovigilc.NewClient(ctx, &octovigilc.Opts{
		VCache:    vCache,
		OcteliumC: fakeC.OcteliumC,
	})
	assert.Nil(t, err)

	secretMan, err := secretman.New(ctx, fakeC.OcteliumC, vCache)
	assert.Nil(t, err)

	srv, err := New(ctx, &modes.Opts{
		OcteliumC:  fakeC.OcteliumC,
		VCache:     vCache,
		OctovigilC: octovigilC,
		SecretMan:  secretMan,
		LBManager:  loadbalancer.NewLbManager(fakeC.OcteliumC, vCache),
	})
	assert.Nil(t, err)
	err = srv.Run(ctx)
	assert.Nil(t, err)
	t.Cleanup(func() {
		srv.Close()
	})

	time.Sleep(1 * time.Second)

	c, err := net.Dial("tcp", fmt.Sprintf("localhost:%d", port))
	assert.Nil(t, err)
	defer c.Close()

	assertClosedByDeadline(t, c, startupTimeout)
}

const (
	testReadTimeout = 10 * time.Second
	testIdleTimeout = 2 * time.Second
)

type testPostgresServer struct {
	srv    *Server
	vCache *vcache.Cache
	svc    *corev1.Service
	port   int
}

func newTestPostgresServer(t *testing.T, ctx context.Context, tst *tests.T,
	rules []*corev1.Policy_Spec_Rule,
	pgAuthz *corev1.Service_Spec_Config_Postgres_Authorization) *testPostgresServer {
	t.Helper()

	fakeC := tst.C
	{
		cc, err := fakeC.OcteliumC.CoreV1Utils().GetClusterConfig(ctx)
		assert.Nil(t, err)

		cc.Status.Network.ClusterNetwork = &metav1.DualStackNetwork{
			V4: "127.0.0.0/8",
			V6: "::1/128",
		}
		_, err = fakeC.OcteliumC.CoreC().UpdateClusterConfig(ctx, cc)
		assert.Nil(t, err)
	}

	adminSrv := admin.NewServer(&admin.Opts{
		OcteliumC:  fakeC.OcteliumC,
		IsEmbedded: true,
	})
	usrSrv := user.NewServer(fakeC.OcteliumC)

	sec, err := adminSrv.CreateSecret(ctx, &corev1.Secret{
		Metadata: &metav1.Metadata{
			Name: utilrand.GetRandomStringCanonical(6),
		},
		Spec: &corev1.Secret_Spec{},
		Data: &corev1.Secret_Data{
			Type: &corev1.Secret_Data_Value{
				Value: "postgres",
			},
		},
	})
	assert.Nil(t, err)

	port := tests.GetPort()

	svc, err := adminSrv.CreateService(ctx, &corev1.Service{
		Metadata: &metav1.Metadata{
			Name: utilrand.GetRandomStringCanonical(6),
		},
		Spec: &corev1.Service_Spec{
			Port: uint32(port),
			Mode: corev1.Service_Spec_POSTGRES,

			Authorization: &corev1.Service_Spec_Authorization{
				InlinePolicies: []*corev1.InlinePolicy{
					{
						Spec: &corev1.Policy_Spec{
							Rules: rules,
						},
					},
				},
			},
			Config: &corev1.Service_Spec_Config{
				Upstream: &corev1.Service_Spec_Config_Upstream{
					Type: &corev1.Service_Spec_Config_Upstream_Url{
						Url: "postgres://localhost:5432",
					},
				},
				Type: &corev1.Service_Spec_Config_Postgres_{
					Postgres: &corev1.Service_Spec_Config_Postgres{
						User:          "postgres",
						Database:      "postgres",
						Authorization: pgAuthz,
						Auth: &corev1.Service_Spec_Config_Postgres_Auth{
							Type: &corev1.Service_Spec_Config_Postgres_Auth_Password_{
								Password: &corev1.Service_Spec_Config_Postgres_Auth_Password{
									Type: &corev1.Service_Spec_Config_Postgres_Auth_Password_FromSecret{
										FromSecret: sec.Metadata.Name,
									},
								},
							},
						},
					},
				},
			},
		},
	})
	assert.Nil(t, err, "%+v", err)

	svcV, err := fakeC.OcteliumC.CoreC().GetService(ctx, &rmetav1.GetOptions{Uid: svc.Metadata.Uid})
	assert.Nil(t, err)

	vCache, err := vcache.NewCache(ctx)
	assert.Nil(t, err)
	vCache.SetService(svcV)

	octovigilC, err := octovigilc.NewClient(ctx, &octovigilc.Opts{
		VCache:    vCache,
		OcteliumC: fakeC.OcteliumC,
	})
	assert.Nil(t, err)

	secretMan, err := secretman.New(ctx, fakeC.OcteliumC, vCache)
	assert.Nil(t, err)

	secretMan.Set(sec)

	srv, err := New(ctx, &modes.Opts{
		OcteliumC:  fakeC.OcteliumC,
		VCache:     vCache,
		OctovigilC: octovigilC,
		SecretMan:  secretMan,
		LBManager:  loadbalancer.NewLbManager(fakeC.OcteliumC, vCache),
	})
	assert.Nil(t, err)
	err = srv.Run(ctx)
	assert.Nil(t, err)
	t.Cleanup(func() {
		srv.Close()
	})

	usr, err := tstuser.NewUser(fakeC.OcteliumC, adminSrv, usrSrv, nil)
	assert.Nil(t, err)
	err = usr.Connect()
	assert.Nil(t, err, "%+v", err)

	usr.Session.Status.Connection = &corev1.Session_Status_Connection{
		Addresses: []*metav1.DualStackNetwork{
			{
				V4: "127.0.0.1/32",
				V6: "::1/128",
			},
		},
		Type:   corev1.Session_Status_Connection_WIREGUARD,
		L3Mode: corev1.Session_Status_Connection_V4,
	}

	usr.Session, err = fakeC.OcteliumC.CoreC().UpdateSession(ctx, usr.Session)
	assert.Nil(t, err)
	usr.Resync()

	srv.octovigilC.GetCache().SetSession(usr.Session)

	time.Sleep(1 * time.Second)

	return &testPostgresServer{
		srv:    srv,
		vCache: vCache,
		svc:    svc,
		port:   port,
	}
}

func newTestFrontend(t *testing.T, port int) (*pgproto3.Frontend, net.Conn, *pgproto3.BackendKeyData) {
	t.Helper()

	c, err := net.Dial("tcp", fmt.Sprintf("localhost:%d", port))
	if err != nil {
		t.Fatal(err)
	}

	fe := pgproto3.NewFrontend(c, c)
	fe.Send(&pgproto3.StartupMessage{
		ProtocolVersion: pgproto3.ProtocolVersionNumber,
		Parameters: map[string]string{
			"user":     "postgres",
			"database": "postgres",
		},
	})
	if err := fe.Flush(); err != nil {
		t.Fatal(err)
	}

	ret := &pgproto3.BackendKeyData{}
	for _, msg := range receiveUntilReadyForQuery(t, c, fe) {
		if keyData, ok := msg.(*pgproto3.BackendKeyData); ok {
			ret.ProcessID = keyData.ProcessID
			ret.SecretKey = keyData.SecretKey
		}
	}

	return fe, c, ret
}

func sendCancelRequest(t *testing.T, port int, keyData *pgproto3.BackendKeyData) {
	t.Helper()

	c, err := net.Dial("tcp", fmt.Sprintf("localhost:%d", port))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	fe := pgproto3.NewFrontend(c, c)
	fe.Send(&pgproto3.CancelRequest{
		ProcessID: keyData.ProcessID,
		SecretKey: keyData.SecretKey,
	})
	if err := fe.Flush(); err != nil {
		t.Fatal(err)
	}
}

func receiveQueryValue(t *testing.T, c net.Conn, fe *pgproto3.Frontend, query string) string {
	t.Helper()

	fe.Send(&pgproto3.Query{String: query})
	if err := fe.Flush(); err != nil {
		t.Fatal(err)
	}

	var ret string
	for {
		msg := receiveMessage(t, c, fe)
		if dataRow, ok := msg.(*pgproto3.DataRow); ok && len(dataRow.Values) == 1 {
			ret = string(dataRow.Values[0])
		}
		if _, ok := msg.(*pgproto3.ReadyForQuery); ok {
			return ret
		}
	}
}

func receiveMessage(t *testing.T, c net.Conn, fe *pgproto3.Frontend) pgproto3.BackendMessage {
	t.Helper()

	if err := c.SetReadDeadline(time.Now().Add(testReadTimeout)); err != nil {
		t.Fatal(err)
	}

	msg, err := fe.Receive()
	if err != nil {
		t.Fatalf("could not receive a backend msg: %+v", err)
	}

	return msg
}

func receiveUntilReadyForQuery(t *testing.T, c net.Conn, fe *pgproto3.Frontend) []pgproto3.BackendMessage {
	t.Helper()

	var ret []pgproto3.BackendMessage
	for {
		msg := receiveMessage(t, c, fe)
		ret = append(ret, msg)
		if _, ok := msg.(*pgproto3.ReadyForQuery); ok {
			return ret
		}
	}
}

func receiveFunctionOID(t *testing.T, c net.Conn, fe *pgproto3.Frontend, name string) uint32 {
	t.Helper()

	fe.Send(&pgproto3.Query{String: fmt.Sprintf("SELECT '%s'::regproc::oid;", name)})
	if err := fe.Flush(); err != nil {
		t.Fatal(err)
	}

	var ret uint64
	for {
		msg := receiveMessage(t, c, fe)
		if dataRow, ok := msg.(*pgproto3.DataRow); ok && len(dataRow.Values) == 1 {
			var err error
			ret, err = strconv.ParseUint(string(dataRow.Values[0]), 10, 32)
			if err != nil {
				t.Fatal(err)
			}
		}
		if _, ok := msg.(*pgproto3.ReadyForQuery); ok {
			break
		}
	}

	if ret == 0 {
		t.Fatalf("could not get the oid of the function %s", name)
	}

	return uint32(ret)
}

func assertNoMessage(t *testing.T, c net.Conn, fe *pgproto3.Frontend) {
	t.Helper()

	if err := c.SetReadDeadline(time.Now().Add(testIdleTimeout)); err != nil {
		t.Fatal(err)
	}

	msg, err := fe.Receive()
	assert.True(t, isTimeoutErr(err), "received an unexpected backend msg: %v %+v", msg, err)
}

func assertClosedByServer(t *testing.T, c net.Conn) {
	t.Helper()

	if err := c.SetReadDeadline(time.Now().Add(testReadTimeout)); err != nil {
		t.Fatal(err)
	}

	_, err := io.Copy(io.Discard, c)
	assert.False(t, isTimeoutErr(err), "the server never closed the conn: %+v", err)
}

func errorResponseCode(msgs ...pgproto3.BackendMessage) string {
	for _, msg := range msgs {
		if errResp, ok := msg.(*pgproto3.ErrorResponse); ok {
			return errResp.Code
		}
	}
	return ""
}

func errorResponseCodes(msgs ...pgproto3.BackendMessage) []string {
	var ret []string
	for _, msg := range msgs {
		if errResp, ok := msg.(*pgproto3.ErrorResponse); ok {
			ret = append(ret, errResp.Code)
		}
	}
	return ret
}

func receiveUntilReadyForQueryValue(t *testing.T, c net.Conn, fe *pgproto3.Frontend) ([]pgproto3.BackendMessage, string) {
	t.Helper()

	var ret []pgproto3.BackendMessage
	var value string
	for {
		msg := receiveMessage(t, c, fe)
		ret = append(ret, msg)
		if dataRow, ok := msg.(*pgproto3.DataRow); ok && len(dataRow.Values) == 1 {
			value = string(dataRow.Values[0])
		}
		if _, ok := msg.(*pgproto3.ReadyForQuery); ok {
			return ret, value
		}
	}
}

func readyForQueryTxStatus(msgs ...pgproto3.BackendMessage) byte {
	for _, msg := range msgs {
		if readyForQuery, ok := msg.(*pgproto3.ReadyForQuery); ok {
			return readyForQuery.TxStatus
		}
	}
	return 0
}

func TestAuthorizationDeny(t *testing.T) {
	ctx := context.Background()

	tst, err := tests.Initialize(nil)
	assert.Nil(t, err, "%+v", err)
	t.Cleanup(func() {
		tst.Destroy()
	})

	ts := newTestPostgresServer(t, ctx, tst, []*corev1.Policy_Spec_Rule{
		{
			Condition: &corev1.Condition{
				Type: &corev1.Condition_Match{
					Match: `ctx.request.postgres.query.query.startsWith("UPDATE")`,
				},
			},
			Effect: corev1.Policy_Spec_Rule_DENY,
		},
		{
			Condition: &corev1.Condition{
				Type: &corev1.Condition_Match{
					Match: `ctx.request.postgres.parse.query.startsWith("UPDATE")`,
				},
			},
			Effect: corev1.Policy_Spec_Rule_DENY,
		},
		{
			Effect: corev1.Policy_Spec_Rule_ALLOW,
			Condition: &corev1.Condition{
				Type: &corev1.Condition_MatchAny{
					MatchAny: true,
				},
			},
		},
	}, &corev1.Service_Spec_Config_Postgres_Authorization{
		Mode: corev1.Service_Spec_Config_Postgres_Authorization_ALL,
	})

	fe, c, _ := newTestFrontend(t, ts.port)
	defer c.Close()

	{
		fe.Send(&pgproto3.Query{String: "UPDATE octelium_nonexistent SET status = 'inactive';"})
		assert.Nil(t, fe.Flush())

		msgs := receiveUntilReadyForQuery(t, c, fe)
		assert.Len(t, msgs, 2)
		assert.Equal(t, "42501", errorResponseCode(msgs...))
	}

	{
		fe.Send(&pgproto3.Query{String: "SELECT 1;"})
		assert.Nil(t, fe.Flush())

		msgs := receiveUntilReadyForQuery(t, c, fe)
		assert.Empty(t, errorResponseCode(msgs...))
		assert.Len(t, msgs, 4)
	}

	{
		fe.Send(&pgproto3.Parse{Query: "UPDATE octelium_nonexistent SET status = $1"})
		fe.Send(&pgproto3.Describe{ObjectType: 'S'})
		fe.Send(&pgproto3.Flush{})
		assert.Nil(t, fe.Flush())

		msg := receiveMessage(t, c, fe)
		assert.Equal(t, "42501", errorResponseCode(msg))

		assertNoMessage(t, c, fe)

		fe.Send(&pgproto3.Sync{})
		assert.Nil(t, fe.Flush())

		msg = receiveMessage(t, c, fe)
		_, ok := msg.(*pgproto3.ReadyForQuery)
		assert.True(t, ok, "%T", msg)
	}

	{
		fe.Send(&pgproto3.Parse{Query: "SELECT 1"})
		fe.Send(&pgproto3.Bind{})
		fe.Send(&pgproto3.Execute{})
		fe.Send(&pgproto3.Sync{})
		assert.Nil(t, fe.Flush())

		msgs := receiveUntilReadyForQuery(t, c, fe)
		assert.Empty(t, errorResponseCode(msgs...))
		assert.Len(t, msgs, 5)
	}

	{
		fe.Send(&pgproto3.Query{String: "SELECT 1;"})
		assert.Nil(t, fe.Flush())

		msgs := receiveUntilReadyForQuery(t, c, fe)
		assert.Empty(t, errorResponseCode(msgs...))
		assert.Len(t, msgs, 4)
	}
}

func TestAuthorizationDenyPipeline(t *testing.T) {
	ctx := context.Background()

	tst, err := tests.Initialize(nil)
	assert.Nil(t, err, "%+v", err)
	t.Cleanup(func() {
		tst.Destroy()
	})

	ts := newTestPostgresServer(t, ctx, tst, []*corev1.Policy_Spec_Rule{
		{
			Condition: &corev1.Condition{
				Type: &corev1.Condition_Match{
					Match: `ctx.request.postgres.query.query.startsWith("UPDATE")`,
				},
			},
			Effect: corev1.Policy_Spec_Rule_DENY,
		},
		{
			Condition: &corev1.Condition{
				Type: &corev1.Condition_Match{
					Match: `ctx.request.postgres.parse.query.startsWith("UPDATE")`,
				},
			},
			Effect: corev1.Policy_Spec_Rule_DENY,
		},
		{
			Effect: corev1.Policy_Spec_Rule_ALLOW,
			Condition: &corev1.Condition{
				Type: &corev1.Condition_MatchAny{
					MatchAny: true,
				},
			},
		},
	}, &corev1.Service_Spec_Config_Postgres_Authorization{
		Mode: corev1.Service_Spec_Config_Postgres_Authorization_ALL,
	})

	fe, c, _ := newTestFrontend(t, ts.port)
	defer c.Close()

	{
		fe.Send(&pgproto3.Query{String: "SELECT 0 FROM pg_sleep(0.3);"})
		for i := 1; i <= 16; i++ {
			fe.Send(&pgproto3.Query{String: "UPDATE octelium_nonexistent SET status = 'inactive';"})
			fe.Send(&pgproto3.FunctionCall{Function: 1})
			fe.Send(&pgproto3.Query{String: fmt.Sprintf("SELECT %d;", i)})
		}
		assert.Nil(t, fe.Flush())

		msgs, value := receiveUntilReadyForQueryValue(t, c, fe)
		assert.Empty(t, errorResponseCodes(msgs...))
		assert.Equal(t, "0", value)

		for i := 1; i <= 16; i++ {
			for range 2 {
				msgs = receiveUntilReadyForQuery(t, c, fe)
				assert.Len(t, msgs, 2)
				assert.Equal(t, []string{"42501"}, errorResponseCodes(msgs...))
				assert.Equal(t, byte('I'), readyForQueryTxStatus(msgs...))
			}

			msgs, value = receiveUntilReadyForQueryValue(t, c, fe)
			assert.Empty(t, errorResponseCodes(msgs...))
			assert.Equal(t, fmt.Sprintf("%d", i), value)
		}
	}

	{
		for i := 1; i <= 16; i++ {
			fe.Send(&pgproto3.Parse{Query: fmt.Sprintf("SELECT %d", i)})
			fe.Send(&pgproto3.Bind{})
			fe.Send(&pgproto3.Execute{})
			fe.Send(&pgproto3.Parse{Query: "UPDATE octelium_nonexistent SET status = $1"})
			fe.Send(&pgproto3.Bind{Parameters: [][]byte{[]byte("inactive")}})
			fe.Send(&pgproto3.Execute{})
			fe.Send(&pgproto3.Sync{})
		}
		fe.Send(&pgproto3.Parse{Query: "SELECT 0"})
		fe.Send(&pgproto3.Bind{})
		fe.Send(&pgproto3.Execute{})
		fe.Send(&pgproto3.Sync{})
		assert.Nil(t, fe.Flush())

		for i := 1; i <= 16; i++ {
			msgs, value := receiveUntilReadyForQueryValue(t, c, fe)
			require.Len(t, msgs, 6)
			assert.Equal(t, fmt.Sprintf("%d", i), value)
			assert.Equal(t, []string{"42501"}, errorResponseCodes(msgs...))
			assert.IsType(t, &pgproto3.ErrorResponse{}, msgs[4])
			assert.Equal(t, byte('I'), readyForQueryTxStatus(msgs...))
		}

		msgs, value := receiveUntilReadyForQueryValue(t, c, fe)
		assert.Len(t, msgs, 5)
		assert.Empty(t, errorResponseCodes(msgs...))
		assert.Equal(t, "0", value)
		assert.Equal(t, byte('I'), readyForQueryTxStatus(msgs...))
	}

	{
		fe.Send(&pgproto3.Parse{Query: "SELECT 1/0"})
		fe.Send(&pgproto3.Bind{})
		fe.Send(&pgproto3.Execute{})
		fe.Send(&pgproto3.Parse{Query: "UPDATE octelium_nonexistent SET status = $1"})
		fe.Send(&pgproto3.Bind{Parameters: [][]byte{[]byte("inactive")}})
		fe.Send(&pgproto3.Execute{})
		fe.Send(&pgproto3.Sync{})
		assert.Nil(t, fe.Flush())

		msgs := receiveUntilReadyForQuery(t, c, fe)
		assert.Equal(t, []string{"22012"}, errorResponseCodes(msgs...))
		assert.Equal(t, byte('I'), readyForQueryTxStatus(msgs...))
	}

	{
		fe.Send(&pgproto3.Query{String: "SELECT 1;"})
		assert.Nil(t, fe.Flush())

		msgs, value := receiveUntilReadyForQueryValue(t, c, fe)
		assert.Len(t, msgs, 4)
		assert.Empty(t, errorResponseCodes(msgs...))
		assert.Equal(t, "1", value)
	}
}

func TestAuthorizationDenyTransaction(t *testing.T) {
	ctx := context.Background()

	tst, err := tests.Initialize(nil)
	assert.Nil(t, err, "%+v", err)
	t.Cleanup(func() {
		tst.Destroy()
	})

	ts := newTestPostgresServer(t, ctx, tst, []*corev1.Policy_Spec_Rule{
		{
			Condition: &corev1.Condition{
				Type: &corev1.Condition_Match{
					Match: `ctx.request.postgres.query.query.startsWith("UPDATE")`,
				},
			},
			Effect: corev1.Policy_Spec_Rule_DENY,
		},
		{
			Condition: &corev1.Condition{
				Type: &corev1.Condition_Match{
					Match: `ctx.request.postgres.parse.query.startsWith("UPDATE")`,
				},
			},
			Effect: corev1.Policy_Spec_Rule_DENY,
		},
		{
			Effect: corev1.Policy_Spec_Rule_ALLOW,
			Condition: &corev1.Condition{
				Type: &corev1.Condition_MatchAny{
					MatchAny: true,
				},
			},
		},
	}, &corev1.Service_Spec_Config_Postgres_Authorization{
		Mode: corev1.Service_Spec_Config_Postgres_Authorization_ALL,
	})

	fe, c, _ := newTestFrontend(t, ts.port)
	defer c.Close()

	table := fmt.Sprintf("users%s", utilrand.GetRandomStringCanonical(6))

	sendQuery := func(query string) []pgproto3.BackendMessage {
		fe.Send(&pgproto3.Query{String: query})
		assert.Nil(t, fe.Flush())
		return receiveUntilReadyForQuery(t, c, fe)
	}

	{
		msgs := sendQuery(fmt.Sprintf("CREATE TABLE %s (id INT);", table))
		assert.Empty(t, errorResponseCodes(msgs...))
	}

	t.Cleanup(func() {
		fe, c, _ := newTestFrontend(t, ts.port)
		defer c.Close()

		fe.Send(&pgproto3.Query{String: fmt.Sprintf("DROP TABLE %s;", table)})
		assert.Nil(t, fe.Flush())
		receiveUntilReadyForQuery(t, c, fe)
	})

	for _, deniedMsgs := range [][]pgproto3.FrontendMessage{
		{
			&pgproto3.Query{String: fmt.Sprintf("UPDATE %s SET id = 2;", table)},
		},
		{
			&pgproto3.FunctionCall{Function: 1},
		},
		{
			&pgproto3.Parse{Query: fmt.Sprintf("UPDATE %s SET id = 2", table)},
			&pgproto3.Bind{},
			&pgproto3.Execute{},
			&pgproto3.Sync{},
		},
	} {
		{
			msgs := sendQuery("BEGIN;")
			assert.Empty(t, errorResponseCodes(msgs...))
			assert.Equal(t, byte('T'), readyForQueryTxStatus(msgs...))
		}

		{
			msgs := sendQuery(fmt.Sprintf("INSERT INTO %s VALUES (1);", table))
			assert.Empty(t, errorResponseCodes(msgs...))
			assert.Equal(t, byte('T'), readyForQueryTxStatus(msgs...))
		}

		{
			for _, msg := range deniedMsgs {
				fe.Send(msg)
			}
			assert.Nil(t, fe.Flush())

			msgs := receiveUntilReadyForQuery(t, c, fe)
			assert.Len(t, msgs, 2)
			assert.Equal(t, []string{"42501"}, errorResponseCodes(msgs...))
			assert.Equal(t, byte('E'), readyForQueryTxStatus(msgs...))
		}

		{
			fe.Send(&pgproto3.Query{String: "COMMIT;"})
			assert.Nil(t, fe.Flush())

			msg := receiveMessage(t, c, fe)
			cmd, ok := msg.(*pgproto3.CommandComplete)
			require.True(t, ok, "%T", msg)
			assert.Equal(t, "ROLLBACK", string(cmd.CommandTag))

			msgs := receiveUntilReadyForQuery(t, c, fe)
			assert.Len(t, msgs, 1)
			assert.Equal(t, byte('I'), readyForQueryTxStatus(msgs...))
		}

		assert.Equal(t, "0",
			receiveQueryValue(t, c, fe, fmt.Sprintf("SELECT count(*) FROM %s;", table)))
	}
}

func TestAuthorizationPreparedStatement(t *testing.T) {
	ctx := context.Background()

	tst, err := tests.Initialize(nil)
	assert.Nil(t, err, "%+v", err)
	t.Cleanup(func() {
		tst.Destroy()
	})

	allowAll := &corev1.Policy_Spec_Rule{
		Effect: corev1.Policy_Spec_Rule_ALLOW,
		Condition: &corev1.Condition{
			Type: &corev1.Condition_MatchAny{
				MatchAny: true,
			},
		},
	}

	denyInsert := &corev1.Policy_Spec_Rule{
		Condition: &corev1.Condition{
			Type: &corev1.Condition_Match{
				Match: `ctx.request.postgres.parse.query.startsWith("INSERT")`,
			},
		},
		Effect: corev1.Policy_Spec_Rule_DENY,
	}

	ts := newTestPostgresServer(t, ctx, tst, []*corev1.Policy_Spec_Rule{allowAll},
		&corev1.Service_Spec_Config_Postgres_Authorization{
			Mode: corev1.Service_Spec_Config_Postgres_Authorization_ALL,
		})

	setRules := func(rules ...*corev1.Policy_Spec_Rule) {
		svc := pbutils.Clone(ts.vCache.GetService()).(*corev1.Service)
		svc.Spec.Authorization.InlinePolicies[0].Spec.Rules = rules
		ts.vCache.SetService(svc)
	}

	fe, c, _ := newTestFrontend(t, ts.port)
	defer c.Close()

	sendMessages := func(msgs ...pgproto3.FrontendMessage) {
		for _, msg := range msgs {
			fe.Send(msg)
		}
		assert.Nil(t, fe.Flush())
	}

	execute := func(name string) ([]pgproto3.BackendMessage, string) {
		sendMessages(&pgproto3.Bind{PreparedStatement: name}, &pgproto3.Execute{}, &pgproto3.Sync{})
		return receiveUntilReadyForQueryValue(t, c, fe)
	}

	table := fmt.Sprintf("users%s", utilrand.GetRandomStringCanonical(6))

	{
		sendMessages(&pgproto3.Query{String: fmt.Sprintf("CREATE TABLE %s (id INT);", table)})
		msgs := receiveUntilReadyForQuery(t, c, fe)
		assert.Empty(t, errorResponseCodes(msgs...))
	}

	t.Cleanup(func() {
		fe, c, _ := newTestFrontend(t, ts.port)
		defer c.Close()

		fe.Send(&pgproto3.Query{String: fmt.Sprintf("DROP TABLE %s;", table)})
		assert.Nil(t, fe.Flush())
		receiveUntilReadyForQuery(t, c, fe)
	})

	db, err := sql.Open("postgres", fmt.Sprintf("postgres://postgres:postgres@localhost:%d/postgres?sslmode=disable", ts.port))
	assert.Nil(t, err)
	t.Cleanup(func() {
		db.Close()
	})

	stmt, err := db.PrepareContext(ctx, fmt.Sprintf("INSERT INTO %s VALUES ($1)", table))
	assert.Nil(t, err, "%+v", err)
	t.Cleanup(func() {
		stmt.Close()
	})

	{
		_, err := stmt.ExecContext(ctx, 1)
		assert.Nil(t, err, "%+v", err)
	}

	longName := strings.Repeat("a", maxStatementNameLen)

	for i, name := range []string{"s1", "s2", "s3", "", longName + "1"} {
		sendMessages(&pgproto3.Parse{
			Name:  name,
			Query: fmt.Sprintf("INSERT INTO %s VALUES (%d)", table, i+2),
		}, &pgproto3.Sync{})
		msgs := receiveUntilReadyForQuery(t, c, fe)
		assert.Empty(t, errorResponseCodes(msgs...))
	}

	{
		sendMessages(&pgproto3.Parse{Name: "select", Query: "SELECT 1"}, &pgproto3.Sync{})
		msgs := receiveUntilReadyForQuery(t, c, fe)
		assert.Empty(t, errorResponseCodes(msgs...))
	}

	setRules(denyInsert, allowAll)

	{
		_, err := stmt.ExecContext(ctx, 10)
		assert.NotNil(t, err)
		assert.Contains(t, err.Error(), "Octelium: Unauthorized")
	}

	for _, name := range []string{"s1", "", longName + "2", "nonexistent"} {
		msgs, _ := execute(name)
		assert.Len(t, msgs, 2, name)
		assert.Equal(t, []string{"42501"}, errorResponseCodes(msgs...), name)
		assert.Equal(t, byte('I'), readyForQueryTxStatus(msgs...))
	}

	{
		msgs, value := execute("select")
		assert.Empty(t, errorResponseCodes(msgs...))
		assert.Equal(t, "1", value)
	}

	{
		sendMessages(&pgproto3.Parse{Name: "s2", Query: "SELECT 2"}, &pgproto3.Sync{})
		msgs := receiveUntilReadyForQuery(t, c, fe)
		assert.Equal(t, []string{"42P05"}, errorResponseCodes(msgs...))

		msgs, _ = execute("s2")
		assert.Equal(t, []string{"42501"}, errorResponseCodes(msgs...))
	}

	{
		sendMessages(&pgproto3.Parse{Query: "SELEC"},
			&pgproto3.Close{ObjectType: 'S', Name: "s3"}, &pgproto3.Sync{})
		msgs := receiveUntilReadyForQuery(t, c, fe)
		assert.Equal(t, []string{"42601"}, errorResponseCodes(msgs...))

		sendMessages(&pgproto3.Parse{Name: "s3", Query: "SELECT 3"}, &pgproto3.Sync{})
		msgs = receiveUntilReadyForQuery(t, c, fe)
		assert.Equal(t, []string{"42P05"}, errorResponseCodes(msgs...))

		msgs, _ = execute("s3")
		assert.Equal(t, []string{"42501"}, errorResponseCodes(msgs...))
	}

	{
		sendMessages(&pgproto3.Close{ObjectType: 'S', Name: "s1"}, &pgproto3.Sync{})
		msgs := receiveUntilReadyForQuery(t, c, fe)
		assert.Empty(t, errorResponseCodes(msgs...))

		sendMessages(&pgproto3.Parse{Name: "s1", Query: "SELECT 5"}, &pgproto3.Sync{})
		msgs = receiveUntilReadyForQuery(t, c, fe)
		assert.Empty(t, errorResponseCodes(msgs...))

		msgs, value := execute("s1")
		assert.Empty(t, errorResponseCodes(msgs...))
		assert.Equal(t, "5", value)
	}

	setRules(allowAll)

	{
		_, err := stmt.ExecContext(ctx, 10)
		assert.Nil(t, err, "%+v", err)

		msgs, _ := execute(longName + "2")
		assert.Empty(t, errorResponseCodes(msgs...))

		msgs, _ = execute("s2")
		assert.Equal(t, []string{"42501"}, errorResponseCodes(msgs...))
	}

	assert.Equal(t, "1,6,10", receiveQueryValue(t, c, fe,
		fmt.Sprintf("SELECT string_agg(id::text, ',' ORDER BY id) FROM %s;", table)))
}

func TestFunctionCall(t *testing.T) {
	ctx := context.Background()

	tst, err := tests.Initialize(nil)
	assert.Nil(t, err, "%+v", err)
	t.Cleanup(func() {
		tst.Destroy()
	})

	ts := newTestPostgresServer(t, ctx, tst, []*corev1.Policy_Spec_Rule{
		{
			Effect: corev1.Policy_Spec_Rule_ALLOW,
			Condition: &corev1.Condition{
				Type: &corev1.Condition_MatchAny{
					MatchAny: true,
				},
			},
		},
	}, &corev1.Service_Spec_Config_Postgres_Authorization{
		Mode: corev1.Service_Spec_Config_Postgres_Authorization_ALL,
	})

	{
		fe, c, _ := newTestFrontend(t, ts.port)
		defer c.Close()

		oid := receiveFunctionOID(t, c, fe, "pg_backend_pid")

		fe.Send(&pgproto3.FunctionCall{Function: oid})
		assert.Nil(t, fe.Flush())

		msgs := receiveUntilReadyForQuery(t, c, fe)
		assert.Len(t, msgs, 2)
		assert.Equal(t, "42501", errorResponseCode(msgs...))

		fe.Send(&pgproto3.Query{String: "SELECT 1;"})
		assert.Nil(t, fe.Flush())

		msgs = receiveUntilReadyForQuery(t, c, fe)
		assert.Empty(t, errorResponseCode(msgs...))
		assert.Len(t, msgs, 4)
	}

	ts.svc.Spec.Config.GetPostgres().Authorization = nil
	ts.svc, err = tst.C.OcteliumC.CoreC().UpdateService(ctx, ts.svc)
	assert.Nil(t, err)
	ts.vCache.SetService(ts.svc)

	{
		fe, c, _ := newTestFrontend(t, ts.port)
		defer c.Close()

		oid := receiveFunctionOID(t, c, fe, "pg_backend_pid")

		fe.Send(&pgproto3.FunctionCall{Function: oid})
		assert.Nil(t, fe.Flush())

		msgs := receiveUntilReadyForQuery(t, c, fe)
		assert.Empty(t, errorResponseCode(msgs...))
		assert.Len(t, msgs, 2)
	}
}

func TestAuthorizationAccessLog(t *testing.T) {
	ctx := context.Background()

	records := newPostgresLogRecorder(t, func(logE *corev1.AccessLog) bool {
		switch logE.Entry.Info.GetPostgres().GetType() {
		case corev1.AccessLog_Entry_Info_Postgres_QUERY,
			corev1.AccessLog_Entry_Info_Postgres_PARSE,
			corev1.AccessLog_Entry_Info_Postgres_BIND,
			corev1.AccessLog_Entry_Info_Postgres_EXECUTE,
			corev1.AccessLog_Entry_Info_Postgres_FUNCTION_CALL:
			return true
		default:
			return false
		}
	})

	tst, err := tests.Initialize(nil)
	assert.Nil(t, err, "%+v", err)
	t.Cleanup(func() {
		tst.Destroy()
	})

	ts := newTestPostgresServer(t, ctx, tst, []*corev1.Policy_Spec_Rule{
		{
			Condition: &corev1.Condition{
				Type: &corev1.Condition_Match{
					Match: `ctx.request.postgres.query.query.startsWith("UPDATE")`,
				},
			},
			Effect: corev1.Policy_Spec_Rule_DENY,
		},
		{
			Condition: &corev1.Condition{
				Type: &corev1.Condition_Match{
					Match: `ctx.request.postgres.parse.query.startsWith("UPDATE")`,
				},
			},
			Effect: corev1.Policy_Spec_Rule_DENY,
		},
		{
			Effect: corev1.Policy_Spec_Rule_ALLOW,
			Condition: &corev1.Condition{
				Type: &corev1.Condition_MatchAny{
					MatchAny: true,
				},
			},
		},
	}, &corev1.Service_Spec_Config_Postgres_Authorization{
		Mode: corev1.Service_Spec_Config_Postgres_Authorization_ALL,
	})

	fe, c, _ := newTestFrontend(t, ts.port)
	defer c.Close()

	assertLog := func(typ corev1.AccessLog_Entry_Info_Postgres_Type,
		status corev1.AccessLog_Entry_Common_Status,
		reason corev1.AccessLog_Entry_Common_Reason_Type) *corev1.AccessLog_Entry_Info_Postgres {
		t.Helper()
		logE := nextPostgresLog(t, records)
		assert.Equal(t, typ, logE.Entry.Info.GetPostgres().Type)
		assert.Equal(t, status, logE.Entry.Common.Status)
		assert.Equal(t, reason, logE.Entry.Common.Reason.GetType())
		return logE.Entry.Info.GetPostgres()
	}

	{
		fe.Send(&pgproto3.Query{String: "UPDATE octelium_nonexistent SET status = 'inactive';"})
		assert.Nil(t, fe.Flush())

		msgs := receiveUntilReadyForQuery(t, c, fe)
		assert.Equal(t, "42501", errorResponseCode(msgs...))

		info := assertLog(corev1.AccessLog_Entry_Info_Postgres_QUERY,
			corev1.AccessLog_Entry_Common_DENIED, corev1.AccessLog_Entry_Common_Reason_POLICY_MATCH)
		assert.Equal(t, "UPDATE octelium_nonexistent SET status = 'inactive';", info.GetQuery().Query)
	}

	{
		fe.Send(&pgproto3.Query{String: "SELECT 1;"})
		assert.Nil(t, fe.Flush())

		msgs := receiveUntilReadyForQuery(t, c, fe)
		assert.Empty(t, errorResponseCode(msgs...))

		info := assertLog(corev1.AccessLog_Entry_Info_Postgres_QUERY,
			corev1.AccessLog_Entry_Common_ALLOWED, corev1.AccessLog_Entry_Common_Reason_POLICY_MATCH)
		assert.Equal(t, "SELECT 1;", info.GetQuery().Query)
	}

	{
		fe.Send(&pgproto3.Parse{Name: "upd", Query: "UPDATE octelium_nonexistent SET status = $1"})
		fe.Send(&pgproto3.Describe{ObjectType: 'S', Name: "upd"})
		fe.Send(&pgproto3.Sync{})
		assert.Nil(t, fe.Flush())

		msgs := receiveUntilReadyForQuery(t, c, fe)
		assert.Equal(t, []string{"42501"}, errorResponseCodes(msgs...))

		info := assertLog(corev1.AccessLog_Entry_Info_Postgres_PARSE,
			corev1.AccessLog_Entry_Common_DENIED, corev1.AccessLog_Entry_Common_Reason_POLICY_MATCH)
		assert.Equal(t, "upd", info.GetParse().Name)
		assert.Equal(t, "UPDATE octelium_nonexistent SET status = $1", info.GetParse().Query)
	}

	{
		fe.Send(&pgproto3.Bind{PreparedStatement: "upd"})
		fe.Send(&pgproto3.Execute{})
		fe.Send(&pgproto3.Sync{})
		assert.Nil(t, fe.Flush())

		msgs := receiveUntilReadyForQuery(t, c, fe)
		assert.Equal(t, []string{"42501"}, errorResponseCodes(msgs...))

		assertLog(corev1.AccessLog_Entry_Info_Postgres_BIND,
			corev1.AccessLog_Entry_Common_DENIED, corev1.AccessLog_Entry_Common_Reason_NO_POLICY_MATCH)
	}

	{
		oid := receiveFunctionOID(t, c, fe, "pg_backend_pid")
		assertLog(corev1.AccessLog_Entry_Info_Postgres_QUERY,
			corev1.AccessLog_Entry_Common_ALLOWED, corev1.AccessLog_Entry_Common_Reason_POLICY_MATCH)

		fe.Send(&pgproto3.FunctionCall{Function: oid})
		assert.Nil(t, fe.Flush())

		msgs := receiveUntilReadyForQuery(t, c, fe)
		assert.Equal(t, "42501", errorResponseCode(msgs...))

		assertLog(corev1.AccessLog_Entry_Info_Postgres_FUNCTION_CALL,
			corev1.AccessLog_Entry_Common_DENIED, corev1.AccessLog_Entry_Common_Reason_NO_POLICY_MATCH)
	}

	{
		fe.Send(&pgproto3.Parse{Query: "SELECT 1"})
		fe.Send(&pgproto3.Bind{})
		fe.Send(&pgproto3.Execute{})
		fe.Send(&pgproto3.Sync{})
		assert.Nil(t, fe.Flush())

		msgs := receiveUntilReadyForQuery(t, c, fe)
		assert.Empty(t, errorResponseCode(msgs...))

		for _, typ := range []corev1.AccessLog_Entry_Info_Postgres_Type{
			corev1.AccessLog_Entry_Info_Postgres_PARSE,
			corev1.AccessLog_Entry_Info_Postgres_BIND,
			corev1.AccessLog_Entry_Info_Postgres_EXECUTE,
		} {
			assertLog(typ, corev1.AccessLog_Entry_Common_ALLOWED,
				corev1.AccessLog_Entry_Common_Reason_POLICY_MATCH)
		}
	}

	select {
	case logE := <-records:
		t.Fatalf("unexpected access log: %+v", logE)
	default:
	}
}

func TestMaxMessageBodyLen(t *testing.T) {
	ctx := context.Background()

	tst, err := tests.Initialize(nil)
	assert.Nil(t, err, "%+v", err)
	t.Cleanup(func() {
		tst.Destroy()
	})

	ts := newTestPostgresServer(t, ctx, tst, []*corev1.Policy_Spec_Rule{
		{
			Effect: corev1.Policy_Spec_Rule_ALLOW,
			Condition: &corev1.Condition{
				Type: &corev1.Condition_MatchAny{
					MatchAny: true,
				},
			},
		},
	}, nil)

	{
		_, c, _ := newTestFrontend(t, ts.port)
		defer c.Close()

		header := make([]byte, 5)
		header[0] = 'Q'
		binary.BigEndian.PutUint32(header[1:], uint32(maxMessageBodyLen)+64)
		_, err := c.Write(header)
		assert.Nil(t, err, "%+v", err)

		assertClosedByServer(t, c)
	}

	{
		fe, c, _ := newTestFrontend(t, ts.port)
		defer c.Close()

		fe.Send(&pgproto3.Query{String: fmt.Sprintf("SELECT repeat('x', %d);",
			maxMessageBodyLen+1024*1024)})
		assert.Nil(t, fe.Flush())

		assertClosedByServer(t, c)
	}
}

func TestCancelRequest(t *testing.T) {
	ctx := context.Background()

	tst, err := tests.Initialize(nil)
	assert.Nil(t, err, "%+v", err)
	t.Cleanup(func() {
		tst.Destroy()
	})

	ts := newTestPostgresServer(t, ctx, tst, []*corev1.Policy_Spec_Rule{
		{
			Effect: corev1.Policy_Spec_Rule_ALLOW,
			Condition: &corev1.Condition{
				Type: &corev1.Condition_MatchAny{
					MatchAny: true,
				},
			},
		},
	}, nil)

	fe, c, keyData := newTestFrontend(t, ts.port)
	defer c.Close()

	assert.Len(t, keyData.SecretKey, 4)

	{
		upstreamPID := receiveQueryValue(t, c, fe, "SELECT pg_backend_pid();")
		assert.NotEmpty(t, upstreamPID)
		assert.NotEqual(t, upstreamPID, fmt.Sprintf("%d", keyData.ProcessID))
	}

	{
		fe.Send(&pgproto3.Query{String: "SELECT pg_sleep(30);"})
		assert.Nil(t, fe.Flush())

		time.Sleep(1 * time.Second)
		sendCancelRequest(t, ts.port, keyData)

		msgs := receiveUntilReadyForQuery(t, c, fe)
		assert.Equal(t, "57014", errorResponseCode(msgs...))
	}

	{
		fe.Send(&pgproto3.Query{String: "SELECT pg_sleep(1);"})
		assert.Nil(t, fe.Flush())

		sendCancelRequest(t, ts.port, &pgproto3.BackendKeyData{
			ProcessID: keyData.ProcessID + 1,
			SecretKey: []byte("octe"),
		})

		msgs := receiveUntilReadyForQuery(t, c, fe)
		assert.Empty(t, errorResponseCode(msgs...))
	}
}

type failingWriter struct{}

func (w failingWriter) Write(p []byte) (int, error) {
	return 0, io.ErrClosedPipe
}

func findSumDataPointByStage(t *testing.T, rm *metricdata.ResourceMetrics, name, stage string) (metricdata.DataPoint[int64], bool) {
	for _, sm := range rm.ScopeMetrics {
		for _, m := range sm.Metrics {
			if m.Name != name {
				continue
			}
			sum, ok := m.Data.(metricdata.Sum[int64])
			assert.True(t, ok, name)
			for _, dp := range sum.DataPoints {
				stageVal, ok := dp.Attributes.Value("stage")
				if ok && stageVal.AsString() == stage {
					return dp, true
				}
			}
		}
	}
	return metricdata.DataPoint[int64]{}, false
}

func TestConnectFailureReleasesUpstream(t *testing.T) {
	ctx := t.Context()

	tst, err := tests.Initialize(nil)
	require.Nil(t, err)
	t.Cleanup(func() { tst.Destroy() })

	ts := newTestPostgresServer(t, ctx, tst, []*corev1.Policy_Spec_Rule{
		{
			Effect: corev1.Policy_Spec_Rule_ALLOW,
			Condition: &corev1.Condition{
				Type: &corev1.Condition_MatchAny{MatchAny: true},
			},
		},
	}, nil)

	db, err := sql.Open("postgres", "postgres://postgres:postgres@localhost:5432/postgres?sslmode=disable")
	require.Nil(t, err)
	defer db.Close()

	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	svc := ts.vCache.GetService()
	reqCtx := &corev1.RequestContext{
		Service: svc,
		Session: &corev1.Session{
			Metadata: &metav1.Metadata{
				Uid: utilrand.GetRandomStringCanonical(8),
			},
		},
	}

	cc := newCountingConn(server)
	dctx := newDctx(ctx, cc, reqCtx, ts.srv.secretMan,
		pgproto3.NewBackend(cc, failingWriter{}),
		&pgproto3.StartupMessage{
			ProtocolVersion: pgproto3.ProtocolVersionNumber,
			Parameters: map[string]string{
				"user":     "postgres",
				"database": "postgres",
			},
		},
		ts.srv.octovigilC, ts.vCache, ts.srv.cancelKeys,
		cc, ts.srv.metricsStore.CommonMetrics, ts.srv.metricsStore.dbMetrics,
		&coctovigilv1.AuthenticateAndAuthorizeResponse{
			RequestContext: reqCtx,
		}, nil)

	err = dctx.connect(ctx, ts.srv.lbManager, svc, ts.srv.secretMan)
	require.True(t, errors.Is(err, io.ErrClosedPipe), "%+v", err)
	require.NotNil(t, dctx.upstreamHijackedConn)
	require.NotZero(t, dctx.upstreamHijackedConn.PID)

	assert.Nil(t, ts.srv.cancelKeys.get(dctx.cancelKey))
	assert.Empty(t, ts.srv.cancelKeys.targets)

	dctx.upstreamHijackedConn.Conn.SetReadDeadline(time.Now().Add(1 * time.Second))
	_, err = dctx.upstreamHijackedConn.Conn.Read(make([]byte, 1))
	assert.True(t, errors.Is(err, net.ErrClosed), "%+v", err)

	assert.Eventually(t, func() bool {
		var count int
		if err := db.QueryRowContext(ctx, "SELECT count(*) FROM pg_stat_activity WHERE pid = $1",
			dctx.upstreamHijackedConn.PID).Scan(&count); err != nil {
			return false
		}
		return count == 0
	}, 5*time.Second, 50*time.Millisecond)
}

func TestStartupClientResetReleasesUpstream(t *testing.T) {
	ctx := t.Context()

	metricsReader := setTestMeterProvider(t)

	tst, err := tests.Initialize(nil)
	require.Nil(t, err)
	t.Cleanup(func() { tst.Destroy() })

	ts := newTestPostgresServer(t, ctx, tst, []*corev1.Policy_Spec_Rule{
		{
			Effect: corev1.Policy_Spec_Rule_ALLOW,
			Condition: &corev1.Condition{
				Type: &corev1.Condition_MatchAny{MatchAny: true},
			},
		},
	}, nil)

	for range 4 {
		c, err := net.Dial("tcp", fmt.Sprintf("localhost:%d", ts.port))
		require.Nil(t, err)

		fe := pgproto3.NewFrontend(c, c)
		fe.Send(&pgproto3.StartupMessage{
			ProtocolVersion: pgproto3.ProtocolVersionNumber,
			Parameters: map[string]string{
				"user":     "postgres",
				"database": "postgres",
			},
		})
		require.Nil(t, fe.Flush())

		require.Nil(t, c.(*net.TCPConn).SetLinger(0))
		require.Nil(t, c.Close())
	}

	require.Eventually(t, func() bool {
		var rm metricdata.ResourceMetrics
		if err := metricsReader.Collect(ctx, &rm); err != nil {
			return false
		}
		dp, found := findSumDataPointByStage(t, &rm, "conn.rejected", "UPSTREAM_DIAL")
		return found && dp.Value == 4
	}, 10*time.Second, 50*time.Millisecond)

	ts.srv.cancelKeys.mu.Lock()
	defer ts.srv.cancelKeys.mu.Unlock()
	assert.Empty(t, ts.srv.cancelKeys.targets)
}
