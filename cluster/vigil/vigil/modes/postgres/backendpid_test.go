package postgres

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"strconv"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgproto3"
	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/cluster/common/tests"
	"github.com/octelium/octelium/pkg/common/pbutils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/log/global"
	sdklog "go.opentelemetry.io/otel/sdk/log"
)

type tstPostgresStartLogProcessor struct {
	records chan *corev1.AccessLog
}

func (p *tstPostgresStartLogProcessor) Enabled(ctx context.Context, param sdklog.EnabledParameters) bool {
	return true
}

func (p *tstPostgresStartLogProcessor) OnEmit(ctx context.Context, record *sdklog.Record) error {
	for _, field := range record.Body().AsMap() {
		if field.Key == "kind" && field.Value.AsString() == "AccessLog" {
			logE := &corev1.AccessLog{}
			if err := pbutils.UnmarshalJSONStrict([]byte(record.Body().String()), logE); err != nil {
				return err
			}
			if logE.Entry.Info.GetPostgres().GetType() == corev1.AccessLog_Entry_Info_Postgres_SESSION_START {
				p.records <- logE
			}
			break
		}
	}
	return nil
}

func (p *tstPostgresStartLogProcessor) Shutdown(ctx context.Context) error {
	return nil
}

func (p *tstPostgresStartLogProcessor) ForceFlush(ctx context.Context) error {
	return nil
}

func newPostgresStartLogRecorder(t *testing.T) <-chan *corev1.AccessLog {
	t.Helper()
	previous := global.GetLoggerProvider()
	processor := &tstPostgresStartLogProcessor{records: make(chan *corev1.AccessLog, 8)}
	provider := sdklog.NewLoggerProvider(sdklog.WithProcessor(processor))
	global.SetLoggerProvider(provider)
	t.Cleanup(func() {
		global.SetLoggerProvider(previous)
		assert.Nil(t, provider.Shutdown(context.Background()))
	})
	return processor.records
}

func nextPostgresStartLog(t *testing.T, records <-chan *corev1.AccessLog) *corev1.AccessLog {
	t.Helper()
	select {
	case logE := <-records:
		return logE
	case <-time.After(5 * time.Second):
		t.Fatal("Timed out waiting for a PostgreSQL session start log")
		return nil
	}
}

func TestSessionStartBackendPID(t *testing.T) {
	ctx := t.Context()
	records := newPostgresStartLogRecorder(t)
	tst, err := tests.Initialize(nil)
	require.Nil(t, err)
	t.Cleanup(func() { tst.Destroy() })
	srv := newTestPostgresServer(t, ctx, tst, []*corev1.Policy_Spec_Rule{
		{
			Effect: corev1.Policy_Spec_Rule_ALLOW,
			Condition: &corev1.Condition{
				Type: &corev1.Condition_MatchAny{MatchAny: true},
			},
		},
	}, nil)

	var pids []uint32
	var connectionIDs []string
	for range 2 {
		frontend, conn, keyData := newTestFrontend(t, srv.port)
		defer conn.Close()
		logE := nextPostgresStartLog(t, records)
		require.Equal(t, corev1.AccessLog_Entry_Common_ALLOWED, logE.Entry.Common.Status)
		start := logE.Entry.Info.GetPostgres().GetStart()
		require.NotNil(t, start)
		require.NotZero(t, start.BackendPID)
		assert.Equal(t, "postgres", start.User)
		assert.Equal(t, "postgres", start.Database)
		assert.NotEqual(t, keyData.ProcessID, start.BackendPID)
		actualPID, err := strconv.ParseUint(receiveQueryValue(t, conn, frontend, "SELECT pg_backend_pid();"), 10, 32)
		require.Nil(t, err)
		assert.Equal(t, uint32(actualPID), start.BackendPID)
		require.NotEmpty(t, logE.Entry.Common.ConnectionID)
		pids = append(pids, start.BackendPID)
		connectionIDs = append(connectionIDs, logE.Entry.Common.ConnectionID)

		data, err := pbutils.MarshalJSON(logE, false)
		require.Nil(t, err)
		var body map[string]any
		require.Nil(t, json.Unmarshal(data, &body))
		entry := body["entry"].(map[string]any)
		info := entry["info"].(map[string]any)
		postgres := info["postgres"].(map[string]any)
		assert.Equal(t, float64(actualPID), postgres["start"].(map[string]any)["backendPID"])
		assert.NotContains(t, string(data), "secretKey")
	}
	assert.NotEqual(t, pids[0], pids[1])
	assert.NotEqual(t, connectionIDs[0], connectionIDs[1])
}

func TestSessionStartBackendPIDDenied(t *testing.T) {
	ctx := t.Context()
	records := newPostgresStartLogRecorder(t)
	tst, err := tests.Initialize(nil)
	require.Nil(t, err)
	t.Cleanup(func() { tst.Destroy() })
	srv := newTestPostgresServer(t, ctx, tst, []*corev1.Policy_Spec_Rule{
		{
			Effect: corev1.Policy_Spec_Rule_DENY,
			Condition: &corev1.Condition{
				Type: &corev1.Condition_MatchAny{MatchAny: true},
			},
		},
	}, nil)
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("localhost:%d", srv.port), time.Second)
	require.Nil(t, err)
	defer conn.Close()
	frontend := pgproto3.NewFrontend(conn, conn)
	frontend.Send(&pgproto3.StartupMessage{
		ProtocolVersion: pgproto3.ProtocolVersionNumber,
		Parameters:      map[string]string{"user": "postgres", "database": "postgres"},
	})
	require.Nil(t, frontend.Flush())
	assertClosedByServer(t, conn)
	logE := nextPostgresStartLog(t, records)
	assert.Equal(t, corev1.AccessLog_Entry_Common_DENIED, logE.Entry.Common.Status)
	assert.Nil(t, logE.Entry.Info.GetPostgres().GetStart())
	data, err := pbutils.MarshalJSON(logE, false)
	require.Nil(t, err)
	assert.NotContains(t, string(data), "backendPID")
}
