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

package otelutils

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/log"
	sdklog "go.opentelemetry.io/otel/sdk/log"
)

type testLogExporter struct {
	records    chan sdklog.Record
	batchSizes chan int
	err        error
	stopped    atomic.Bool
}

func (e *testLogExporter) Export(ctx context.Context, records []sdklog.Record) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if e.stopped.Load() {
		return sdklog.ErrExporterShutdown
	}
	if len(records) == 0 {
		return nil
	}
	if e.err != nil {
		return e.err
	}
	e.batchSizes <- len(records)
	for _, record := range records {
		e.records <- record.Clone()
	}
	return nil
}

func (e *testLogExporter) ForceFlush(context.Context) error {
	return nil
}

func (e *testLogExporter) Shutdown(context.Context) error {
	e.stopped.Store(true)
	return nil
}

func TestLoggerProviderLifecycle(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()

	resource, err := getResource(ctx)
	require.Nil(t, err)
	exporter := &testLogExporter{
		records:    make(chan sdklog.Record, 16),
		batchSizes: make(chan int, 16),
	}
	provider := sdklog.NewLoggerProvider(
		sdklog.WithResource(resource),
		sdklog.WithProcessor(sdklog.NewBatchProcessor(exporter,
			sdklog.WithMaxQueueSize(16), sdklog.WithExportMaxBatchSize(4),
			sdklog.WithExportInterval(time.Hour))),
	)
	previous := otel.GetLoggerProvider()
	otel.SetLoggerProvider(provider)
	t.Cleanup(func() {
		otel.SetLoggerProvider(previous)
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		assert.Nil(t, provider.Shutdown(ctx))
	})

	now := time.Now()
	for i := range 6 {
		record := log.Record{}
		record.SetTimestamp(now)
		record.SetSeverity(log.SeverityInfo)
		record.SetBody(attribute.MapValue(attribute.String("message", "exported")))
		record.AddAttributes(attribute.Int("sequence", i))
		GetLogger().Emit(ctx, record)
	}
	require.Nil(t, provider.ForceFlush(ctx))
	require.Len(t, exporter.records, 6)

	seen := map[int64]bool{}
	for range 6 {
		record := <-exporter.records
		assert.Equal(t, now, record.Timestamp())
		assert.Equal(t, log.SeverityInfo, record.Severity())
		assert.Equal(t, attribute.MapValue(attribute.String("message", "exported")), record.Body())
		assert.True(t, resource.Equal(record.Resource()))
		value, ok := record.Resource().Set().Value("service.name")
		assert.True(t, ok)
		assert.Equal(t, "octelium", value.AsString())
		assert.Equal(t, "default", record.InstrumentationScope().Name)
		require.Equal(t, 1, record.AttributesLen())
		record.WalkAttributes(func(kv attribute.KeyValue) bool {
			assert.Equal(t, attribute.Key("sequence"), kv.Key)
			assert.False(t, seen[kv.Value.AsInt64()])
			seen[kv.Value.AsInt64()] = true
			return true
		})
	}
	for i := range 6 {
		assert.True(t, seen[int64(i)])
	}

	for range 3 {
		record := log.Record{}
		record.SetBody(attribute.StringValue("shutdown"))
		GetLogger().Emit(ctx, record)
	}
	require.Nil(t, provider.Shutdown(ctx))
	assert.True(t, exporter.stopped.Load())
	require.Len(t, exporter.records, 3)
	for range 3 {
		record := <-exporter.records
		assert.Equal(t, "shutdown", record.Body().AsString())
	}
	for len(exporter.batchSizes) > 0 {
		assert.LessOrEqual(t, <-exporter.batchSizes, 4)
	}
	GetLogger().Emit(ctx, log.Record{})
	assert.Empty(t, exporter.records)
}

func TestLoggerProviderExportError(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()

	want := errors.New("export failed")
	exporter := &testLogExporter{err: want}
	provider := sdklog.NewLoggerProvider(sdklog.WithProcessor(sdklog.NewBatchProcessor(
		exporter, sdklog.WithExportInterval(time.Hour))))
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		assert.Nil(t, provider.Shutdown(ctx))
	})
	provider.Logger("default").Emit(ctx, log.Record{})
	assert.ErrorIs(t, provider.ForceFlush(ctx), want)

	canceled, cancel := context.WithCancel(ctx)
	cancel()
	assert.ErrorIs(t, provider.ForceFlush(canceled), context.Canceled)
}
