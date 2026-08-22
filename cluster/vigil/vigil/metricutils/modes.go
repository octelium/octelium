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

package metricutils

import (
	"context"
	"math"
	"time"

	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/cluster/common/otelutils"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
)

type LLMMetrics struct {
	InputTokens      metric.Int64Counter
	OutputTokens     metric.Int64Counter
	CacheReadTokens  metric.Int64Counter
	CacheWriteTokens metric.Int64Counter
	ReasoningTokens  metric.Int64Counter
	TotalTokens      metric.Int64Counter

	TimeToFirstToken metric.Float64Histogram

	StreamEvents metric.Int64Counter

	Models *BoundedValues

	commonAttrs attribute.Set
}

const maxLLMModelValues = 64

var llmTTFTBoundaries = []float64{
	10, 50, 100, 250, 500, 1000, 2000, 5000,
	10000, 20000, 30000, 60000, 120000,
}

func NewLLMMetrics(ctx context.Context, svc *corev1.Service) (*LLMMetrics, error) {
	ret := &LLMMetrics{
		Models:      NewBoundedValues(maxLLMModelValues),
		commonAttrs: GetServiceAttributes(svc),
	}
	var err error

	meter := otelutils.GetMeter()

	ret.InputTokens, err = meter.Int64Counter("llm.tokens.input",
		metric.WithDescription("Total LLM input tokens"))
	if err != nil {
		return nil, err
	}

	ret.OutputTokens, err = meter.Int64Counter("llm.tokens.output",
		metric.WithDescription("Total LLM output tokens"))
	if err != nil {
		return nil, err
	}

	ret.CacheReadTokens, err = meter.Int64Counter("llm.tokens.cache_read",
		metric.WithDescription("Total LLM cache read input tokens"))
	if err != nil {
		return nil, err
	}

	ret.CacheWriteTokens, err = meter.Int64Counter("llm.tokens.cache_write",
		metric.WithDescription("Total LLM cache creation input tokens"))
	if err != nil {
		return nil, err
	}

	ret.ReasoningTokens, err = meter.Int64Counter("llm.tokens.reasoning",
		metric.WithDescription("Total LLM reasoning tokens"))
	if err != nil {
		return nil, err
	}

	ret.TotalTokens, err = meter.Int64Counter("llm.tokens.total",
		metric.WithDescription("Total LLM tokens"))
	if err != nil {
		return nil, err
	}

	ret.TimeToFirstToken, err = meter.Float64Histogram("llm.ttft",
		metric.WithUnit("ms"),
		metric.WithDescription("LLM time to first token in milliseconds"),
		metric.WithExplicitBucketBoundaries(llmTTFTBoundaries...))
	if err != nil {
		return nil, err
	}

	ret.StreamEvents, err = meter.Int64Counter("llm.stream.events",
		metric.WithDescription("Total LLM streamed response events"))
	if err != nil {
		return nil, err
	}

	return ret, nil
}

type LLMUsageOpts struct {
	InputTokens      uint64
	OutputTokens     uint64
	CacheReadTokens  uint64
	CacheWriteTokens uint64
	ReasoningTokens  uint64
	TotalTokens      uint64

	StreamEvents uint64

	TimeToFirstToken time.Duration
}

func (m *LLMMetrics) AddUsage(opts *LLMUsageOpts, attrs metric.MeasurementOption) {
	if opts == nil {
		return
	}

	ctx := context.Background()

	addOpts := []metric.AddOption{metric.WithAttributeSet(m.commonAttrs)}
	if attrs != nil {
		addOpts = append(addOpts, attrs)
	}

	for _, it := range []struct {
		counter metric.Int64Counter
		value   uint64
	}{
		{m.InputTokens, opts.InputTokens},
		{m.OutputTokens, opts.OutputTokens},
		{m.CacheReadTokens, opts.CacheReadTokens},
		{m.CacheWriteTokens, opts.CacheWriteTokens},
		{m.ReasoningTokens, opts.ReasoningTokens},
		{m.TotalTokens, opts.TotalTokens},
		{m.StreamEvents, opts.StreamEvents},
	} {
		if it.value <= math.MaxInt64 {
			it.counter.Add(ctx, int64(it.value), addOpts...)
		}
	}

	if opts.TimeToFirstToken > 0 {
		recordOpts := []metric.RecordOption{metric.WithAttributeSet(m.commonAttrs)}
		if attrs != nil {
			recordOpts = append(recordOpts, attrs)
		}
		m.TimeToFirstToken.Record(ctx,
			float64(opts.TimeToFirstToken.Nanoseconds())/1000000, recordOpts...)
	}
}

type DBMetrics struct {
	CommandTotal  metric.Int64Counter
	AuthzDuration metric.Float64Histogram

	commonAttrs attribute.Set
}

func NewDBMetrics(ctx context.Context, svc *corev1.Service) (*DBMetrics, error) {
	ret := &DBMetrics{
		commonAttrs: GetServiceAttributes(svc),
	}
	var err error

	meter := otelutils.GetMeter()

	ret.CommandTotal, err = meter.Int64Counter("db.command.total",
		metric.WithDescription("Total number of database commands"))
	if err != nil {
		return nil, err
	}

	ret.AuthzDuration, err = meter.Float64Histogram("db.authz.duration",
		metric.WithUnit("ms"),
		metric.WithDescription("Per-command authorization duration in milliseconds"))
	if err != nil {
		return nil, err
	}

	return ret, nil
}

func (m *DBMetrics) AddCommand(command, state, reason string) {
	m.CommandTotal.Add(context.Background(), 1,
		metric.WithAttributeSet(m.commonAttrs),
		metric.WithAttributes(
			attribute.String("db.command", command),
			attribute.String("state", state),
			attribute.String("reason", reason),
		))
}

func (m *DBMetrics) RecordAuthz(startTime time.Time, state string) {
	durationMs := float64(time.Since(startTime).Nanoseconds()) / 1000000

	m.AuthzDuration.Record(context.Background(), durationMs,
		metric.WithAttributeSet(m.commonAttrs),
		metric.WithAttributes(attribute.String("state", state)))
}

type SSHMetrics struct {
	ChannelTotal metric.Int64Counter
	RequestTotal metric.Int64Counter

	commonAttrs attribute.Set
}

func NewSSHMetrics(ctx context.Context, svc *corev1.Service) (*SSHMetrics, error) {
	ret := &SSHMetrics{
		commonAttrs: GetServiceAttributes(svc),
	}
	var err error

	meter := otelutils.GetMeter()

	ret.ChannelTotal, err = meter.Int64Counter("ssh.channel.total",
		metric.WithDescription("Total number of SSH channels"))
	if err != nil {
		return nil, err
	}

	ret.RequestTotal, err = meter.Int64Counter("ssh.request.total",
		metric.WithDescription("Total number of SSH channel requests"))
	if err != nil {
		return nil, err
	}

	return ret, nil
}

func (m *SSHMetrics) AddChannel(channelType, state string) {
	m.ChannelTotal.Add(context.Background(), 1,
		metric.WithAttributeSet(m.commonAttrs),
		metric.WithAttributes(
			attribute.String("ssh.channel.type", channelType),
			attribute.String("state", state),
		))
}

func (m *SSHMetrics) AddRequest(requestType, state, reason string) {
	m.RequestTotal.Add(context.Background(), 1,
		metric.WithAttributeSet(m.commonAttrs),
		metric.WithAttributes(
			attribute.String("ssh.request.type", requestType),
			attribute.String("state", state),
			attribute.String("reason", reason),
		))
}

type DNSMetrics struct {
	MalformedTotal metric.Int64Counter
	ResponseBytes  metric.Int64Histogram

	commonAttrs attribute.Set
}

func NewDNSMetrics(ctx context.Context, svc *corev1.Service) (*DNSMetrics, error) {
	ret := &DNSMetrics{
		commonAttrs: GetServiceAttributes(svc),
	}
	var err error

	meter := otelutils.GetMeter()

	ret.MalformedTotal, err = meter.Int64Counter("dns.malformed.total",
		metric.WithDescription("Total number of malformed DNS queries"))
	if err != nil {
		return nil, err
	}

	ret.ResponseBytes, err = meter.Int64Histogram("dns.response.bytes",
		metric.WithUnit("bytes"),
		metric.WithDescription("DNS response size in bytes"))
	if err != nil {
		return nil, err
	}

	return ret, nil
}

func (m *DNSMetrics) AddMalformed(reason string) {
	m.MalformedTotal.Add(context.Background(), 1,
		metric.WithAttributeSet(m.commonAttrs),
		metric.WithAttributes(attribute.String("reason", reason)))
}

func (m *DNSMetrics) RecordResponseBytes(size int, isTruncated bool) {
	m.ResponseBytes.Record(context.Background(), int64(size),
		metric.WithAttributeSet(m.commonAttrs),
		metric.WithAttributes(attribute.Bool("dns.truncated", isTruncated)))
}
