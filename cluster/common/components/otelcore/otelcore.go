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

package otelcore

import (
	"context"
	"encoding/base64"
	"time"

	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/apis/main/metav1"
	"github.com/octelium/octelium/cluster/common/components"
	"github.com/octelium/octelium/cluster/common/vutils"
	"github.com/octelium/octelium/pkg/apiutils/ucorev1"
	"github.com/octelium/octelium/pkg/common/pbutils"
	"go.opentelemetry.io/otel/log"
	"go.uber.org/zap/zapcore"
	"google.golang.org/protobuf/types/known/structpb"
)

func NewOTELCore(logger log.Logger) zapcore.Core {

	return &otelCore{
		logger: logger,
	}
}

type otelCore struct {
	logger log.Logger
}

func (c *otelCore) Enabled(zapcore.Level) bool {
	return true
}

func (c *otelCore) With(fs []zapcore.Field) zapcore.Core {
	return nil
}

func (c *otelCore) Check(ent zapcore.Entry, ce *zapcore.CheckedEntry) *zapcore.CheckedEntry {
	if c.Enabled(ent.Level) {
		return ce.AddCore(ent, c)
	}
	return ce
}

func (c *otelCore) Write(ent zapcore.Entry, fields []zapcore.Field) error {
	rec := log.Record{}
	lr := &corev1.ComponentLog{
		ApiVersion: ucorev1.APIVersion,
		Kind:       ucorev1.KindComponentLog,
		Metadata: &metav1.LogMetadata{
			Id:        vutils.GenerateLogID(),
			CreatedAt: pbutils.Now(),
		},
		Entry: &corev1.ComponentLog_Entry{
			Level:   c.getLevel(ent.Level),
			Message: ent.Message,
			Time:    pbutils.Timestamp(ent.Time.UTC()),
			Component: &corev1.ComponentLog_Entry_Component{
				Uid:       components.MyComponentUID(),
				Namespace: components.MyComponentNamespace(),
				Type:      components.MyComponentType(),
			},
			Function: ent.Caller.Function,
			Line:     int32(ent.Caller.Line),
			File:     ent.Caller.File,
			Fields:   c.getFields(fields),
		},
	}

	lrJSON, err := pbutils.MarshalJSON(lr, false)
	if err != nil {
		return err
	}

	rec.SetBody(log.StringValue(string(lrJSON)))
	rec.SetTimestamp(ent.Time)
	rec.SetObservedTimestamp(pbutils.Now().AsTime())
	rec.SetSeverity(log.Severity(ent.Level))
	rec.SetSeverityText(ent.Level.String())

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	c.logger.Emit(ctx, rec)
	return nil
}

func (c *otelCore) getLevel(l zapcore.Level) corev1.ComponentLog_Entry_Level {
	switch l {
	case zapcore.DebugLevel:
		return corev1.ComponentLog_Entry_DEBUG
	case zapcore.FatalLevel:
		return corev1.ComponentLog_Entry_FATAL
	case zapcore.ErrorLevel:
		return corev1.ComponentLog_Entry_ERROR
	case zapcore.InfoLevel:
		return corev1.ComponentLog_Entry_INFO
	case zapcore.DPanicLevel:
		return corev1.ComponentLog_Entry_PANIC
	default:
		return corev1.ComponentLog_Entry_LEVEL_UNSET
	}
}

func (c *otelCore) getFields(fields []zapcore.Field) *structpb.Struct {

	if len(fields) < 1 {
		return nil
	}

	ret := &structpb.Struct{
		Fields: map[string]*structpb.Value{},
	}

	for _, f := range fields {

		switch f.Type {
		case zapcore.ErrorType:
			ret.Fields[f.Key] = &structpb.Value{
				Kind: &structpb.Value_StringValue{
					StringValue: f.Interface.(error).Error(),
				},
			}
		case zapcore.StringType:
			ret.Fields[f.Key] = &structpb.Value{
				Kind: &structpb.Value_StringValue{
					StringValue: f.String,
				},
			}

		case zapcore.BinaryType:

			ret.Fields[f.Key] = &structpb.Value{
				Kind: &structpb.Value_StringValue{
					StringValue: base64.StdEncoding.EncodeToString(f.Interface.([]byte)),
				},
			}
		case zapcore.BoolType:

			ret.Fields[f.Key] = &structpb.Value{
				Kind: &structpb.Value_BoolValue{
					BoolValue: f.Integer == 1,
				},
			}
		case zapcore.ByteStringType:
			ret.Fields[f.Key] = &structpb.Value{
				Kind: &structpb.Value_StringValue{
					StringValue: base64.StdEncoding.EncodeToString(f.Interface.([]byte)),
				},
			}

		case zapcore.Int64Type, zapcore.Int32Type, zapcore.Int16Type,
			zapcore.Int8Type, zapcore.Float32Type, zapcore.Float64Type,
			zapcore.Uint64Type, zapcore.Uint32Type, zapcore.Uint16Type,
			zapcore.Uint8Type, zapcore.DurationType:
			ret.Fields[f.Key] = &structpb.Value{
				Kind: &structpb.Value_NumberValue{
					NumberValue: float64(f.Integer),
				},
			}

		case zapcore.TimeType:
			if f.Interface != nil {

				ret.Fields[f.Key] = &structpb.Value{
					Kind: &structpb.Value_StringValue{
						StringValue: time.Unix(0, f.Integer).
							In(f.Interface.(*time.Location)).UTC().Format(time.RFC3339Nano),
					},
				}
			} else {
				ret.Fields[f.Key] = &structpb.Value{
					Kind: &structpb.Value_StringValue{
						StringValue: time.Unix(0, f.Integer).UTC().Format(time.RFC3339Nano),
					},
				}
			}

		case zapcore.TimeFullType:

			ret.Fields[f.Key] = &structpb.Value{
				Kind: &structpb.Value_StringValue{
					StringValue: f.Interface.(time.Time).UTC().Format(time.RFC3339Nano),
				},
			}
		default:
			if msg, ok := f.Interface.(pbutils.Message); ok {
				if jsn, err := pbutils.MarshalJSON(msg, false); err == nil {
					ret.Fields[f.Key] = &structpb.Value{
						Kind: &structpb.Value_StringValue{
							StringValue: string(jsn),
						},
					}
				}
			}
		}
	}

	return ret
}

func (c *otelCore) Sync() error {
	return nil
}
