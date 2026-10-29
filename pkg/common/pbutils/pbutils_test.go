package pbutils

import (
	"testing"
	"time"

	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/apis/main/metav1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/structpb"
	"google.golang.org/protobuf/types/known/timestamppb"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

func TestYAMLRoundTrip(t *testing.T) {
	for _, itm := range []struct {
		name string
		in   proto.Message
		want string
	}{
		{
			name: "resource",
			in: &corev1.Secret{
				ApiVersion: "core/v1",
				Kind:       "Secret",
				Metadata: &metav1.Metadata{
					Name:   "secret1",
					Labels: map[string]string{"enabled": "yes", "port": "8080"},
					Tags:   []string{"one", "two"},
				},
				Spec: &corev1.Secret_Spec{
					Data: &corev1.Secret_Spec_Data{
						Type: &corev1.Secret_Spec_Data_ValueBytes{ValueBytes: []byte("secret")},
					},
				},
			},
			want: `apiVersion: core/v1
kind: Secret
metadata:
  labels:
    enabled: "yes"
    port: "8080"
  name: secret1
  tags:
  - one
  - two
spec:
  data:
    valueBytes: c2VjcmV0
`,
		},
		{name: "int64", in: wrapperspb.Int64(9223372036854775807), want: "\"9223372036854775807\"\n"},
		{name: "uint64", in: wrapperspb.UInt64(18446744073709551615), want: "\"18446744073709551615\"\n"},
		{name: "boolean string", in: wrapperspb.String("on"), want: "\"on\"\n"},
		{name: "boolean", in: wrapperspb.Bool(true), want: "true\n"},
		{name: "enum", in: &corev1.User_Spec{Type: corev1.User_Spec_HUMAN}, want: "type: HUMAN\n"},
		{name: "bytes", in: wrapperspb.Bytes([]byte("secret")), want: "c2VjcmV0\n"},
		{name: "duration", in: durationpb.New(1500 * time.Millisecond), want: "1.500s\n"},
		{name: "timestamp", in: timestamppb.New(time.Date(2026, time.October, 29, 12, 0, 0, 0, time.UTC)), want: "\"2026-10-29T12:00:00Z\"\n"},
		{name: "null", in: structpb.NewNullValue(), want: "null\n"},
	} {
		t.Run(itm.name, func(t *testing.T) {
			out, err := MarshalYAML(itm.in)
			require.NoError(t, err)
			assert.Equal(t, itm.want, string(out))

			ret := itm.in.ProtoReflect().New().Interface()
			require.NoError(t, UnmarshalYAML(out, ret))
			assert.True(t, proto.Equal(itm.in, ret), "%v", ret)
		})
	}
}

func TestUnmarshalYAML(t *testing.T) {
	for _, itm := range []struct {
		name string
		in   string
		want proto.Message
	}{
		{
			name: "unknown fields",
			in:   "kind: Secret\nunknownField: ignored\nmetadata:\n  name: secret1\n  unknownField: ignored\n",
			want: &corev1.Secret{Kind: "Secret", Metadata: &metav1.Metadata{Name: "secret1"}},
		},
		{
			name: "anchors and merge keys",
			in:   "defaults: &defaults\n  name: secret1\nkind: Secret\nmetadata:\n  <<: *defaults\n",
			want: &corev1.Secret{Kind: "Secret", Metadata: &metav1.Metadata{Name: "secret1"}},
		},
		{
			name: "duplicate keys",
			in:   "kind: User\nkind: Secret\n",
			want: &corev1.Secret{Kind: "Secret"},
		},
		{name: "JSON input", in: `{"kind":"Secret"}`, want: &corev1.Secret{Kind: "Secret"}},
		{name: "YAML boolean", in: "yes", want: wrapperspb.Bool(true)},
		{name: "numeric keys", in: "42: value", want: &structpb.Struct{Fields: map[string]*structpb.Value{"42": structpb.NewStringValue("value")}}},
	} {
		t.Run(itm.name, func(t *testing.T) {
			ret := itm.want.ProtoReflect().New().Interface()
			require.NoError(t, UnmarshalYAML([]byte(itm.in), ret))
			assert.True(t, proto.Equal(itm.want, ret), "%v", ret)
		})
	}
}

func TestUnmarshalYAMLErrors(t *testing.T) {
	for _, in := range []string{
		"metadata: [",
		"? [one, two]\n: value",
		"metadata: invalid",
		"metadata:\n  name: true",
	} {
		t.Run(in, func(t *testing.T) {
			assert.Error(t, UnmarshalYAML([]byte(in), &corev1.Secret{}))
		})
	}
}
