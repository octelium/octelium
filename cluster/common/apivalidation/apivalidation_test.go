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

package apivalidation

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/apis/main/metav1"
	"github.com/octelium/octelium/cluster/common/tests"
	"github.com/octelium/octelium/cluster/common/vutils"
	"github.com/octelium/octelium/pkg/apiutils/umetav1"
	"github.com/octelium/octelium/pkg/common/pbutils"
	"github.com/octelium/octelium/pkg/grpcerr"
	"github.com/octelium/octelium/pkg/utils/utilrand"
	"github.com/stretchr/testify/assert"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/structpb"
)

func TestValidateMetadata(t *testing.T) {
	assert.Nil(t, ValidateMetadata(&metav1.Metadata{}, nil))
	assert.Equal(t, codes.InvalidArgument, status.Code(ValidateMetadata(nil, nil)))
	assert.NotNil(t, ValidateMetadata(&metav1.Metadata{}, &ValidateMetadataOpts{RequireName: true}))
	assert.NotNil(t, ValidateMetadata(&metav1.Metadata{}, &ValidateMetadataOpts{RequireUID: true}))

	valid := &metav1.Metadata{
		Name: "service.namespace", Uid: vutils.UUIDv4(),
		DisplayName: strings.Repeat("a", 100), Description: strings.Repeat("a", 1024),
		Labels: map[string]string{}, Annotations: map[string]string{},
	}
	for i := range 64 {
		key := fmt.Sprintf("key-%02d", i)
		valid.Labels[key] = strings.Repeat("a", 32)
		valid.Annotations[key] = strings.Repeat("a", 63)
		valid.Tags = append(valid.Tags, key)
	}
	opts := &ValidateMetadataOpts{RequireName: true, RequireUID: true, ParentsMust: 1}
	before := proto.Clone(valid)
	assert.Nil(t, ValidateMetadata(valid, opts))
	assert.True(t, proto.Equal(before, valid))

	for _, tc := range []struct {
		name string
		set  func(*metav1.Metadata)
	}{
		{"Name", func(m *metav1.Metadata) { m.Name = "invalid/name" }},
		{"UID", func(m *metav1.Metadata) { m.Uid = "not-a-uuid" }},
		{"DisplayName", func(m *metav1.Metadata) { m.DisplayName += "a" }},
		{"Description", func(m *metav1.Metadata) { m.Description += "a" }},
		{"Labels", func(m *metav1.Metadata) { m.Labels["extra"] = "value" }},
		{"LabelKey", func(m *metav1.Metadata) { m.Labels = map[string]string{"Invalid": "value"} }},
		{"LabelValue", func(m *metav1.Metadata) { m.Labels = map[string]string{"valid": "Invalid"} }},
		{"Annotations", func(m *metav1.Metadata) { m.Annotations["extra"] = "value" }},
		{"AnnotationKey", func(m *metav1.Metadata) { m.Annotations = map[string]string{"Invalid": "value"} }},
		{"AnnotationValue", func(m *metav1.Metadata) { m.Annotations["key-00"] += "a" }},
		{"Tags", func(m *metav1.Metadata) { m.Tags = append(m.Tags, "extra") }},
		{"Tag", func(m *metav1.Metadata) { m.Tags = []string{"Invalid"} }},
		{"DuplicateTags", func(m *metav1.Metadata) { m.Tags = []string{"first", "second", "first"} }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := proto.Clone(valid).(*metav1.Metadata)
			tc.set(m)
			assert.Equal(t, codes.InvalidArgument, status.Code(ValidateMetadata(m, opts)))
		})
	}
}

func TestValidateNameBoundaries(t *testing.T) {
	for _, tc := range []struct {
		name string
		must uint64
		max  uint64
		ok   bool
	}{
		{"ab", 0, 0, true},
		{strings.Repeat("a", 40), 0, 0, true},
		{strings.Repeat("a", 41), 0, 0, false},
		{"service.namespace", 1, 0, true},
		{"service.namespace", 0, 1, true},
		{"service.namespace.parent", 0, 1, false},
		{"service..namespace", 0, 2, false},
		{"service..namespace", 2, 0, false},
		{"service--name.namespace", 1, 0, false},
		{strings.Repeat("a", 40) + "." + strings.Repeat("b", 40) + "." + strings.Repeat("c", 40) + ".ddddd", 0, 3, true},
		{strings.Repeat("a", 40) + "." + strings.Repeat("b", 40) + "." + strings.Repeat("c", 40) + ".dddddd", 0, 3, false},
	} {
		assert.Equal(t, tc.ok, ValidateName(tc.name, tc.must, tc.max) == nil, tc.name)
	}
}

func TestValidateResourceFields(t *testing.T) {
	sec := &corev1.Secret{Metadata: &metav1.Metadata{Name: "secret"}, Spec: &corev1.Secret_Spec{}}
	opts := &ValidateCommonOpts{RequireStatus: true, RequireData: true}
	assert.NotNil(t, ValidateCommon(sec, opts))
	sec.Status = &corev1.Secret_Status{}
	assert.NotNil(t, ValidateCommon(sec, opts))
	sec.Data = &corev1.Secret_Data{}
	assert.Nil(t, ValidateCommon(sec, opts))
	var nilSec *corev1.Secret
	assert.NotNil(t, ValidateCommon(nilSec, nil))
}

func TestValidateAttrs(t *testing.T) {
	assert.Nil(t, ValidateAttrs(nil))
	for _, tc := range []struct {
		name string
		data map[string]any
		ok   bool
	}{
		{"Empty", map[string]any{}, true},
		{"Values", map[string]any{"someValue": "value", "number1": 1, "bool": false, "null": nil}, true},
		{"Nested", map[string]any{"outer": map[string]any{"innerValue": []any{1, "value"}}}, true},
		{"EmptyKey", map[string]any{"": "value"}, false},
		{"UpperCase", map[string]any{"Invalid": "value"}, false},
		{"SnakeCase", map[string]any{"some_value": "value"}, false},
		{"NestedKey", map[string]any{"outer": map[string]any{"invalid-key": true}}, false},
		{"LongKey", map[string]any{strings.Repeat("a", 101): true}, false},
		{"MaxKey", map[string]any{strings.Repeat("a", 100): true}, true},
		{"Oversized", map[string]any{"value": strings.Repeat("a", 20001)}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			attrs, err := structpb.NewStruct(tc.data)
			assert.Nil(t, err)
			err = ValidateAttrs(attrs)
			assert.Equal(t, tc.ok, err == nil, "%+v", err)
			if err != nil {
				assert.Equal(t, codes.InvalidArgument, status.Code(err))
			}
		})
	}
	assert.NotNil(t, ValidateAttrs(&structpb.Struct{Fields: map[string]*structpb.Value{
		"value": structpb.NewStringValue(string([]byte{0xff})),
	}}))
}

func TestValidateIdentifiers(t *testing.T) {
	uid := vutils.UUIDv4()
	assert.Nil(t, DoCheckUID(uid))
	assert.Nil(t, CheckUID(&metav1.GetOptions{Uid: uid}))
	assert.NotNil(t, CheckUID(nil))
	for _, arg := range []string{"", "invalid", "00000000-0000-0000-0000-000000000000"} {
		assert.NotNil(t, DoCheckUID(arg))
		assert.NotNil(t, CheckUID(&metav1.GetOptions{Uid: arg}))
	}
	for _, tc := range []struct {
		req  *metav1.GetOptions
		opts *CheckGetOptionsOpts
		ok   bool
	}{
		{&metav1.GetOptions{Uid: uid}, &CheckGetOptionsOpts{HasName: true}, false},
		{&metav1.GetOptions{Name: "service"}, &CheckGetOptionsOpts{HasUID: true}, false},
		{&metav1.GetOptions{Name: "invalid/name"}, nil, false},
		{&metav1.GetOptions{Name: "service.namespace", Uid: uid}, &CheckGetOptionsOpts{HasName: true, HasUID: true, ParentsMust: 1}, true},
	} {
		assert.Equal(t, tc.ok, CheckGetOptions(tc.req, tc.opts) == nil)
		assert.Equal(t, tc.ok, CheckDeleteOptions(&metav1.DeleteOptions{Name: tc.req.Name, Uid: tc.req.Uid}, tc.opts) == nil)
		assert.Equal(t, tc.ok, CheckObjectRef(&metav1.ObjectReference{Name: tc.req.Name, Uid: tc.req.Uid}, tc.opts) == nil)
	}
	assert.NotNil(t, CheckDeleteOptions(nil, nil))
	assert.NotNil(t, CheckObjectRef(nil, nil))
}

func TestResourceGuards(t *testing.T) {
	for _, check := range []func(umetav1.ResourceObjectI) error{CheckIsSystem, CheckIsSystemHidden, CheckIsUserHidden} {
		assert.Equal(t, codes.InvalidArgument, status.Code(check(nil)))
		assert.Equal(t, codes.InvalidArgument, status.Code(check(&corev1.User{})))
		assert.Nil(t, check(&corev1.User{Metadata: &metav1.Metadata{}}))
	}
	assert.Equal(t, codes.PermissionDenied, status.Code(CheckIsSystem(&corev1.User{Metadata: &metav1.Metadata{IsSystem: true}})))
	assert.Equal(t, codes.PermissionDenied, status.Code(CheckIsSystemHidden(&corev1.User{Metadata: &metav1.Metadata{IsSystemHidden: true}})))
	assert.Equal(t, codes.PermissionDenied, status.Code(CheckIsUserHidden(&corev1.User{Metadata: &metav1.Metadata{IsUserHidden: true}})))
	assert.Equal(t, codes.PermissionDenied, status.Code(CheckIsUserHidden(&corev1.User{Metadata: &metav1.Metadata{IsSystemHidden: true}})))
}

func TestObjectOptionsConversions(t *testing.T) {
	for _, ref := range []*metav1.ObjectReference{nil, {}, {Name: "service", Uid: vutils.UUIDv4()}} {
		for _, opts := range []interface {
			GetName() string
			GetUid() string
		}{
			ObjectReferenceToGetOptions(ref), ObjectReferenceToRGetOptions(ref),
			ObjectReferenceToDeleteOptions(ref), ObjectReferenceToRDeleteOptions(ref),
			GetOptionsToRGetOptions(ObjectReferenceToGetOptions(ref)),
			DeleteOptionsToRGetOptions(ObjectReferenceToDeleteOptions(ref)),
		} {
			assert.Equal(t, ref.GetName(), opts.GetName())
			assert.Equal(t, ref.GetUid(), opts.GetUid())
		}
	}
	assert.Empty(t, GetOptionsToRGetOptions(nil).Name)
	assert.Empty(t, DeleteOptionsToRGetOptions(nil).Name)
	for _, obj := range []umetav1.ResourceObjectI{nil, &corev1.User{}, &corev1.User{Metadata: &metav1.Metadata{Name: "user", Uid: vutils.UUIDv4()}}} {
		name, uid := "", ""
		if obj != nil && obj.GetMetadata() != nil {
			name, uid = obj.GetMetadata().Name, obj.GetMetadata().Uid
		}
		assert.Equal(t, name, ObjectToRGetOptions(obj).Name)
		assert.Equal(t, uid, ObjectToRGetOptions(obj).Uid)
		assert.Equal(t, name, ObjectToRDeleteOptions(obj).Name)
		assert.Equal(t, uid, ObjectToRDeleteOptions(obj).Uid)
	}
}

func TestValidateNetworkValues(t *testing.T) {
	for _, arg := range []string{"example.com:443", "127.0.0.1:80", "[2001:db8::1]:443"} {
		assert.Nil(t, ValidateHostPort(arg), arg)
	}
	for _, arg := range []string{"", "example.com", ":443", "example.com:", "example.com:65536", "example.com:-1", "example.com:http", "invalid/host:80", "2001:db8::1:443"} {
		assert.Equal(t, codes.InvalidArgument, status.Code(ValidateHostPort(arg)), arg)
	}
	for _, port := range []int{1, 80, 443, 65535} {
		assert.Nil(t, ValidatePort(port))
	}
	for _, port := range []int{-1, 65536} {
		assert.NotNil(t, ValidatePort(port))
	}
	for _, code := range []int64{200, 299, 400, 500, 599} {
		assert.Nil(t, ValidateHTTPStatusCode(code))
	}
	for _, code := range []int64{-1, 0, 100, 199, 600} {
		assert.NotNil(t, ValidateHTTPStatusCode(code))
	}
}

func TestValidateDurations(t *testing.T) {
	for _, arg := range []*metav1.Duration{
		nil, {Type: &metav1.Duration_Seconds{Seconds: 1}},
		{Type: &metav1.Duration_Milliseconds{Milliseconds: 1000}},
		{Type: &metav1.Duration_Months{Months: 1200}},
	} {
		assert.Nil(t, ValidateDuration(arg))
	}
	for _, arg := range []*metav1.Duration{
		{}, {Type: &metav1.Duration_Milliseconds{Milliseconds: 999}},
		{Type: &metav1.Duration_Months{Months: 1201}},
	} {
		assert.NotNil(t, ValidateDuration(arg))
	}
}

func TestValidateEnvironment(t *testing.T) {
	for _, key := range []string{"KEY", "key_1", strings.Repeat("a", 256)} {
		assert.Nil(t, ValidateEnvVar(key, strings.Repeat("a", 8129)))
		assert.NotNil(t, ValidateEnvVar(key, strings.Repeat("a", 8130)))
	}
	for _, key := range []string{"", "KEY=VALUE", "KEY\x00", "KEY\n", "KEY\x7f", strings.Repeat("a", 257)} {
		assert.NotNil(t, ValidateEnvVarKey(key))
		assert.NotNil(t, ValidateEnvVar(key, ""))
	}
	assert.Nil(t, ValidateEnvVarValue(""))
}

func TestValidateASCIIAndBrowser(t *testing.T) {
	assert.Nil(t, ValidateGenASCII(strings.Repeat("a", 150)))
	for _, arg := range []string{"", "é", strings.Repeat("a", 151)} {
		assert.NotNil(t, ValidateGenASCII(arg))
	}
	assert.Nil(t, ValidateBrowserUserAgent("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"))
	for _, arg := range []string{"", "ab", "unknown", "curl/8.0.0", strings.Repeat("a", 301)} {
		assert.NotNil(t, ValidateBrowserUserAgent(arg), arg)
	}
}

func TestCheckEmailInvalid(t *testing.T) {
	for _, arg := range []string{"", "invalid", "user@localhost", "user@example.com", "é@example.net", strings.Repeat("a", 65) + "@example.net", "user@127.0.0.1", strings.Repeat("a", 128) + "@example.net"} {
		assert.NotNil(t, CheckEmail(arg), arg)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	assert.NotNil(t, CheckEmailCtx(ctx, "user@example.net"))
	assert.NotNil(t, ValidateAttrs(&pbutils.Struct{Fields: map[string]*structpb.Value{"value": {}}}))
}

func TestValidateCommon(t *testing.T) {

	tst, err := tests.Initialize(nil)

	assert.Nil(t, err)
	t.Cleanup(func() {
		tst.Destroy()
	})

	{
		invalids := []umetav1.ResourceObjectI{
			nil,
			&corev1.Device{},
			&corev1.Namespace{
				Metadata: &metav1.Metadata{
					Name: utilrand.GetRandomStringCanonical(8),
				},
			},
		}

		for _, valid := range invalids {
			err := ValidateCommon(valid, nil)
			assert.NotNil(t, err)
			assert.True(t, grpcerr.IsInvalidArg(err))
		}
	}

	{
		invalids := []umetav1.ResourceObjectI{
			&corev1.Namespace{
				Metadata: &metav1.Metadata{
					Name: utilrand.GetRandomStringCanonical(8),
				},
				Spec: &corev1.Namespace_Spec{},
			},
		}

		for _, valid := range invalids {
			err := ValidateCommon(valid, &ValidateCommonOpts{
				ValidateMetadataOpts: ValidateMetadataOpts{
					ParentsMust: 1,
				},
			})
			assert.NotNil(t, err)
			assert.True(t, grpcerr.IsInvalidArg(err))
		}
	}

	{
		valids := []umetav1.ResourceObjectI{
			&corev1.Namespace{
				Metadata: &metav1.Metadata{
					Name: utilrand.GetRandomStringCanonical(8),
				},
				Spec: &corev1.Namespace_Spec{},
			},
		}

		for _, valid := range valids {
			assert.Nil(t, ValidateCommon(valid, nil))
		}
	}

	{
		{
			assert.Nil(t, ValidateCommon(&corev1.Namespace{
				Metadata: &metav1.Metadata{
					Name: utilrand.GetRandomStringCanonical(8),
					Tags: []string{"tag1"},
				},
				Spec: &corev1.Namespace_Spec{},
			}, nil))
		}

		{
			assert.NotNil(t, ValidateCommon(&corev1.Namespace{
				Metadata: &metav1.Metadata{
					Name: utilrand.GetRandomStringCanonical(8),
					Tags: []string{"tag1", "Tag2"},
				},
				Spec: &corev1.Namespace_Spec{},
			}, nil))
		}

		{
			assert.NotNil(t, ValidateCommon(&corev1.Namespace{
				Metadata: &metav1.Metadata{
					Name: utilrand.GetRandomStringCanonical(8),
					Tags: []string{"tag1", ""},
				},
				Spec: &corev1.Namespace_Spec{},
			}, nil))
		}

		{
			assert.NotNil(t, ValidateCommon(&corev1.Namespace{
				Metadata: &metav1.Metadata{
					Name: utilrand.GetRandomStringCanonical(8),
					Tags: []string{"tag1", "tag2", "tag1"},
				},
				Spec: &corev1.Namespace_Spec{},
			}, nil))
		}
	}
}

func TestValidateName(t *testing.T) {
	type tstCase struct {
		arg         string
		parentsMust uint64
		parentsMax  uint64
	}

	invalids := []tstCase{
		{},
		{
			arg: "Arg01",
		},
		{
			arg: "arg:abc",
		},
		{
			arg: utilrand.GetRandomStringCanonical(60),
		},
		{
			arg: utilrand.GetRandomStringCanonical(41),
		},
		{
			arg: "arg-",
		},
		{
			arg: "arg_",
		},
		{
			arg: "arg--abc",
		},
		{
			arg: ".",
		},
		{
			arg: "..",
		},
		{
			arg: "...",
		},
		{
			arg: "a.b",
		},
		{
			arg: "arg.",
		},
		{
			arg: "arg.abc.",
		},
		{
			arg:         "arg.abc.",
			parentsMust: 1,
		},
		{
			arg:         "arg",
			parentsMust: 1,
		},
		{
			arg:         "arg.abc",
			parentsMust: 2,
		},
	}

	for _, invalid := range invalids {
		assert.NotNil(t, validateName(invalid.arg, invalid.parentsMust, invalid.parentsMax))
	}
}

func TestCheckGetOptions(t *testing.T) {
	{
		assert.NotNil(t, CheckGetOptions(nil, nil))
	}
	{
		assert.NotNil(t, CheckGetOptions(&metav1.GetOptions{}, nil))
	}
	{
		assert.NotNil(t, CheckGetOptions(&metav1.GetOptions{
			Uid: utilrand.GetRandomStringCanonical(8),
		}, nil))
	}

	{
		assert.Nil(t, CheckGetOptions(&metav1.GetOptions{
			Name: utilrand.GetRandomStringCanonical(8),
		}, nil))
	}

	{
		assert.Nil(t, CheckGetOptions(&metav1.GetOptions{
			Uid: vutils.UUIDv4(),
		}, nil))
	}

	{
		assert.Nil(t, CheckGetOptions(&metav1.GetOptions{
			Name: utilrand.GetRandomStringCanonical(8),
			Uid:  vutils.UUIDv4(),
		}, nil))
	}
}

func TestGetNameAndParents(t *testing.T) {

	tst, err := tests.Initialize(nil)

	assert.Nil(t, err)
	t.Cleanup(func() {
		tst.Destroy()
	})

	{
		ret, err := GetNameAndParents("aa.bb.cc.dd")
		assert.Nil(t, err)
		assert.Equal(t, 4, len(ret))
		assert.Equal(t, "aa.bb.cc.dd", ret[0])
		assert.Equal(t, "bb.cc.dd", ret[1])
		assert.Equal(t, "cc.dd", ret[2])
		assert.Equal(t, "dd", ret[3])
	}

	{
		ret, err := GetNameAndParents("abc")
		assert.Nil(t, err)
		assert.Equal(t, 1, len(ret))
		assert.Equal(t, "abc", ret[0])
	}

	{
		_, err := GetNameAndParents("")
		assert.NotNil(t, err)
	}
}
