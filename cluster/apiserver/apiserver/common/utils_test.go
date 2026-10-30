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

package common

import (
	"strings"
	"testing"

	"github.com/octelium/octelium/apis/main/metav1"
	"github.com/stretchr/testify/assert"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
)

func TestMetadata(t *testing.T) {
	from := &metav1.Metadata{
		Name: "resource", Uid: "untrusted", IsSystem: true, IsSystemHidden: true, IsUserHidden: true,
		DisplayName: "Resource", Description: "description", PicURL: "https://example.com/picture",
		Labels: map[string]string{"key": "value"}, Annotations: map[string]string{"key": "value"}, Tags: []string{"tag"},
		SystemLabels: map[string]string{"internal": "value"}, SpecLabels: map[string]string{"internal": "value"},
	}
	want := &metav1.Metadata{
		Name: "resource", DisplayName: from.DisplayName, Description: from.Description, PicURL: from.PicURL,
		Labels: from.Labels, Annotations: from.Annotations, Tags: from.Tags,
	}
	assert.True(t, proto.Equal(want, MetadataFrom(from)))
	to := &metav1.Metadata{Name: "original", Uid: "original-uid", IsSystem: true, SystemLabels: map[string]string{"protected": "value"}}
	MetadataUpdate(to, from)
	want.Name, want.Uid, want.IsSystem, want.SystemLabels = to.Name, to.Uid, to.IsSystem, to.SystemLabels
	assert.Equal(t, "original", to.Name)
	assert.Equal(t, "original-uid", to.Uid)
	assert.True(t, proto.Equal(want, to))
	MetadataUpdate(to, &metav1.Metadata{})
	assert.Empty(t, to.DisplayName)
	assert.Empty(t, to.Description)
	assert.Empty(t, to.Labels)
	assert.Empty(t, to.Annotations)
	assert.Empty(t, to.Tags)
	assert.Empty(t, to.PicURL)
	assert.Equal(t, map[string]string{"protected": "value"}, to.SystemLabels)
}

func TestCheckGetOrDeleteOptions(t *testing.T) {
	for _, tc := range []struct {
		name string
		uid  string
		code codes.Code
	}{
		{"resource", "", codes.OK},
		{strings.Repeat("a", 64), "", codes.OK},
		{"", "7f0da666-37af-4cf9-8d0f-995d82877e70", codes.OK},
		{"", "", codes.InvalidArgument},
		{"Resource", "", codes.InvalidArgument},
		{"resource.namespace", "", codes.InvalidArgument},
		{"-resource", "", codes.InvalidArgument},
		{"resource-", "", codes.InvalidArgument},
		{strings.Repeat("a", 65), "", codes.InvalidArgument},
		{"resource\x00", "", codes.InvalidArgument},
		{"", "invalid", codes.InvalidArgument},
		{"resource", "7f0da666-37af-4cf9-8d0f-995d82877e70", codes.InvalidArgument},
	} {
		assert.Equal(t, tc.code, status.Code(CheckGetOrDeleteOptions(&metav1.GetOptions{Name: tc.name, Uid: tc.uid})))
		assert.Equal(t, tc.code, status.Code(CheckGetOrDeleteOptions(&metav1.DeleteOptions{Name: tc.name, Uid: tc.uid})))
	}
	assert.Equal(t, codes.InvalidArgument, status.Code(CheckGetOrDeleteOptions((*metav1.GetOptions)(nil))))
	assert.Equal(t, "default", GetNamespace(""))
	assert.Equal(t, "production", GetNamespace("production"))
}

func TestValidateDuration(t *testing.T) {
	for _, tc := range []struct {
		value *metav1.Duration
		valid bool
	}{
		{nil, true},
		{&metav1.Duration{}, false},
		{&metav1.Duration{Type: &metav1.Duration_Milliseconds{Milliseconds: 999}}, false},
		{&metav1.Duration{Type: &metav1.Duration_Milliseconds{Milliseconds: 1000}}, true},
		{&metav1.Duration{Type: &metav1.Duration_Seconds{Seconds: 1}}, true},
		{&metav1.Duration{Type: &metav1.Duration_Days{Days: 36000}}, true},
		{&metav1.Duration{Type: &metav1.Duration_Days{Days: 36001}}, false},
	} {
		assert.Equal(t, tc.valid, ValidateDuration(tc.value) == nil)
	}
}

func TestValidationHelpers(t *testing.T) {
	assert.True(t, stringInSlice("GET", httpMethods))
	assert.False(t, stringInSlice("get", httpMethods))
	assert.False(t, stringInSlice("GET", nil))
	assert.Equal(t, "hello", sanitize("<b>hello</b>"))
	assert.Equal(t, "", sanitize("<script>alert(1)</script>"))
}
