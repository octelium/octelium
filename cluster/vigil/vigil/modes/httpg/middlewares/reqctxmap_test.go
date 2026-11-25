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

package middlewares

import (
	"fmt"
	"math"
	"math/rand/v2"
	"reflect"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/apis/main/metav1"
	"github.com/octelium/octelium/pkg/common/pbutils"
	"github.com/stretchr/testify/assert"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/types/known/structpb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func isSameMap(a, b any) bool {
	return reflect.ValueOf(a).UnsafePointer() == reflect.ValueOf(b).UnsafePointer()
}

func requireSameRequestContextMap(t testing.TB, c *reqCtxMapCache, i *corev1.RequestContext) (map[string]any, error) {
	t.Helper()
	exp, expErr := pbutils.ConvertToMap(i)
	ret, err := getRequestContextMap(c, i)
	if expErr != nil {
		assert.Nil(t, ret)
		if assert.NotNil(t, err) {
			assert.Equal(t, expErr.Error(), err.Error())
		}
		return nil, err
	}
	assert.Nil(t, err)
	assert.Equal(t, exp, ret)
	return ret, err
}

func isReqCtxMapMemoized(obj interface{ GetMetadata() *metav1.Metadata }) bool {
	return obj.GetMetadata().GetUid() != "" && obj.GetMetadata().GetResourceVersion() != ""
}

func assertReqCtxMapShared(t testing.TB, i *corev1.RequestContext, a, b map[string]any) {
	t.Helper()
	assert.False(t, isSameMap(a, b))
	if i.GetRequest() != nil {
		assert.False(t, isSameMap(a["request"], b["request"]))
	}
	if i.GetDevice() != nil {
		assert.False(t, isSameMap(a["device"], b["device"]))
	}
	if i.GetSession() != nil {
		assert.Equal(t, isReqCtxMapMemoized(i.Session), isSameMap(a["session"], b["session"]))
	}
	if i.GetUser() != nil {
		assert.Equal(t, isReqCtxMapMemoized(i.User), isSameMap(a["user"], b["user"]))
	}
	for idx, grp := range i.GetGroups() {
		assert.Equal(t, isReqCtxMapMemoized(grp),
			isSameMap(a["groups"].([]any)[idx], b["groups"].([]any)[idx]))
	}
	if i.GetService() != nil {
		assert.Equal(t, isReqCtxMapMemoized(i.Service), isSameMap(a["service"], b["service"]))
	}
	if i.GetNamespace() != nil {
		assert.Equal(t, isReqCtxMapMemoized(i.Namespace), isSameMap(a["namespace"], b["namespace"]))
	}
}

func newReqCtxMapTestContext(prefix string) *corev1.RequestContext {
	createdAt := timestamppb.New(time.Date(2026, 11, 24, 10, 0, 0, 123456789, time.UTC))
	md := func(name string) *metav1.Metadata {
		return &metav1.Metadata{
			Uid:             fmt.Sprintf("%s-%s-uid", prefix, name),
			Name:            name,
			ResourceVersion: fmt.Sprintf("%s-%s-rv", prefix, name),
			CreatedAt:       createdAt,
			Labels:          map[string]string{"app": name},
		}
	}
	attrs := &structpb.Struct{Fields: map[string]*structpb.Value{
		"number": structpb.NewNumberValue(-0.5),
		"list": structpb.NewListValue(&structpb.ListValue{Values: []*structpb.Value{
			structpb.NewNullValue(), structpb.NewBoolValue(true), structpb.NewStringValue("str"),
		}}),
	}}

	return &corev1.RequestContext{
		Request: &corev1.RequestContext_Request{Type: &corev1.RequestContext_Request_Http{
			Http: &corev1.RequestContext_Request_HTTP{
				Path:    "/path",
				Method:  "POST",
				Headers: map[string]string{"x-custom": "value"},
				Body:    []byte(`{"key":"value"}`),
				BodyMap: &structpb.Struct{Fields: map[string]*structpb.Value{"key": structpb.NewStringValue("value")}},
			},
		}},
		Session: &corev1.Session{
			Metadata: md("session"),
			Spec: &corev1.Session_Spec{
				State:     corev1.Session_Spec_ACTIVE,
				ExpiresAt: createdAt,
			},
			Status: &corev1.Session_Status{
				Type:        corev1.Session_Status_CLIENT,
				IsConnected: true,
				UserRef:     &metav1.ObjectReference{Kind: "User", Name: "user", Uid: fmt.Sprintf("%s-user-uid", prefix)},
			},
		},
		User: &corev1.User{
			Metadata: md("user"),
			Spec: &corev1.User_Spec{
				Type:   corev1.User_Spec_HUMAN,
				Email:  "user@example.com",
				Groups: []string{"group1", "group2"},
				Attrs:  attrs,
			},
		},
		Groups: []*corev1.Group{
			{Metadata: md("group1"), Spec: &corev1.Group_Spec{Attrs: attrs}},
			{Metadata: md("group2"), Spec: &corev1.Group_Spec{}},
		},
		Device: &corev1.Device{
			Metadata: md("device"),
			Spec:     &corev1.Device_Spec{State: corev1.Device_Spec_ACTIVE},
			Status:   &corev1.Device_Status{Hostname: "host", OsType: corev1.Device_Status_LINUX},
		},
		Service: &corev1.Service{
			Metadata: md("service"),
			Spec: &corev1.Service_Spec{
				Port:     8080,
				Mode:     corev1.Service_Spec_HTTP,
				IsPublic: true,
			},
			Status: &corev1.Service_Status{
				NamespaceRef: &metav1.ObjectReference{Kind: "Namespace", Name: "namespace"},
			},
		},
		Namespace: &corev1.Namespace{
			Metadata: md("namespace"),
			Spec:     &corev1.Namespace_Spec{Attrs: attrs},
		},
	}
}

func getReqCtxMapTestMetadata(i *corev1.RequestContext) []*metav1.Metadata {
	var ret []*metav1.Metadata
	for _, md := range []*metav1.Metadata{
		i.GetSession().GetMetadata(), i.GetUser().GetMetadata(),
		i.GetDevice().GetMetadata(), i.GetService().GetMetadata(), i.GetNamespace().GetMetadata(),
	} {
		if md != nil {
			ret = append(ret, md)
		}
	}
	for _, grp := range i.GetGroups() {
		if grp.GetMetadata() != nil {
			ret = append(ret, grp.Metadata)
		}
	}
	return ret
}

type reqCtxMapRandom struct {
	*rand.Rand
	invalid bool
	n       int
}

func (r *reqCtxMapRandom) string() string {
	if r.invalid && r.IntN(48) == 0 {
		return "invalid-\xff"
	}
	runes := []rune("aZ09-_./: é界\U0001f600")
	ret := make([]rune, r.IntN(6))
	for i := range ret {
		ret[i] = runes[r.IntN(len(runes))]
	}
	return string(ret)
}

func (r *reqCtxMapRandom) value(fd protoreflect.FieldDescriptor, v protoreflect.Value, depth int) protoreflect.Value {
	switch fd.Kind() {
	case protoreflect.BoolKind:
		return protoreflect.ValueOfBool(r.IntN(2) == 0)
	case protoreflect.EnumKind:
		values := fd.Enum().Values()
		if r.IntN(8) == 0 {
			return protoreflect.ValueOfEnum(protoreflect.EnumNumber(r.Int32N(2000) - 1000))
		}
		return protoreflect.ValueOfEnum(values.Get(r.IntN(values.Len())).Number())
	case protoreflect.Int32Kind, protoreflect.Sint32Kind, protoreflect.Sfixed32Kind:
		return protoreflect.ValueOfInt32(int32(r.Uint32()))
	case protoreflect.Int64Kind, protoreflect.Sint64Kind, protoreflect.Sfixed64Kind:
		return protoreflect.ValueOfInt64(int64(r.Uint64()))
	case protoreflect.Uint32Kind, protoreflect.Fixed32Kind:
		return protoreflect.ValueOfUint32(r.Uint32())
	case protoreflect.Uint64Kind, protoreflect.Fixed64Kind:
		return protoreflect.ValueOfUint64(r.Uint64())
	case protoreflect.FloatKind:
		return protoreflect.ValueOfFloat32(float32(r.NormFloat64() * 1000))
	case protoreflect.DoubleKind:
		return protoreflect.ValueOfFloat64(r.NormFloat64() * 1e9)
	case protoreflect.StringKind:
		return protoreflect.ValueOfString(r.string())
	case protoreflect.BytesKind:
		return protoreflect.ValueOfBytes([]byte(r.string()))
	default:
		r.populate(v.Message(), depth-1)
		return v
	}
}

func (r *reqCtxMapRandom) populate(m protoreflect.Message, depth int) {
	md := m.Descriptor()
	fds := md.Fields()

	switch md.FullName() {
	case "google.protobuf.Timestamp":
		secs := r.Int64N(253402300799)
		if r.invalid && r.IntN(16) == 0 {
			secs = 253402300800
		}
		m.Set(fds.ByNumber(1), protoreflect.ValueOfInt64(secs))
		m.Set(fds.ByNumber(2), protoreflect.ValueOfInt32(r.Int32N(1000000000)))
		return
	case "google.protobuf.Duration":
		secs, nanos := r.Int64N(315576000000), r.Int32N(1000000000)
		if r.IntN(2) == 0 {
			secs, nanos = -secs, -nanos
		}
		m.Set(fds.ByNumber(1), protoreflect.ValueOfInt64(secs))
		m.Set(fds.ByNumber(2), protoreflect.ValueOfInt32(nanos))
		return
	case "google.protobuf.Value":
		kinds := md.Oneofs().ByName("kind").Fields()
		fd := kinds.Get(r.IntN(kinds.Len()))
		switch {
		case fd.Kind() == protoreflect.MessageKind && depth <= 0:
			m.Set(kinds.ByName("string_value"), protoreflect.ValueOfString(r.string()))
		case fd.Kind() == protoreflect.DoubleKind && r.invalid && r.IntN(16) == 0:
			m.Set(fd, protoreflect.ValueOfFloat64(math.NaN()))
		default:
			m.Set(fd, r.value(fd, m.NewField(fd), depth))
		}
		return
	}

	for i := range fds.Len() {
		fd := fds.Get(i)
		if r.IntN(3) == 0 || (fd.Message() != nil && depth <= 0) {
			continue
		}
		if od := fd.ContainingOneof(); od != nil && m.WhichOneof(od) != nil {
			continue
		}

		switch {
		case fd.IsList():
			lst := m.Mutable(fd).List()
			for range r.IntN(3) + 1 {
				lst.Append(r.value(fd, lst.NewElement(), depth))
			}
		case fd.IsMap():
			mp := m.Mutable(fd).Map()
			for range r.IntN(3) + 1 {
				mp.Set(r.value(fd.MapKey(), protoreflect.Value{}, depth).MapKey(),
					r.value(fd.MapValue(), mp.NewValue(), depth))
			}
		default:
			m.Set(fd, r.value(fd, m.NewField(fd), depth))
		}
	}
}

func (r *reqCtxMapRandom) setResourceVersions(i *corev1.RequestContext) {
	for _, md := range getReqCtxMapTestMetadata(i) {
		r.n++
		if r.IntN(4) == 0 {
			md.ResourceVersion = ""
		} else {
			md.ResourceVersion = fmt.Sprintf("rv-%d", r.n)
		}
	}
}

func (r *reqCtxMapRandom) newReqCtx(depth int) *corev1.RequestContext {
	ret := &corev1.RequestContext{}
	r.populate(ret.ProtoReflect(), depth)
	r.setResourceVersions(ret)
	return ret
}

func (r *reqCtxMapRandom) mutate(i *corev1.RequestContext) {
	for _, md := range getReqCtxMapTestMetadata(i) {
		md.DisplayName = r.string()
	}
	r.setResourceVersions(i)
}

func TestGetRequestContextMapFields(t *testing.T) {
	fds := (&corev1.RequestContext{}).ProtoReflect().Descriptor().Fields()
	var names []string
	for i := range fds.Len() {
		names = append(names, fds.Get(i).JSONName())
	}
	assert.Equal(t, []string{"request", "session", "user", "groups", "device", "service", "namespace"}, names)
}

func TestGetRequestContextMap(t *testing.T) {
	c := newReqCtxMapCache()
	full := newReqCtxMapTestContext("full")

	noResourceVersion := proto.Clone(full).(*corev1.RequestContext)
	for _, md := range getReqCtxMapTestMetadata(noResourceVersion) {
		md.ResourceVersion = ""
	}
	noUID := proto.Clone(full).(*corev1.RequestContext)
	for _, md := range getReqCtxMapTestMetadata(noUID) {
		md.Uid = ""
	}

	for _, tc := range []struct {
		name   string
		reqCtx *corev1.RequestContext
	}{
		{"Nil", nil},
		{"Empty", &corev1.RequestContext{}},
		{"Request", &corev1.RequestContext{Request: full.Request}},
		{"EmptyRequest", &corev1.RequestContext{Request: &corev1.RequestContext_Request{}}},
		{"Session", &corev1.RequestContext{Session: full.Session}},
		{"User", &corev1.RequestContext{User: full.User}},
		{"Groups", &corev1.RequestContext{Groups: full.Groups}},
		{"EmptyGroups", &corev1.RequestContext{Groups: []*corev1.Group{}}},
		{"NilGroup", &corev1.RequestContext{Groups: []*corev1.Group{nil, full.Groups[0], nil}}},
		{"Device", &corev1.RequestContext{Device: full.Device}},
		{"Service", &corev1.RequestContext{Service: full.Service}},
		{"Namespace", &corev1.RequestContext{Namespace: full.Namespace}},
		{"EmptyResources", &corev1.RequestContext{
			Session: &corev1.Session{}, User: &corev1.User{}, Groups: []*corev1.Group{{}},
			Device: &corev1.Device{}, Service: &corev1.Service{}, Namespace: &corev1.Namespace{},
		}},
		{"Anonymous", &corev1.RequestContext{Service: full.Service, Request: full.Request, Namespace: full.Namespace}},
		{"Full", full},
		{"Clone", proto.Clone(full).(*corev1.RequestContext)},
		{"NoResourceVersion", noResourceVersion},
		{"NoUID", noUID},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for range 3 {
				requireSameRequestContextMap(t, c, tc.reqCtx)
			}
		})
	}

	first, err := getRequestContextMap(c, full)
	assert.Nil(t, err)
	second, err := getRequestContextMap(c, full)
	assert.Nil(t, err)
	assertReqCtxMapShared(t, full, first, second)
	for _, key := range []string{"session", "user", "service", "namespace"} {
		assert.True(t, isSameMap(first[key], second[key]), key)
	}
	assert.False(t, isSameMap(first["groups"], second["groups"]))
	assert.Equal(t, 6, c.Len())

	clone := proto.Clone(full).(*corev1.RequestContext)
	cloneMap, err := getRequestContextMap(c, clone)
	assert.Nil(t, err)
	assertReqCtxMapShared(t, clone, first, cloneMap)

	for _, i := range []*corev1.RequestContext{noResourceVersion, noUID} {
		ret, err := getRequestContextMap(c, i)
		assert.Nil(t, err)
		assertReqCtxMapShared(t, i, first, ret)
		for _, key := range []string{"session", "user", "service", "namespace"} {
			assert.False(t, isSameMap(first[key], ret[key]), key)
		}
	}
	assert.Equal(t, 6, c.Len())

	updated := proto.Clone(full).(*corev1.RequestContext)
	for idx, md := range getReqCtxMapTestMetadata(updated) {
		md.DisplayName = "updated"
		md.ResourceVersion = fmt.Sprintf("updated-%d", idx)
	}
	updatedMap, err := requireSameRequestContextMap(t, c, updated)
	assert.Nil(t, err)
	assert.Equal(t, "updated", updatedMap["user"].(map[string]any)["metadata"].(map[string]any)["displayName"])
	for _, key := range []string{"session", "user", "service", "namespace"} {
		assert.False(t, isSameMap(first[key], updatedMap[key]), key)
	}
	assert.Equal(t, 12, c.Len())

	ret, err := requireSameRequestContextMap(t, c, full)
	assert.Nil(t, err)
	assert.True(t, isSameMap(first["user"], ret["user"]))

	sameKey := &corev1.RequestContext{
		User:   proto.Clone(full.User).(*corev1.User),
		Groups: []*corev1.Group{{Metadata: proto.Clone(full.User.Metadata).(*metav1.Metadata)}},
	}
	ret, err = requireSameRequestContextMap(t, c, sameKey)
	assert.Nil(t, err)
	assert.True(t, isSameMap(first["user"], ret["user"]))
	assert.False(t, isSameMap(ret["user"], ret["groups"].([]any)[0]))
	ret, err = requireSameRequestContextMap(t, c, sameKey)
	assert.Nil(t, err)
	assert.True(t, isSameMap(first["user"], ret["user"]))
}

func TestGetRequestContextMapErrors(t *testing.T) {
	invalid := "invalid-\xff"
	invalidTimestamp := &timestamppb.Timestamp{Seconds: -62135596801}

	for _, memoized := range []bool{false, true} {
		for _, tc := range []struct {
			name   string
			mutate func(i *corev1.RequestContext)
		}{
			{"Request", func(i *corev1.RequestContext) {
				i.Request.GetHttp().Headers = map[string]string{"x-invalid": invalid}
			}},
			{"RequestBodyMap", func(i *corev1.RequestContext) {
				i.Request.GetHttp().BodyMap = &structpb.Struct{Fields: map[string]*structpb.Value{"nan": structpb.NewNumberValue(math.NaN())}}
			}},
			{"Session", func(i *corev1.RequestContext) {
				i.Session.Metadata.DisplayName = invalid
			}},
			{"SessionTimestamp", func(i *corev1.RequestContext) {
				i.Session.Metadata.CreatedAt = invalidTimestamp
			}},
			{"User", func(i *corev1.RequestContext) {
				i.User.Spec.Attrs = &structpb.Struct{Fields: map[string]*structpb.Value{"nan": structpb.NewNumberValue(math.NaN())}}
			}},
			{"UserValue", func(i *corev1.RequestContext) {
				i.User.Spec.Attrs = &structpb.Struct{Fields: map[string]*structpb.Value{"empty": {}}}
			}},
			{"Group", func(i *corev1.RequestContext) {
				i.Groups[1].Metadata.DisplayName = invalid
			}},
			{"Device", func(i *corev1.RequestContext) {
				i.Device.Metadata.DisplayName = invalid
			}},
			{"Service", func(i *corev1.RequestContext) {
				i.Service.Metadata.CreatedAt = invalidTimestamp
			}},
			{"Namespace", func(i *corev1.RequestContext) {
				i.Namespace.Metadata.DisplayName = invalid
			}},
			{"RequestAndNamespace", func(i *corev1.RequestContext) {
				i.Request.GetHttp().Headers = map[string]string{"x-invalid": invalid}
				i.Namespace.Metadata.DisplayName = invalid
			}},
			{"SessionAndUser", func(i *corev1.RequestContext) {
				i.Session.Metadata.CreatedAt = invalidTimestamp
				i.User.Metadata.DisplayName = invalid
			}},
			{"GroupsAndDevice", func(i *corev1.RequestContext) {
				i.Groups[0].Metadata.CreatedAt = invalidTimestamp
				i.Groups[1].Metadata.DisplayName = invalid
				i.Device.Metadata.DisplayName = invalid
			}},
			{"ServiceAndNamespace", func(i *corev1.RequestContext) {
				i.Service.Metadata.DisplayName = invalid
				i.Namespace.Metadata.CreatedAt = invalidTimestamp
			}},
		} {
			t.Run(fmt.Sprintf("%s/Memoized%t", tc.name, memoized), func(t *testing.T) {
				c := newReqCtxMapCache()
				i := newReqCtxMapTestContext("errors")

				if memoized {
					_, err := requireSameRequestContextMap(t, c, i)
					assert.Nil(t, err)
					assert.Equal(t, 6, c.Len())
				}

				tc.mutate(i)
				for idx, md := range getReqCtxMapTestMetadata(i) {
					md.ResourceVersion = fmt.Sprintf("mutated-%d", idx)
				}

				for range 2 {
					_, err := requireSameRequestContextMap(t, c, i)
					assert.NotNil(t, err)
				}

				for _, md := range getReqCtxMapTestMetadata(i) {
					md.ResourceVersion = ""
				}
				_, err := requireSameRequestContextMap(t, c, i)
				assert.NotNil(t, err)
			})
		}
	}
}

func TestGetRequestContextMapRandom(t *testing.T) {
	c := newReqCtxMapCache()
	r := &reqCtxMapRandom{Rand: rand.New(rand.NewPCG(20261124, 4))}

	var nOK, nErr, nShared int
	check := func(i *corev1.RequestContext) map[string]any {
		t.Helper()
		ret, err := requireSameRequestContextMap(t, c, i)
		if err != nil {
			nErr++
		} else {
			nOK++
		}
		return ret
	}
	checkShared := func(i *corev1.RequestContext, a, b map[string]any) {
		t.Helper()
		if a != nil && b != nil {
			assertReqCtxMapShared(t, i, a, b)
			nShared++
		}
	}

	for itr := range 400 {
		r.invalid = itr%4 == 3
		i := r.newReqCtx(4)
		first := check(i)
		checkShared(i, first, check(i))

		next := proto.Clone(i).(*corev1.RequestContext)
		checkShared(next, first, check(next))
		check(i)

		r.mutate(next)
		check(next)
		check(next)
		checkShared(i, first, check(i))
	}

	assert.Greater(t, nOK, 2*nErr)
	assert.Greater(t, nErr, 0)
	assert.Greater(t, nShared, 600)
}

func TestGetRequestContextMapExpiration(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		c := newReqCtxMapCache()
		defer c.Close()

		i := newReqCtxMapTestContext("expiration")
		first, err := requireSameRequestContextMap(t, c, i)
		assert.Nil(t, err)

		time.Sleep(reqCtxMapTTL - time.Second)
		ret, err := requireSameRequestContextMap(t, c, i)
		assert.Nil(t, err)
		assertReqCtxMapShared(t, i, first, ret)

		time.Sleep(2 * time.Second)
		ret, err = requireSameRequestContextMap(t, c, i)
		assert.Nil(t, err)
		for _, key := range []string{"session", "user", "service", "namespace"} {
			assert.False(t, isSameMap(first[key], ret[key]), key)
		}

		second, err := requireSameRequestContextMap(t, c, i)
		assert.Nil(t, err)
		assertReqCtxMapShared(t, i, ret, second)
		assert.Equal(t, 6, c.Len())

		time.Sleep(3 * reqCtxMapTTL)
		synctest.Wait()
		assert.Equal(t, 0, c.Len())
	})
}

func TestGetRequestContextMapConcurrent(t *testing.T) {
	c := newReqCtxMapCache()

	var versions []*corev1.RequestContext
	for idx := range 16 {
		i := newReqCtxMapTestContext("concurrent")
		for _, md := range getReqCtxMapTestMetadata(i) {
			md.DisplayName = fmt.Sprintf("version-%d", idx)
			md.ResourceVersion = fmt.Sprintf("%s-%d", md.ResourceVersion, idx)
		}
		versions = append(versions, i)
	}

	var wg sync.WaitGroup
	for n := range 16 {
		wg.Go(func() {
			r := rand.New(rand.NewPCG(20261124, uint64(n)))
			for range 64 {
				i := proto.Clone(versions[r.IntN(len(versions))]).(*corev1.RequestContext)
				for range 2 {
					if _, err := requireSameRequestContextMap(t, c, i); !assert.Nil(t, err) {
						return
					}
				}
			}
		})
	}
	wg.Wait()
}

type eagerReqCtx struct {
	downstreamInfo *corev1.RequestContext
	reqCtxMap      map[string]any
}

func (r *eagerReqCtx) setReqCtxMap() {
	if r.downstreamInfo == nil {
		r.reqCtxMap = nil
		return
	}
	r.reqCtxMap = pbutils.MustConvertToMap(r.downstreamInfo)
}

func (r *eagerReqCtx) authenticate(i *corev1.RequestContext) {
	r.downstreamInfo = i
	r.reqCtxMap = pbutils.MustConvertToMap(r.downstreamInfo)
}

func (r *eagerReqCtx) getPluginInput() (map[string]any, error) {
	if r.reqCtxMap == nil {
		reqCtxMap, err := pbutils.ConvertToMap(r.downstreamInfo)
		if err != nil {
			return nil, err
		}
		r.reqCtxMap = reqCtxMap
	}
	return map[string]any{"ctx": r.reqCtxMap}, nil
}

func (r *eagerReqCtx) setLuaInput() {
	if r.reqCtxMap == nil && r.downstreamInfo != nil {
		r.reqCtxMap = pbutils.MustConvertToMap(r.downstreamInfo)
	}
}

func (r *eagerReqCtx) getLuaInput() (map[string]any, error) {
	r.setLuaInput()
	ret := r.reqCtxMap
	if _, err := r.getPluginInput(); err != nil {
		return nil, err
	}
	return ret, nil
}

func (r *eagerReqCtx) getLLMInput() map[string]any {
	if r.reqCtxMap == nil {
		r.setReqCtxMap()
	}
	return map[string]any{"ctx": r.reqCtxMap}
}

func authenticateReqCtxMap(r *RequestContext, i *corev1.RequestContext) {
	r.DownstreamInfo = i
	r.SetReqCtxMap()
}

func getReqCtxMapPluginInput(r *RequestContext) (map[string]any, error) {
	if r.ReqCtxMap == nil {
		reqCtxMap, err := GetRequestContextMap(r.DownstreamInfo)
		if err != nil {
			return nil, err
		}
		r.ReqCtxMap = reqCtxMap
	}
	return map[string]any{"ctx": r.ReqCtxMap}, nil
}

func setReqCtxMapLuaInput(r *RequestContext) {
	if r.ReqCtxMap == nil && r.DownstreamInfo != nil {
		r.SetReqCtxMap()
	}
}

func getReqCtxMapLuaInput(r *RequestContext) (map[string]any, error) {
	setReqCtxMapLuaInput(r)
	if _, err := getReqCtxMapPluginInput(r); err != nil {
		return nil, err
	}
	return r.GetReqCtxMap(), nil
}

func TestReqCtxMap(t *testing.T) {
	i := newReqCtxMapTestContext("reqctx")
	exp := pbutils.MustConvertToMap(i)

	{
		reqCtx := &RequestContext{DownstreamInfo: i}
		assert.Nil(t, reqCtx.GetReqCtxMap())
		assert.Nil(t, reqCtx.ReqCtxMap)

		reqCtx.SetReqCtxMap()
		assert.Nil(t, reqCtx.ReqCtxMap)

		ret := reqCtx.GetReqCtxMap()
		assert.Equal(t, exp, ret)
		assert.True(t, isSameMap(ret, reqCtx.ReqCtxMap))
		assert.True(t, isSameMap(ret, reqCtx.GetReqCtxMap()))

		reqCtx.SetReqCtxMap()
		assert.Nil(t, reqCtx.ReqCtxMap)
		second := reqCtx.GetReqCtxMap()
		assert.Equal(t, exp, second)
		assert.False(t, isSameMap(ret, second))
		assertReqCtxMapShared(t, i, ret, second)
	}

	{
		reqCtx := &RequestContext{}
		reqCtx.SetReqCtxMap()
		assert.Nil(t, reqCtx.GetReqCtxMap())
		assert.Nil(t, reqCtx.ReqCtxMap)

		reqCtx.DownstreamInfo = i
		assert.Nil(t, reqCtx.GetReqCtxMap())
		reqCtx.SetReqCtxMap()
		assert.Equal(t, exp, reqCtx.GetReqCtxMap())

		reqCtx.DownstreamInfo = nil
		reqCtx.SetReqCtxMap()
		assert.Nil(t, reqCtx.GetReqCtxMap())
	}

	{
		injected := map[string]any{"request": map[string]any{}}
		reqCtx := &RequestContext{DownstreamInfo: i, ReqCtxMap: injected}
		assert.True(t, isSameMap(injected, reqCtx.GetReqCtxMap()))
	}

	{
		reqCtx := &RequestContext{DownstreamInfo: i}
		reqCtx.SetReqCtxMap()
		assert.Equal(t, exp, reqCtx.GetReqCtxMap())

		updated := proto.Clone(i).(*corev1.RequestContext)
		updated.User.Metadata.DisplayName = "updated"
		updated.User.Metadata.ResourceVersion = "updated"
		authenticateReqCtxMap(reqCtx, updated)
		assert.Nil(t, reqCtx.ReqCtxMap)
		assert.Equal(t, pbutils.MustConvertToMap(updated), reqCtx.GetReqCtxMap())
	}

	{
		invalid := proto.Clone(i).(*corev1.RequestContext)
		invalid.User.Metadata.DisplayName = "invalid-\xff"
		invalid.User.Metadata.ResourceVersion = "invalid"
		_, expErr := pbutils.ConvertToMap(invalid)
		assert.NotNil(t, expErr)

		reqCtx := &RequestContext{DownstreamInfo: invalid}
		reqCtx.SetReqCtxMap()
		for range 2 {
			assert.Nil(t, reqCtx.GetReqCtxMap())
			assert.Nil(t, reqCtx.GetInputMap()["ctx"])
			_, err := getReqCtxMapPluginInput(reqCtx)
			if assert.NotNil(t, err) {
				assert.Equal(t, expErr.Error(), err.Error())
			}
		}
	}
}

func TestGetInputMap(t *testing.T) {
	i := newReqCtxMapTestContext("input")
	exp := pbutils.MustConvertToMap(i)

	{
		reqCtx := &RequestContext{}
		assert.Equal(t, map[string]any{"ctx": map[string]any(nil)}, reqCtx.GetInputMap())
		assert.Nil(t, reqCtx.ReqCtxMap)
		assert.Nil(t, reqCtx.GetReqCtxMap())
	}

	{
		preAuth := &corev1.RequestContext{Request: i.Request, Service: i.Service}
		reqCtx := &RequestContext{DownstreamInfo: preAuth}
		ret := reqCtx.GetInputMap()
		assert.Equal(t, map[string]any{"ctx": pbutils.MustConvertToMap(preAuth)}, ret)
		assert.Len(t, ret, 1)
		assert.True(t, isSameMap(ret["ctx"], reqCtx.ReqCtxMap))
		assert.True(t, isSameMap(ret["ctx"], reqCtx.GetInputMap()["ctx"]))
		assert.True(t, isSameMap(ret["ctx"], reqCtx.GetReqCtxMap()))

		authenticateReqCtxMap(reqCtx, i)
		assert.Nil(t, reqCtx.ReqCtxMap)
		authenticated := reqCtx.GetInputMap()
		assert.Equal(t, map[string]any{"ctx": exp}, authenticated)
		assert.False(t, isSameMap(ret["ctx"], authenticated["ctx"]))
		assert.True(t, isSameMap(authenticated["ctx"], reqCtx.GetInputMap()["ctx"]))
	}

	{
		reqCtx := &RequestContext{DownstreamInfo: i}
		reqCtx.SetReqCtxMap()
		assert.Nil(t, reqCtx.ReqCtxMap)
		ret := reqCtx.GetInputMap()
		assert.Equal(t, map[string]any{"ctx": exp}, ret)
		assert.True(t, isSameMap(ret["ctx"], reqCtx.ReqCtxMap))
	}

	{
		injected := map[string]any{"request": map[string]any{}}
		reqCtx := &RequestContext{DownstreamInfo: i, ReqCtxMap: injected}
		assert.True(t, isSameMap(injected, reqCtx.GetInputMap()["ctx"]))
		assert.True(t, isSameMap(injected, reqCtx.ReqCtxMap))
	}

	{
		reqCtx := &RequestContext{DownstreamInfo: i}
		assert.Nil(t, reqCtx.GetReqCtxMap())
		assert.Equal(t, map[string]any{"ctx": exp}, reqCtx.GetInputMap())
		assert.Equal(t, exp, reqCtx.GetReqCtxMap())
	}

	{
		invalid := proto.Clone(i).(*corev1.RequestContext)
		invalid.User.Metadata.DisplayName = "invalid-\xff"
		invalid.User.Metadata.ResourceVersion = "invalid-input"
		reqCtx := &RequestContext{DownstreamInfo: invalid}
		for range 2 {
			assert.Equal(t, map[string]any{"ctx": map[string]any(nil)}, reqCtx.GetInputMap())
			assert.Nil(t, reqCtx.ReqCtxMap)
		}
	}
}

func TestReqCtxMapLazy(t *testing.T) {
	r := &reqCtxMapRandom{Rand: rand.New(rand.NewPCG(20261124, 5))}

	var identities []*corev1.RequestContext
	for idx := range 6 {
		i := newReqCtxMapTestContext(fmt.Sprintf("lazy-%d", idx%3))
		for _, md := range getReqCtxMapTestMetadata(i) {
			md.DisplayName = fmt.Sprintf("identity-%d", idx)
			md.ResourceVersion = fmt.Sprintf("%s-%d", md.ResourceVersion, idx)
		}
		if idx == 5 {
			i.User.Spec.Attrs = &structpb.Struct{Fields: map[string]*structpb.Value{"nan": structpb.NewNumberValue(math.NaN())}}
		}
		identities = append(identities, i)
	}

	newRequest := func() *corev1.RequestContext_Request {
		headers := map[string]string{"x-custom": r.string()}
		if r.IntN(10) == 0 {
			headers["x-invalid"] = "invalid-\xff"
		}
		return &corev1.RequestContext_Request{Type: &corev1.RequestContext_Request_Http{
			Http: &corev1.RequestContext_Request_HTTP{Path: "/" + r.string(), Headers: headers},
		}}
	}

	var nMap, nNil, nErr int
	compare := func(eager, lazy map[string]any) {
		t.Helper()
		assert.Equal(t, eager, lazy)
		ctxMap, isInput := eager["ctx"].(map[string]any)
		switch {
		case eager == nil, isInput && ctxMap == nil:
			nNil++
		default:
			nMap++
		}
	}
	compareErr := func(eager, lazy map[string]any, eagerErr, lazyErr error) {
		t.Helper()
		if eagerErr != nil {
			nErr++
			assert.Nil(t, lazy)
			if assert.NotNil(t, lazyErr) {
				assert.Equal(t, eagerErr.Error(), lazyErr.Error())
			}
			return
		}
		assert.Nil(t, lazyErr)
		compare(eager, lazy)
	}

	for range 3000 {
		eager := &eagerReqCtx{}
		lazy := &RequestContext{}

		if r.IntN(8) == 0 {
			for range r.IntN(4) {
				switch r.IntN(4) {
				case 0:
					eager.setReqCtxMap()
					lazy.SetReqCtxMap()
				case 1:
					e, eErr := eager.getPluginInput()
					l, lErr := getReqCtxMapPluginInput(lazy)
					compareErr(e, l, eErr, lErr)
				case 2:
					compare(eager.getLLMInput(), lazy.GetInputMap())
				default:
					compare(eager.reqCtxMap, lazy.GetReqCtxMap())
				}
			}
		}

		svc := identities[r.IntN(len(identities))].Service
		preAuth := &corev1.RequestContext{
			Request: newRequest(),
			Service: proto.Clone(svc).(*corev1.Service),
		}
		eager.downstreamInfo = preAuth
		lazy.DownstreamInfo = preAuth

		isAuthenticated := false
		isAnonymous := r.IntN(3) == 0
		isDone := false

		for range r.IntN(16) + 1 {
			if isDone {
				break
			}

			switch r.IntN(9) {
			case 0:
				eager.setReqCtxMap()
				lazy.SetReqCtxMap()
			case 1:
				eager.downstreamInfo.Request = newRequest()
				eager.setReqCtxMap()
				lazy.SetReqCtxMap()
			case 2:
				if isAuthenticated || isAnonymous {
					continue
				}
				isAuthenticated = true
				i := proto.Clone(identities[r.IntN(len(identities))]).(*corev1.RequestContext)
				i.Request = eager.downstreamInfo.Request
				eager.authenticate(i)
				authenticateReqCtxMap(lazy, i)
			case 3:
				e, eErr := eager.getPluginInput()
				l, lErr := getReqCtxMapPluginInput(lazy)
				compareErr(e, l, eErr, lErr)
				isDone = eErr != nil
			case 4:
				e, eErr := eager.getLuaInput()
				l, lErr := getReqCtxMapLuaInput(lazy)
				compareErr(e, l, eErr, lErr)
				isDone = eErr != nil
			case 5:
				eager.setLuaInput()
				setReqCtxMapLuaInput(lazy)
			case 6:
				compare(eager.getLLMInput(), lazy.GetInputMap())
			default:
				compare(eager.reqCtxMap, lazy.GetReqCtxMap())
			}
		}

		compare(eager.reqCtxMap, lazy.GetReqCtxMap())
	}

	assert.Greater(t, nMap, 1000)
	assert.Greater(t, nNil, 100)
	assert.Greater(t, nErr, 10)
}

func BenchmarkGetRequestContextMap(b *testing.B) {
	i := newReqCtxMapTestContext("benchmark")

	b.Run("ConvertToMap", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			if _, err := pbutils.ConvertToMap(i); err != nil {
				b.Fatal(err)
			}
		}
	})

	b.Run("GetRequestContextMap", func(b *testing.B) {
		c := newReqCtxMapCache()
		requireSameRequestContextMap(b, c, i)
		b.ReportAllocs()
		for b.Loop() {
			if _, err := getRequestContextMap(c, i); err != nil {
				b.Fatal(err)
			}
		}
	})
}
