// Copyright Octelium Labs, LLC. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package rscdiff

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/apis/main/metav1"
	"github.com/octelium/octelium/client/common/resources"
	"github.com/octelium/octelium/pkg/apiutils/ucorev1"
	"github.com/octelium/octelium/pkg/apiutils/umetav1"
	"github.com/octelium/octelium/pkg/common/pbutils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
	"google.golang.org/protobuf/reflect/protoreflect"
)

func TestDiff(t *testing.T) {

	currentItems := []umetav1.ResourceObjectI{
		&corev1.User{
			Metadata: &metav1.Metadata{
				Name: "usr1",
			},
			Spec: &corev1.User_Spec{
				Type: corev1.User_Spec_HUMAN,
			},
		},

		&corev1.Service{
			Metadata: &metav1.Metadata{
				Name: "svc1",
			},
			Spec: &corev1.Service_Spec{
				Port: 8080,
			},
		},
		&corev1.Namespace{
			Metadata: &metav1.Metadata{
				Name: "ns1",
			},
			Spec: &corev1.Namespace_Spec{},
		},
	}

	desiredItems := []umetav1.ResourceObjectI{
		&corev1.User{
			Metadata: &metav1.Metadata{
				Name: "usr1",
			},
			Spec: &corev1.User_Spec{
				Type: corev1.User_Spec_HUMAN,
			},
		},

		&corev1.User{
			Metadata: &metav1.Metadata{
				Name: "usr2",
			},
			Spec: &corev1.User_Spec{
				Type: corev1.User_Spec_HUMAN,
			},
		},

		&corev1.Service{
			Metadata: &metav1.Metadata{
				Name: "svc1",
			},
			Spec: &corev1.Service_Spec{
				Port: 8081,
			},
		},
	}

	diffCtl := &diffCtl{
		currentItems: currentItems,
		desiredItems: desiredItems,
	}

	diffCtl.setDiff()

	assert.Equal(t, "usr2", diffCtl.createItems[0].GetMetadata().Name)
	assert.Equal(t, "svc1", diffCtl.updateItems[0].GetMetadata().Name)
	assert.Equal(t, "ns1", diffCtl.deleteItems[0].GetMetadata().Name)
}

func TestDiffUnsetSpec(t *testing.T) {

	currentItems := []umetav1.ResourceObjectI{
		&corev1.Group{
			Metadata: &metav1.Metadata{
				Name: "grp1",
			},
			Spec: &corev1.Group_Spec{},
		},
		&corev1.Group{
			Metadata: &metav1.Metadata{
				Name: "grp2",
			},
			Spec: &corev1.Group_Spec{
				Authorization: &corev1.Group_Spec_Authorization{
					Policies: []string{"allow-all"},
				},
			},
		},
	}

	desiredItems := []umetav1.ResourceObjectI{
		&corev1.Group{
			Metadata: &metav1.Metadata{
				Name: "grp1",
			},
		},
		&corev1.Group{
			Metadata: &metav1.Metadata{
				Name: "grp2",
			},
		},
	}

	diffCtl := &diffCtl{
		kind:         ucorev1.KindGroup,
		currentItems: currentItems,
		desiredItems: desiredItems,
	}

	diffCtl.setDiff()

	assert.Equal(t, 0, len(diffCtl.createItems))
	assert.Equal(t, 0, len(diffCtl.deleteItems))
	assert.Equal(t, 1, len(diffCtl.updateItems))
	assert.Equal(t, "grp2", diffCtl.updateItems[0].GetMetadata().Name)
}

func TestCheckDuplicateItems(t *testing.T) {

	diffCtl := &diffCtl{
		api:  ucorev1.API,
		kind: ucorev1.KindService,
		desiredItems: []umetav1.ResourceObjectI{
			&corev1.Service{
				Kind: ucorev1.KindService,
				Metadata: &metav1.Metadata{
					Name: "svc1",
				},
				Spec: &corev1.Service_Spec{},
			},
			&corev1.Service{
				Kind: ucorev1.KindService,
				Metadata: &metav1.Metadata{
					Name: "svc2.ns1",
				},
				Spec: &corev1.Service_Spec{},
			},
		},
	}

	assert.Nil(t, diffCtl.checkDuplicateItems())

	diffCtl.desiredItems = append(diffCtl.desiredItems, &corev1.Service{
		Kind: ucorev1.KindService,
		Metadata: &metav1.Metadata{
			Name: "svc1.default",
		},
		Spec: &corev1.Service_Spec{},
	})

	assert.NotNil(t, diffCtl.checkDuplicateItems())
}

type fakeMainServiceClient struct {
	corev1.MainServiceClient

	createCount int
	updateCount int
	deleteCount int
}

func (c *fakeMainServiceClient) CreateUser(ctx context.Context,
	req *corev1.User, opts ...grpc.CallOption) (*corev1.User, error) {
	c.createCount++
	return req, nil
}

func (c *fakeMainServiceClient) UpdateUser(ctx context.Context,
	req *corev1.User, opts ...grpc.CallOption) (*corev1.User, error) {
	c.updateCount++
	return req, nil
}

func (c *fakeMainServiceClient) DeleteUser(ctx context.Context,
	req *metav1.DeleteOptions, opts ...grpc.CallOption) (*metav1.OperationResult, error) {
	c.deleteCount++
	return &metav1.OperationResult{}, nil
}

func TestApplyDryRun(t *testing.T) {

	ctx := context.Background()

	newUser := func(name string, typ corev1.User_Spec_Type) *corev1.User {
		return &corev1.User{
			Kind: ucorev1.KindUser,
			Metadata: &metav1.Metadata{
				Name: name,
			},
			Spec: &corev1.User_Spec{
				Type: typ,
			},
		}
	}

	currentItems := []umetav1.ResourceObjectI{
		newUser("usr1", corev1.User_Spec_HUMAN),
		newUser("usr2", corev1.User_Spec_HUMAN),
		newUser("usr3", corev1.User_Spec_HUMAN),
	}

	desiredItems := []umetav1.ResourceObjectI{
		newUser("usr1", corev1.User_Spec_HUMAN),
		newUser("usr2", corev1.User_Spec_WORKLOAD),
		newUser("usr4", corev1.User_Spec_HUMAN),
	}

	for _, doDelete := range []bool{false, true} {
		for _, dryRun := range []bool{false, true} {
			fakeC := &fakeMainServiceClient{}

			diffCtl, err := NewDiffCtl(ucorev1.API, ucorev1.KindUser, fakeC,
				nil, nil, desiredItems, doDelete, dryRun)
			assert.Nil(t, err, "%+v", err)

			diffCtl.currentItems = currentItems
			diffCtl.setDiff()

			ret := &DiffCtlResponse{}

			err = diffCtl.Apply(ctx, ret)
			assert.Nil(t, err, "%+v", err)

			err = diffCtl.Prune(ctx, ret)
			assert.Nil(t, err, "%+v", err)

			assert.Equal(t, 1, ret.CountCreated)
			assert.Equal(t, 1, ret.CountUpdated)
			if doDelete {
				assert.Equal(t, 1, ret.CountDeleted)
			} else {
				assert.Equal(t, 0, ret.CountDeleted)
			}

			if dryRun {
				assert.Equal(t, 0, fakeC.createCount)
				assert.Equal(t, 0, fakeC.updateCount)
				assert.Equal(t, 0, fakeC.deleteCount)
			} else {
				assert.Equal(t, ret.CountCreated, fakeC.createCount)
				assert.Equal(t, ret.CountUpdated, fakeC.updateCount)
				assert.Equal(t, ret.CountDeleted, fakeC.deleteCount)
			}
		}
	}
}

func TestCheckDuplicateCoreResources(t *testing.T) {

	newSvc := func(name string) *corev1.Service {
		return &corev1.Service{
			Kind: ucorev1.KindService,
			Metadata: &metav1.Metadata{
				Name: name,
			},
			Spec: &corev1.Service_Spec{},
		}
	}

	kinds := []string{ucorev1.KindUser, ucorev1.KindGroup, ucorev1.KindService}

	desiredItems := []umetav1.ResourceObjectI{
		newSvc("svc1"),
		newSvc("svc2.ns1"),
		&corev1.User{
			Kind: ucorev1.KindUser,
			Metadata: &metav1.Metadata{
				Name: "usr1",
			},
			Spec: &corev1.User_Spec{},
		},
		&corev1.Group{
			Kind: ucorev1.KindGroup,
			Metadata: &metav1.Metadata{
				Name: "usr1",
			},
			Spec: &corev1.Group_Spec{},
		},
	}

	assert.Equal(t, 0, len(CheckDuplicateCoreResources(kinds, desiredItems)))

	desiredItems = append(desiredItems, newSvc("svc1.default"), newSvc("svc1"))

	errs := CheckDuplicateCoreResources(kinds, desiredItems)
	assert.Equal(t, 1, len(errs))
	assert.True(t, strings.Contains(errs[0].Error(), "svc1.default"), "%+v", errs[0])

	assert.Equal(t, 0, len(CheckDuplicateCoreResources([]string{ucorev1.KindUser}, desiredItems)))
}

type errorMainServiceClient struct {
	corev1.MainServiceClient
	err   error
	calls int
}

func (c *errorMainServiceClient) CreateUser(ctx context.Context, req *corev1.User, opts ...grpc.CallOption) (*corev1.User, error) {
	c.calls++
	return req, c.err
}

func (c *errorMainServiceClient) UpdateUser(ctx context.Context, req *corev1.User, opts ...grpc.CallOption) (*corev1.User, error) {
	c.calls++
	return req, c.err
}

func (c *errorMainServiceClient) DeleteUser(ctx context.Context, req *metav1.DeleteOptions, opts ...grpc.CallOption) (*metav1.OperationResult, error) {
	c.calls++
	return &metav1.OperationResult{}, c.err
}

func (c *errorMainServiceClient) ListUser(ctx context.Context, req *corev1.ListUserOptions, opts ...grpc.CallOption) (*corev1.UserList, error) {
	c.calls++
	return nil, c.err
}

func TestApplyAndPruneErrors(t *testing.T) {
	for _, code := range []codes.Code{codes.OK, codes.InvalidArgument, codes.NotFound, codes.AlreadyExists, codes.PermissionDenied, codes.Unavailable} {
		for _, operation := range []string{"create", "update", "delete"} {
			t.Run(operation+"/"+code.String(), func(t *testing.T) {
				client := &errorMainServiceClient{err: status.Error(code, "operation failed")}
				c, err := NewDiffCtl(ucorev1.API, ucorev1.KindUser, client, nil, nil, nil, true, false)
				require.NoError(t, err)
				items := []umetav1.ResourceObjectI{
					&corev1.User{Metadata: &metav1.Metadata{Name: "first", Uid: "first-uid"}},
					&corev1.User{Metadata: &metav1.Metadata{Name: "second", Uid: "second-uid"}},
				}
				ret := &DiffCtlResponse{}
				switch operation {
				case "create":
					c.createItems = items
					err = c.Apply(context.Background(), ret)
				case "update":
					c.updateItems = items
					err = c.Apply(context.Background(), ret)
				case "delete":
					c.deleteItems = items
					err = c.Prune(context.Background(), ret)
				}
				if code == codes.PermissionDenied || code == codes.Unavailable {
					assert.Equal(t, code, status.Code(err))
					assert.Equal(t, 1, client.calls)
				} else {
					assert.NoError(t, err)
					assert.Equal(t, 2, client.calls)
				}
				if code == codes.OK {
					assert.Equal(t, 2, ret.CountCreated+ret.CountUpdated+ret.CountDeleted)
				} else {
					assert.Equal(t, &DiffCtlResponse{}, ret)
				}
			})
		}
	}
}

func TestDiffLoadErrors(t *testing.T) {
	ctx := context.Background()
	wantErr := errors.New("factory failed")
	newOpts := func() (protoreflect.ProtoMessage, error) { return &corev1.ListUserOptions{}, nil }
	c, err := NewDiffCtl(ucorev1.API, ucorev1.KindUser, &errorMainServiceClient{}, nil,
		func() (protoreflect.ProtoMessage, error) { return nil, wantErr }, nil, false, false)
	require.NoError(t, err)
	assert.ErrorIs(t, c.Load(ctx), wantErr)
	c.newObjectListOptionsFn = newOpts
	c.client = reflect.ValueOf(struct{}{})
	assert.ErrorContains(t, c.Load(ctx), "Unsupported kind")
	item := &corev1.User{Metadata: &metav1.Metadata{Name: "user"}}
	assert.ErrorContains(t, c.doCreateItem(ctx, item), "Unsupported kind")
	assert.ErrorContains(t, c.doUpdateItem(ctx, item), "Unsupported kind")
	assert.ErrorContains(t, c.doDeleteItem(ctx, item), "Unsupported kind")
	c.client = reflect.ValueOf(&errorMainServiceClient{err: status.Error(codes.PermissionDenied, "denied")})
	assert.Equal(t, codes.PermissionDenied, status.Code(c.Load(ctx)))
	c.desiredItems = []umetav1.ResourceObjectI{item, item}
	assert.ErrorContains(t, c.Load(ctx), "defined more than once")
}

func TestDiffMetadataAndData(t *testing.T) {
	c := &diffCtl{api: ucorev1.API, kind: ucorev1.KindService}
	a := &corev1.Service{Kind: ucorev1.KindService, Metadata: &metav1.Metadata{Name: "api", Uid: "one"}, Spec: &corev1.Service_Spec{Port: 443}}
	b := &corev1.Service{Kind: ucorev1.KindService, Metadata: &metav1.Metadata{Name: "api.default", Uid: "two"}, Spec: &corev1.Service_Spec{Port: 443}}
	assert.True(t, c.isEqual(a, b))
	for _, mutate := range []func(*corev1.Service){
		func(itm *corev1.Service) { itm.Metadata.DisplayName = "display" },
		func(itm *corev1.Service) { itm.Metadata.Description = "description" },
		func(itm *corev1.Service) { itm.Metadata.Labels = map[string]string{"team": "platform"} },
		func(itm *corev1.Service) { itm.Metadata.Annotations = map[string]string{"key": "value"} },
		func(itm *corev1.Service) { itm.Metadata.Tags = []string{"production"} },
		func(itm *corev1.Service) { itm.Metadata.PicURL = "https://example.com/icon" },
		func(itm *corev1.Service) { itm.Spec.Port = 8443 },
	} {
		cur := pbutils.Clone(b).(*corev1.Service)
		mutate(cur)
		assert.False(t, c.isEqual(a, cur))
	}
	assert.NotNil(t, getFieldSpec(&corev1.Secret{}))
	secret := &corev1.Secret{Metadata: &metav1.Metadata{Name: "secret"}, Data: &corev1.Secret_Data{}}
	assert.True(t, hasFieldData(secret))
	assert.Len(t, c.getDiffUpdate([]umetav1.ResourceObjectI{secret}, []umetav1.ResourceObjectI{secret}), 1)
}

func TestDiffCoreResourcesE2E(t *testing.T) {
	for _, dryRun := range []bool{false, true} {
		for _, doDelete := range []bool{false, true} {
			t.Run(fmt.Sprintf("dryRun=%t/delete=%t", dryRun, doDelete), func(t *testing.T) {
				var mu sync.Mutex
				var events []string
				current := map[string]umetav1.ResourceObjectI{
					"Namespace/old":    &corev1.Namespace{Kind: ucorev1.KindNamespace, Metadata: &metav1.Metadata{Name: "old", Uid: "old-ns"}},
					"Namespace/system": &corev1.Namespace{Kind: ucorev1.KindNamespace, Metadata: &metav1.Metadata{Name: "system", IsSystem: true}},
					"Service/api.new":  &corev1.Service{Kind: ucorev1.KindService, Metadata: &metav1.Metadata{Name: "api.new", Uid: "api"}, Spec: &corev1.Service_Spec{Port: 80}},
					"Service/old.old":  &corev1.Service{Kind: ucorev1.KindService, Metadata: &metav1.Metadata{Name: "old.old", Uid: "old-svc"}},
				}
				lis := bufconn.Listen(1 << 20)
				srv := grpc.NewServer(grpc.UnaryInterceptor(func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
					mu.Lock()
					defer mu.Unlock()
					method := info.FullMethod[strings.LastIndex(info.FullMethod, "/")+1:]
					switch method {
					case "ListNamespace":
						arg := req.(*corev1.ListNamespaceOptions)
						page := arg.GetCommon().GetPage()
						events = append(events, fmt.Sprintf("list Namespace %d", page))
						items := []*corev1.Namespace{}
						for _, item := range current {
							if ns, ok := item.(*corev1.Namespace); ok {
								items = append(items, ns)
							}
						}
						slices.SortFunc(items, func(a, b *corev1.Namespace) int { return strings.Compare(a.Metadata.Name, b.Metadata.Name) })
						if int(page) >= len(items) {
							return &corev1.NamespaceList{}, nil
						}
						return &corev1.NamespaceList{Items: items[page : page+1], ListResponseMeta: &metav1.ListResponseMeta{HasMore: int(page)+1 < len(items)}}, nil
					case "ListService":
						events = append(events, "list Service")
						items := []*corev1.Service{}
						for _, item := range current {
							if svc, ok := item.(*corev1.Service); ok {
								items = append(items, svc)
							}
						}
						return &corev1.ServiceList{Items: items}, nil
					case "CreateNamespace", "CreateService", "UpdateService":
						item := req.(umetav1.ResourceObjectI)
						key := item.GetKind() + "/" + item.GetMetadata().Name
						events = append(events, method+" "+key)
						current[key] = item
						return item, nil
					case "DeleteNamespace", "DeleteService":
						uid := req.(*metav1.DeleteOptions).Uid
						events = append(events, method+" "+uid)
						for key, item := range current {
							if item.GetMetadata().Uid == uid {
								delete(current, key)
							}
						}
						return &metav1.OperationResult{}, nil
					}
					return handler(ctx, req)
				}))
				corev1.RegisterMainServiceServer(srv, &corev1.UnimplementedMainServiceServer{})
				go srv.Serve(lis)
				t.Cleanup(srv.Stop)
				conn, err := grpc.NewClient("passthrough:///bufconn", grpc.WithTransportCredentials(insecure.NewCredentials()),
					grpc.WithContextDialer(func(ctx context.Context, addr string) (net.Conn, error) { return lis.DialContext(ctx) }))
				require.NoError(t, err)
				t.Cleanup(func() { conn.Close() })
				path := filepath.Join(t.TempDir(), "resources.yaml")
				require.NoError(t, os.WriteFile(path, []byte("kind: Namespace\nmetadata:\n  name: new\n---\nkind: Service\nmetadata:\n  name: api.new\nspec:\n  port: 443\n---\nkind: Service\nmetadata:\n  name: web.new\nspec:\n  port: 8080\n"), 0600))
				desired, err := resources.LoadCoreResources(path)
				require.NoError(t, err)
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				ret, err := DiffCoreResources(ctx, []string{ucorev1.KindNamespace, ucorev1.KindService}, conn, desired, doDelete, dryRun)
				require.NoError(t, err)
				assert.Equal(t, 2, ret.CountCreated)
				assert.Equal(t, 1, ret.CountUpdated)
				if doDelete {
					assert.Equal(t, 2, ret.CountDeleted)
				} else {
					assert.Zero(t, ret.CountDeleted)
				}
				mu.Lock()
				gotEvents := slices.Clone(events)
				_, systemExists := current["Namespace/system"]
				mu.Unlock()
				assert.True(t, systemExists)
				assert.Equal(t, []string{"list Namespace 0", "list Namespace 1", "list Service"}, gotEvents[:3])
				if dryRun {
					assert.Len(t, gotEvents, 3)
				} else {
					assert.Equal(t, []string{"CreateNamespace Namespace/new", "CreateService Service/web.new", "UpdateService Service/api.new"}, gotEvents[3:6])
					if doDelete {
						assert.Equal(t, []string{"DeleteService old-svc", "DeleteNamespace old-ns"}, gotEvents[6:])
					}
					ret, err = DiffCoreResources(ctx, []string{ucorev1.KindNamespace, ucorev1.KindService}, conn, desired, doDelete, false)
					require.NoError(t, err)
					assert.Equal(t, &DiffCtlResponse{}, ret)
				}
			})
		}
	}
}
