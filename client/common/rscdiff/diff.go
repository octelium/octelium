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
	"fmt"
	"reflect"
	"strings"

	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/apis/main/metav1"
	"github.com/octelium/octelium/client/common/cliutils"
	"github.com/octelium/octelium/pkg/apiutils/ucorev1"
	"github.com/octelium/octelium/pkg/apiutils/umetav1"
	"github.com/octelium/octelium/pkg/common/pbutils"
	"github.com/octelium/octelium/pkg/grpcerr"
	"github.com/pkg/errors"
	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
)

func (c *diffCtl) isEqual(a, b umetav1.ResourceObjectI) bool {
	return pbutils.IsEqual(c.getCmpMetadata(a), c.getCmpMetadata(b)) &&
		pbutils.IsEqual(getFieldSpec(a), getFieldSpec(b))
}

func (c *diffCtl) getCmpMetadata(itm umetav1.ResourceObjectI) *metav1.Metadata {
	md := itm.GetMetadata()
	return &metav1.Metadata{
		Name:        c.getFullName(itm),
		DisplayName: md.DisplayName,
		Labels:      md.Labels,
		Description: md.Description,
		Annotations: md.Annotations,
		PicURL:      md.PicURL,
	}
}

func (c *diffCtl) getFullName(itm umetav1.ResourceObjectI) string {
	name := itm.GetMetadata().Name
	switch c.api {
	case ucorev1.API:
		switch itm.GetKind() {
		case ucorev1.KindService:
			if len(strings.Split(name, ".")) == 1 {
				return fmt.Sprintf("%s.default", name)
			}
		}

	}
	return itm.GetMetadata().Name
}

func DiffCoreResource(ctx context.Context,
	kind string, conn *grpc.ClientConn, desiredItems []umetav1.ResourceObjectI, doDelete bool) (*DiffCtlResponse, error) {
	ctl, err := NewDiffCtl("core", kind, corev1.NewMainServiceClient(conn),
		func() (umetav1.ResourceObjectI, error) {
			return ucorev1.NewObject(kind)
		}, func() (protoreflect.ProtoMessage, error) {
			return ucorev1.NewObjectListOptions(kind)
		}, desiredItems, doDelete)
	if err != nil {
		return nil, err
	}

	return ctl.Run(ctx)
}

type diffCtl struct {
	api          string
	kind         string
	client       reflect.Value
	desiredItems []umetav1.ResourceObjectI
	currentItems []umetav1.ResourceObjectI

	createItems []umetav1.ResourceObjectI
	updateItems []umetav1.ResourceObjectI
	deleteItems []umetav1.ResourceObjectI

	doDelete bool

	getNewObjectFn         func() (umetav1.ResourceObjectI, error)
	newObjectListOptionsFn func() (protoreflect.ProtoMessage, error)
}

func NewDiffCtl(api, kind string, client any,
	getNewObjectFn func() (umetav1.ResourceObjectI, error),
	newObjectListOptionsFn func() (protoreflect.ProtoMessage, error),
	desiredItems []umetav1.ResourceObjectI, doDelete bool) (*diffCtl, error) {

	var filteredDesiredItems []umetav1.ResourceObjectI
	for _, itm := range desiredItems {
		if itm.GetKind() == kind {
			filteredDesiredItems = append(filteredDesiredItems, itm)
		}
	}

	return &diffCtl{
		api:                    api,
		kind:                   kind,
		client:                 reflect.ValueOf(client),
		desiredItems:           filteredDesiredItems,
		doDelete:               doDelete,
		getNewObjectFn:         getNewObjectFn,
		newObjectListOptionsFn: newObjectListOptionsFn,
	}, nil
}

type DiffCtlResponse struct {
	CountCreated int
	CountUpdated int
	CountDeleted int
}

func (c *diffCtl) Run(ctx context.Context) (*DiffCtlResponse, error) {

	ret := &DiffCtlResponse{}
	if err := c.setCurrentItems(ctx); err != nil {
		return nil, err
	}

	c.setDiff()

	for _, itm := range c.createItems {
		if err := c.doCreateItem(ctx, itm); err != nil {
			if isUserError(err) {
				cliutils.LineWarn("Could not create %s %s. %s\n",
					c.kind, itm.GetMetadata().Name, cliutils.GrpcErr(err))
				continue
			}

			return nil, err
		}
		ret.CountCreated += 1
		cliutils.LineNotify("%s: %s Created\n", c.kind, itm.GetMetadata().Name)
	}

	for _, itm := range c.updateItems {
		if err := c.doUpdateItem(ctx, itm); err != nil {
			if isUserError(err) {
				cliutils.LineWarn("Could not update %s %s. %s\n",
					c.kind, itm.GetMetadata().Name, cliutils.GrpcErr(err))
				continue
			}
			return nil, err
		}
		ret.CountUpdated += 1
		cliutils.LineNotify("%s: %s Updated\n", c.kind, itm.GetMetadata().Name)
	}

	if c.doDelete {
		for _, itm := range c.deleteItems {
			if err := c.doDeleteItem(ctx, itm); err != nil {
				if grpcerr.IsNotFound(err) {
					continue
				}
				return nil, err
			}
			ret.CountDeleted += 1
			cliutils.LineNotify("%s: %s Deleted\n", c.kind, itm.GetMetadata().Name)
		}
	}

	return ret, nil
}

func isUserError(err error) bool {
	return grpcerr.IsInvalidArg(err) || grpcerr.IsNotFound(err) ||
		grpcerr.AlreadyExists(err) || grpcerr.IsResourceChanged(err)
}

func getFieldSpec(item umetav1.ResourceObjectI) proto.Message {
	var spec protoreflect.Value

	item.ProtoReflect().Range(func(fd protoreflect.FieldDescriptor, v protoreflect.Value) bool {
		if fd.Name() == "spec" {
			spec = v
		}
		return true
	})

	return spec.Message().Interface()
}

func hasFieldData(item umetav1.ResourceObjectI) bool {
	var ret bool

	item.ProtoReflect().Range(func(fd protoreflect.FieldDescriptor, v protoreflect.Value) bool {
		if fd.Name() == "data" {
			ret = true
		}
		return true
	})

	return ret
}

func (c *diffCtl) setCurrentItems(ctx context.Context) error {

	hasMore := true
	page := 0

	for hasMore {
		listOpts, err := c.newObjectListOptionsFn()
		if err != nil {
			return err
		}

		listOptsMap := pbutils.MustConvertToMap(listOpts)
		listOptsMap["common"] = map[string]any{
			"page": page,
		}

		if err := pbutils.UnmarshalFromMap(listOptsMap, listOpts); err != nil {
			return err
		}

		res := c.client.MethodByName(fmt.Sprintf("List%s", c.kind)).Call(
			[]reflect.Value{
				reflect.ValueOf(ctx),
				reflect.ValueOf(listOpts),
			},
		)

		if len(res) != 2 {
			return errors.Errorf("Invalid reflect ret len")
		}

		if res[1].Interface() != nil {
			return res[1].Interface().(error)
		}

		if res[0].Interface() == nil {
			return errors.Errorf("Could not run watcher. Client stream is nil")
		}
		callRes := res[0].Interface().(umetav1.ObjectI)

		retMap, err := pbutils.ConvertToMap(callRes)
		if err != nil {
			return err
		}

		listResponseMetaMap, ok := retMap["listResponseMeta"].(map[string]any)
		if ok && listResponseMetaMap != nil {
			hasMore, _ = listResponseMetaMap["hasMore"].(bool)
			if hasMore {
				zap.L().Debug("There are more pages",
					zap.String("kind", c.kind),
					zap.Any("listResponseMeta", listResponseMetaMap))
				page += 1
			} else {
				zap.L().Debug("No more pages",
					zap.String("kind", c.kind),
					zap.Any("listResponseMeta", listResponseMetaMap))
			}
		} else {
			hasMore = false
			zap.L().Debug("Could not find listResponseMeta in response",
				zap.String("kind", c.kind))
		}

		if retMap["items"] == nil {
			return nil
		}

		retItemsMap := retMap["items"].([]any)

		for _, itmMapAny := range retItemsMap {
			itmMap := itmMapAny.(map[string]any)

			itm, err := c.getNewObjectFn()
			if err != nil {
				return err
			}
			if err := pbutils.UnmarshalFromMap(itmMap, itm); err != nil {
				return err
			}
			if itm.GetMetadata().IsSystem {
				continue
			}

			c.currentItems = append(c.currentItems, itm)
		}
	}

	return nil
}

func (c *diffCtl) setDiff() {

	c.createItems = c.getDiffCreate(c.desiredItems, c.currentItems)
	c.updateItems = c.getDiffUpdate(c.desiredItems, c.currentItems)
	c.deleteItems = c.getDiffDelete(c.desiredItems, c.currentItems)
}

func (c *diffCtl) getDiffCreate(desiredItems, currentItems []umetav1.ResourceObjectI) []umetav1.ResourceObjectI {
	var ret []umetav1.ResourceObjectI
	for _, itm := range desiredItems {
		if !c.isInList(currentItems, itm) {
			ret = append(ret, itm)
		}
	}

	return ret
}

func (c *diffCtl) getDiffUpdate(desiredItems, currentItems []umetav1.ResourceObjectI) []umetav1.ResourceObjectI {
	var ret []umetav1.ResourceObjectI
	for _, itm := range desiredItems {
		cur := c.getInList(currentItems, itm)
		if cur == nil {
			continue
		}

		if hasFieldData(itm) {
			ret = append(ret, itm)
		} else if !c.isEqual(itm, cur) {
			ret = append(ret, itm)
		}
	}

	return ret
}

func (c *diffCtl) getDiffDelete(desiredItems, currentItems []umetav1.ResourceObjectI) []umetav1.ResourceObjectI {
	var ret []umetav1.ResourceObjectI
	for _, itm := range currentItems {
		if !c.isInList(desiredItems, itm) {
			ret = append(ret, itm)
		}
	}
	return ret
}

func (c *diffCtl) isInList(lst []umetav1.ResourceObjectI, cur umetav1.ResourceObjectI) bool {
	for _, itm := range lst {
		if c.getFullName(itm) == c.getFullName(cur) {
			return true
		}
	}
	return false
}

func (c *diffCtl) getInList(lst []umetav1.ResourceObjectI, cur umetav1.ResourceObjectI) umetav1.ResourceObjectI {
	for _, itm := range lst {
		if c.getFullName(itm) == c.getFullName(cur) {
			return itm
		}
	}
	return nil
}

func (c diffCtl) doCreateItem(ctx context.Context, item umetav1.ResourceObjectI) error {

	zap.L().Debug("Creating item", zap.Any("item", item))

	res := c.client.MethodByName(fmt.Sprintf("Create%s", c.kind)).Call(
		[]reflect.Value{
			reflect.ValueOf(ctx),
			reflect.ValueOf(item),
		},
	)

	if len(res) != 2 {
		return errors.Errorf("Invalid reflect ret len")
	}

	if res[1].Interface() != nil {
		return res[1].Interface().(error)
	}

	return nil
}

func (c *diffCtl) doUpdateItem(ctx context.Context, item umetav1.ResourceObjectI) error {

	zap.L().Debug("Updating item", zap.Any("item", item))

	res := c.client.MethodByName(fmt.Sprintf("Update%s", c.kind)).Call(
		[]reflect.Value{
			reflect.ValueOf(ctx),
			reflect.ValueOf(item),
		},
	)

	if len(res) != 2 {
		return errors.Errorf("Invalid reflect ret len")
	}

	if res[1].Interface() != nil {
		return res[1].Interface().(error)
	}

	return nil
}

func (c *diffCtl) doDeleteItem(ctx context.Context, item umetav1.ResourceObjectI) error {

	zap.L().Debug("Deleting item", zap.Any("item", item))

	res := c.client.MethodByName(fmt.Sprintf("Delete%s", c.kind)).Call(
		[]reflect.Value{
			reflect.ValueOf(ctx),
			reflect.ValueOf(&metav1.DeleteOptions{
				Uid: item.GetMetadata().Uid,
			}),
		},
	)

	if len(res) != 2 {
		return errors.Errorf("Invalid reflect ret len")
	}

	if res[1].Interface() != nil {
		return res[1].Interface().(error)
	}

	return nil
}
