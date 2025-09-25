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

package rscserver

import (
	"context"
	"database/sql"
	"fmt"
	"regexp"
	"strings"

	"github.com/asaskevich/govalidator"
	"github.com/doug-martin/goqu/v9"
	"github.com/doug-martin/goqu/v9/exp"
	"github.com/go-redis/redis/v8"
	"github.com/octelium/octelium/apis/main/metav1"
	"github.com/octelium/octelium/apis/rsc/rmetav1"
	"github.com/octelium/octelium/cluster/common/grpcutils"
	"github.com/octelium/octelium/cluster/common/vutils"
	"github.com/octelium/octelium/cluster/rscserver/rscserver/rerr"
	"github.com/octelium/octelium/pkg/apiutils/umetav1"
	"github.com/octelium/octelium/pkg/common/pbutils"
	"github.com/octelium/octelium/pkg/grpcerr"
	"github.com/octelium/octelium/pkg/utils/ldflags"
	"github.com/pkg/errors"
	"go.uber.org/zap"
	"google.golang.org/grpc/metadata"
)

var rgxName = regexp.MustCompile(`^[a-z0-9][a-z0-9-:]{0,52}[a-z0-9]$`)

const tableName = "octelium_resources"

const defaultItemsPerPage = 200
const maxItemsPerPage = 1000

func checkName(arg string) error {
	ln := len(arg)
	if ln == 0 {
		return errors.Errorf("Empty name")
	}
	if ln < 2 {
		return errors.Errorf("Name must contain at least 2 characters: %s", arg)
	}
	if ln > 140 {
		return errors.Errorf("Name is too long: %s", arg)
	}
	nameArgs := strings.Split(arg, ".")
	if len(nameArgs) > vutils.MaxNameSubArgs {
		return errors.Errorf("Invalid name format: %s", arg)
	}

	for _, nameArg := range nameArgs {
		if !rgxName.MatchString(nameArg) {
			return errors.Errorf("Invalid name: %s", arg)
		}
	}

	return nil
}

func checkListOptions(req *rmetav1.ListOptions) error {

	return nil
}

func checkGetOptions(req *rmetav1.GetOptions) error {
	if req.Name == "" && req.Uid == "" {
		return errors.Errorf("At least either the name or the UID must be specified")
	}
	if req.Name != "" {
		if err := checkName(req.Name); err != nil {
			return err
		}
	}

	if req.Uid != "" && !govalidator.IsUUIDv4(req.Uid) {
		return errors.Errorf("Invalid UID: %s", req.Uid)
	}

	return nil
}

func (s *Server) doGet(ctx context.Context, req *rmetav1.GetOptions, api, version, kind string) (umetav1.ResourceObjectI, error) {

	if err := checkGetOptions(req); err != nil {
		return nil, rerr.InvalidWithErr(err)
	}

	if !ldflags.IsTest() {
		cached, found, err := s.doGetCache(ctx, req, api, version, kind)
		if err == nil && found {
			return cached, nil
		}
		if err != nil {
			zap.L().Warn("Could not get cached value", zap.Error(err))
		}
	}

	var filters []exp.Expression

	filters = append(filters, goqu.C("api").Eq(api))
	filters = append(filters, goqu.C("version").Eq(version))
	filters = append(filters, goqu.C("kind").Eq(kind))

	if req.Name != "" {
		filters = append(filters, goqu.L(`resource->'metadata'->>'name'`).Eq(req.Name))
	} else if req.Uid != "" {
		filters = append(filters, goqu.L(`resource->'metadata'->>'uid'`).Eq(req.Uid))
	} else {
		return nil, rerr.InvalidWithErr(errors.Errorf("GetOptions have no args"))
	}

	ds := goqu.From(tableName).Where(filters...).Select("resource")
	sqln, sqlargs, err := ds.ToSQL()
	if err != nil {
		return nil, rerr.InternalWithErr(err)
	}

	var attr []byte

	if err := s.db.QueryRowContext(ctx, sqln, sqlargs...).Scan(&attr); err != nil {
		if err == sql.ErrNoRows {
			identifier := req.Name
			if identifier == "" {
				identifier = req.Uid
			}
			return nil, rerr.NotFound("%s.%s.%s %s does not exist", api, version, kind, identifier)
		}
		return nil, rerr.InternalWithErr(err)
	}

	ret, err := s.opts.NewResourceObject(api, version, kind)
	if err != nil {
		return nil, err
	}

	if err := pbutils.UnmarshalJSON(attr, ret); err != nil {
		return nil, rerr.InternalWithErr(err)
	}

	ret, err = s.handleSecretManagerGet(ctx, ret, api, version, kind)
	if err != nil {
		return nil, err
	}

	if s.opts.PostGet != nil {
		if err := s.opts.PostGet(ctx, ret, api, version, kind); err != nil {
			return nil, err
		}
	}

	s.doSetCache(ctx, ret, api, version, kind)

	return ret, nil
}

func (s *Server) CreateResource(ctx context.Context, req umetav1.ResourceObjectI, api, version, kind string) (umetav1.ResourceObjectI, error) {
	return s.doCreate(ctx, req, api, version, kind)
}

func (s *Server) GetResource(ctx context.Context, req *rmetav1.GetOptions, api, version, kind string) (umetav1.ResourceObjectI, error) {
	return s.doGet(ctx, req, api, version, kind)
}

func (s *Server) doCreate(ctx context.Context, req umetav1.ResourceObjectI, api, version, kind string) (umetav1.ResourceObjectI, error) {

	reqMap, err := pbutils.ConvertToMap(req)
	if err != nil {
		return nil, err
	}

	reqMap["kind"] = kind
	reqMap["apiVersion"] = vutils.GetApiVersion(api, version)

	if reqMap["spec"] == nil {
		reqMap["spec"] = map[string]any{}
	}
	if reqMap["status"] == nil {
		reqMap["status"] = map[string]any{}
	}

	req, err = s.opts.NewResourceObject(api, version, kind)
	if err != nil {
		return nil, err
	}

	if err := pbutils.UnmarshalFromMap(reqMap, req); err != nil {
		return nil, err
	}

	md := req.GetMetadata()

	if md == nil {
		return nil, grpcutils.InvalidArg("Nil Metadata")
	}

	{
		getOpts := &rmetav1.GetOptions{Name: md.Name}
		if err := checkGetOptions(getOpts); err != nil {
			return nil, rerr.InvalidWithErr(err)
		}

		_, err := s.doGet(ctx, getOpts, api, version, kind)
		if err == nil {
			return nil, rerr.AlreadyExistsWithErr(
				errors.Errorf("%s.%s.%s %s already exists", api, version, kind, md.Name))
		}
		if !grpcerr.IsNotFound(err) {
			return nil, err
		}
	}

	md.CreatedAt = pbutils.Now()
	md.Uid = vutils.UUIDv4()
	md.ResourceVersion = vutils.UUIDv7()
	md.ActorRef = getActorRef(ctx)
	md.ActorOperation = getActorOp(ctx)

	req, err = s.handleSecretManagerSet(ctx, req, api, version, kind)
	if err != nil {
		return nil, err
	}

	reqJSONBytes, err := pbutils.MarshalJSON(req, false)
	if err != nil {
		return nil, rerr.InternalWithErr(err)
	}

	ds := goqu.Insert(tableName).
		Cols("uid", "created_at", "api", "version", "kind", "resource").
		Vals(goqu.Vals{md.Uid, md.CreatedAt.AsTime(), api, version, kind, string(reqJSONBytes)})

	sqln, sqlargs, err := ds.ToSQL()
	if err != nil {
		return nil, rerr.InternalWithErr(err)
	}

	if s.opts.PreCreate != nil {
		if err := s.opts.PreCreate(ctx, req, api, version, kind); err != nil {
			return nil, err
		}
	}

	_, err = s.db.ExecContext(ctx, sqln, sqlargs...)
	if err != nil {
		return nil, rerr.InternalWithErr(err)
	}

	if s.isTypeSecret(kind) {
		req, err = s.doGet(ctx, &rmetav1.GetOptions{
			Uid: md.Uid,
		}, api, version, kind)
		if err != nil {
			return nil, err
		}
	}

	if s.opts.PostCreate != nil {
		if err := s.opts.PostCreate(ctx, req, api, version, kind); err != nil {
			return nil, err
		}
	}

	if err := s.doPostCreate(ctx, req, api, version, kind); err != nil {
		zap.L().Warn("Could not do postCreate", zap.Error(err))
	}

	return req, nil
}

func (s *Server) doUpdate(ctx context.Context, req umetav1.ResourceObjectI, api, version, kind string) (umetav1.ResourceObjectI, umetav1.ResourceObjectI, error) {

	mdNew := req.GetMetadata()
	if mdNew == nil {
		return nil, nil, grpcutils.InvalidArg("Nil Metadata")
	}

	old, err := s.doGet(ctx, &rmetav1.GetOptions{
		Uid: mdNew.Uid,
	}, api, version, kind)
	if err != nil {
		return nil, nil, err
	}

	if old.GetMetadata().ResourceVersion != mdNew.ResourceVersion {
		return nil, nil, rerr.ResourceChanged(
			errors.Errorf("Cannot Update. %s.%s.%s %s has already changed",
				api, version, kind, old.GetMetadata().Name))
	}

	if pbutils.IsEqual(req, old) {
		return req, old, nil
	}

	mdNew.LastResourceVersion = mdNew.ResourceVersion
	mdNew.ResourceVersion = vutils.UUIDv7()
	mdNew.UpdatedAt = pbutils.Now()
	mdNew.ActorRef = getActorRef(ctx)
	mdNew.ActorOperation = getActorOp(ctx)

	req, err = s.handleSecretManagerSet(ctx, req, api, version, kind)
	if err != nil {
		return nil, nil, err
	}

	reqJSONBytes, err := pbutils.MarshalJSON(req, false)
	if err != nil {
		return nil, nil, rerr.InternalWithErr(err)
	}

	ds := goqu.Update(tableName).Where(goqu.C("uid").Eq(mdNew.Uid)).Set(
		goqu.Record{"resource": string(reqJSONBytes)},
	)

	sqln, sqlargs, err := ds.ToSQL()
	if err != nil {
		return nil, nil, rerr.InternalWithErr(err)
	}

	if s.opts.PreUpdate != nil {
		if err := s.opts.PreUpdate(ctx, req, old, api, version, kind); err != nil {
			return nil, nil, err
		}
	}

	if _, err := s.db.ExecContext(ctx, sqln, sqlargs...); err != nil {
		return nil, nil, rerr.InternalWithErr(err)
	}

	if s.isTypeSecret(kind) {
		req, err = s.doGet(ctx, &rmetav1.GetOptions{
			Uid: mdNew.Uid,
		}, api, version, kind)
		if err != nil {
			return nil, nil, err
		}
	}

	if s.opts.PostUpdate != nil {
		if err := s.opts.PostUpdate(ctx, req, old, api, version, kind); err != nil {
			return nil, nil, err
		}
	}

	if s.doPostUpdate(ctx, req, old, api, version, kind); err != nil {
		zap.L().Warn("Could not do postUpdate", zap.Error(err))
	}

	return req, old, nil
}

func (s *Server) doList(ctx context.Context,
	req *rmetav1.ListOptions, api, version, kind string) ([]umetav1.ResourceObjectI, *metav1.ListResponseMeta, error) {
	var filters []exp.Expression
	var retItems []umetav1.ResourceObjectI

	listMeta := &metav1.ListResponseMeta{}

	filters = append(filters, goqu.C("api").Eq(api))
	filters = append(filters, goqu.C("version").Eq(version))
	filters = append(filters, goqu.C("kind").Eq(kind))

	if err := checkListOptions(req); err != nil {
		return nil, nil, rerr.InvalidWithErr(err)
	}

	{
		if req.SpecLabels != nil {
			for k, v := range req.SpecLabels {
				filters = append(filters,
					goqu.L(fmt.Sprintf(`resource->'metadata'->'specLabels'->>'%s'`, k)).Eq(v))
			}
		}

		if req.SpecLabelsORed != nil {
			oredFilters := []exp.Expression{}
			for k, v := range req.SpecLabelsORed {
				oredFilters = append(oredFilters,
					goqu.L(fmt.Sprintf(`resource->'metadata'->'specLabels'->>'%s'`, k)).Eq(v))
			}

			filters = append(filters, goqu.Or(oredFilters...))
		}
	}

	{
		if req.SystemLabels != nil {
			for k, v := range req.SystemLabels {
				filters = append(filters,
					goqu.L(fmt.Sprintf(`resource->'metadata'->'systemLabels'->>'%s'`, k)).Eq(v))
			}
		}

		if req.SystemLabelsORed != nil {
			oredFilters := []exp.Expression{}
			for k, v := range req.SystemLabelsORed {
				oredFilters = append(oredFilters,
					goqu.L(fmt.Sprintf(`resource->'metadata'->'systemLabels'->>'%s'`, k)).Eq(v))
			}

			filters = append(filters, goqu.Or(oredFilters...))
		}
	}

	if len(req.Filters) > 0 {
		filters = append(filters, getListFilters(req)...)
	}

	ds := goqu.From(tableName).Where(filters...).
		Select("resource", goqu.L(`count(*) OVER() AS full_count`))
	if req.Paginate {
		limit := req.ItemsPerPage
		if req.Page > 10000 {
			return nil, nil, rerr.InvalidWithErr(errors.Errorf("Page number is too high"))
		}

		if limit == 0 {
			limit = defaultItemsPerPage
		} else if limit > maxItemsPerPage {
			limit = maxItemsPerPage
		}

		offset := req.Page * limit

		ds = ds.Offset(uint(offset)).Limit(uint(limit))

		listMeta.ItemsPerPage = limit
		listMeta.Page = req.Page
	}

	if len(req.OrderBy) > 0 {
		for _, order := range req.OrderBy {
			switch order.Type {
			case rmetav1.ListOptions_OrderBy_TYPE_CREATED_AT:
				if order.Mode == rmetav1.ListOptions_OrderBy_MODE_DESC {
					ds = ds.OrderAppend(goqu.I(`created_at`).Desc())
				} else {

					ds = ds.OrderAppend(goqu.I(`created_at`).Asc())
				}
			case rmetav1.ListOptions_OrderBy_TYPE_NAME:

				if order.Mode == rmetav1.ListOptions_OrderBy_MODE_DESC {

					ds = ds.OrderAppend(goqu.L(`resource->'metadata'->>'name'`).Desc())
				} else {
					ds = ds.OrderAppend(goqu.L(`resource->'metadata'->>'name'`).Asc())
				}
			default:
				ds = ds.Order(goqu.I(`id`).Asc())
			}
		}
	} else {
		ds = ds.Order(goqu.I(`id`).Asc())
	}

	sqln, sqlargs, err := ds.ToSQL()
	if err != nil {
		return nil, nil, rerr.InternalWithErr(err)
	}

	rows, err := s.db.QueryContext(ctx, sqln, sqlargs...)
	if err != nil {
		return nil, nil, rerr.InternalWithErr(err)
	}

	for rows.Next() {
		var data []byte
		var count int
		if err := rows.Scan(&data, &count); err != nil {
			return nil, nil, rerr.InternalWithErr(err)
		}

		listMeta.TotalCount = uint32(count)

		obj, err := s.opts.NewResourceObject(api, version, kind)
		if err != nil {
			return nil, nil, rerr.InternalWithErr(err)
		}

		if err := pbutils.UnmarshalJSON(data, obj); err != nil {
			return nil, nil, rerr.InternalWithErr(err)
		}
		retItems = append(retItems, obj)
	}

	if len(retItems) == 0 && req.Page > 0 {
		return nil, nil, rerr.NotFound("Not Items found for that page")
	}

	if err := rows.Err(); err != nil {
		return nil, nil, rerr.InternalWithErr(err)
	}

	retItems, err = s.handleSecretManagerList(ctx, retItems, api, version, kind)
	if err != nil {
		return nil, nil, err
	}

	objList := &ObjectList{
		Items: retItems,
	}

	if s.opts.PostList != nil {
		if err := s.opts.PostList(ctx, objList, api, version, kind); err != nil {
			return nil, nil, err
		}
	}

	if listMeta.TotalCount > (listMeta.Page+1)*listMeta.ItemsPerPage {
		listMeta.HasMore = true
	}

	return objList.Items, listMeta, nil
}

func (s *Server) doDelete(ctx context.Context, req *rmetav1.DeleteOptions, api, version, kind string) (umetav1.ResourceObjectI, error) {

	getOpts := &rmetav1.GetOptions{
		Name: req.Name,
		Uid:  req.Uid,
	}

	if err := checkGetOptions(getOpts); err != nil {
		return nil, rerr.InvalidWithErr(err)
	}

	itm, err := s.doGet(ctx, getOpts, api, version, kind)
	if err != nil {
		return nil, err
	}

	ds := goqu.Delete(tableName).Where(goqu.C("uid").Eq(itm.GetMetadata().Uid))

	sqln, sqlargs, err := ds.ToSQL()
	if err != nil {
		return nil, rerr.InternalWithErr(err)
	}

	if err := s.handleSecretManagerDelete(ctx, itm, api, version, kind); err != nil {
		return nil, err
	}

	if s.opts.PreDelete != nil {
		if err := s.opts.PreDelete(ctx, itm, api, version, kind); err != nil {
			return nil, err
		}
	}

	_, err = s.db.ExecContext(ctx, sqln, sqlargs...)
	if err != nil {
		return nil, rerr.InternalWithErr(err)
	}

	md := itm.GetMetadata()

	md.LastResourceVersion = md.ResourceVersion
	md.ResourceVersion = vutils.UUIDv7()
	md.UpdatedAt = pbutils.Now()
	md.ActorRef = getActorRef(ctx)
	md.ActorOperation = getActorOp(ctx)

	if s.opts.PostDelete != nil {
		if err := s.opts.PostDelete(ctx, itm, api, version, kind); err != nil {
			return nil, err
		}
	}

	if err := s.doPostDelete(ctx, itm, api, version, kind); err != nil {
		zap.L().Error("Could not do postDelete", zap.Error(err))
	}

	return itm, nil
}

func (s *Server) doPostCreate(ctx context.Context, obj umetav1.ResourceObjectI, api, version, kind string) error {
	s.doSetCache(ctx, obj, api, version, kind)

	msg := &rmetav1.WatchEvent{
		Event: &rmetav1.WatchEvent_Event{
			ApiVersion: vutils.GetApiVersion(api, version),
			Kind:       kind,
			Type: &rmetav1.WatchEvent_Event_Create_{
				Create: &rmetav1.WatchEvent_Event_Create{
					Item: pbutils.MessageToAnyMust(obj),
				},
			},
		},
	}

	if err := s.publishMessage(ctx, api, version, kind, msg); err != nil {
		return err
	}

	return nil
}

func (s *Server) doPostUpdate(ctx context.Context, new, old umetav1.ResourceObjectI, api, version, kind string) error {
	s.doSetCache(ctx, new, api, version, kind)

	msg := &rmetav1.WatchEvent{
		Event: &rmetav1.WatchEvent_Event{
			ApiVersion: vutils.GetApiVersion(api, version),
			Kind:       kind,
			Type: &rmetav1.WatchEvent_Event_Update_{
				Update: &rmetav1.WatchEvent_Event_Update{
					NewItem: pbutils.MessageToAnyMust(new),
					OldItem: pbutils.MessageToAnyMust(old),
				},
			},
		},
	}

	if err := s.publishMessage(ctx, api, version, kind, msg); err != nil {
		return err
	}

	return nil
}

func (s *Server) doPostDelete(ctx context.Context, obj umetav1.ResourceObjectI, api, version, kind string) error {
	s.doDeleteCache(ctx, obj, api, version, kind)

	if err := s.doPostDeletePublish(ctx, obj, api, version, kind); err != nil {
		return err
	}

	return nil
}

func (s *Server) doPostDeletePublish(ctx context.Context, obj umetav1.ResourceObjectI, api, version, kind string) error {

	msg := &rmetav1.WatchEvent{
		Event: &rmetav1.WatchEvent_Event{
			ApiVersion: vutils.GetApiVersion(api, version),
			Kind:       kind,
			Type: &rmetav1.WatchEvent_Event_Delete_{
				Delete: &rmetav1.WatchEvent_Event_Delete{
					Item: pbutils.MessageToAnyMust(obj),
				},
			},
		},
	}

	if err := s.publishMessage(ctx, api, version, kind, msg); err != nil {
		return err
	}

	return nil
}

func (s *Server) isTypeSecret(kind string) bool {
	return strings.HasSuffix(kind, "Secret")
}

func (s *Server) doGetCache(ctx context.Context, req *rmetav1.GetOptions, api, version, kind string) (umetav1.ResourceObjectI, bool, error) {
	var key string
	if s.isTypeSecret(kind) {
		return nil, false, nil
	}

	if req.Name != "" {
		key = getObjectKeyByName(api, version, kind, req.Name)
	} else if req.Uid != "" {
		key = getObjectKeyByUID(req.Uid)
	} else {
		return nil, false, rerr.InvalidWithErr(errors.Errorf("No name or UID"))
	}

	rscBytes, err := s.redisC.Get(ctx, key).Result()
	if err != nil {
		if err == redis.Nil {
			return nil, false, nil
		}
		return nil, false, rerr.InternalWithErr(err)
	}

	ret, err := s.opts.NewResourceObject(api, version, kind)
	if err != nil {
		return nil, false, rerr.InternalWithErr(err)
	}

	if err := pbutils.Unmarshal([]byte(rscBytes), ret); err != nil {
		return nil, false, rerr.InternalWithErr(err)
	}

	return ret, true, nil
}

func (s *Server) doSetCache(ctx context.Context, itm umetav1.ResourceObjectI, api, version, kind string) {
	md := itm.GetMetadata()

	// Secrets are not stored in the secondary storage for now
	if s.isTypeSecret(kind) {
		return
	}

	itmBytes, _ := pbutils.Marshal(itm)

	s.redisC.Set(ctx, getObjectKeyByName(api, version, kind, md.Name), string(itmBytes), 0).Result()
	s.redisC.Set(ctx, getObjectKeyByUID(md.Uid), string(itmBytes), 0).Result()
}

func (s *Server) doDeleteCache(ctx context.Context, itm umetav1.ResourceObjectI, api, version, kind string) {
	md := itm.GetMetadata()

	if _, err := s.redisC.Del(ctx,
		getObjectKeyByName(api, version, kind, md.Name),
		getObjectKeyByUID(md.Uid)).Result(); err != nil {
		zap.L().Warn("Could not do redis delete in doDeleteCache", zap.Error(err))
	}
}

func getObjectKeyByUID(uid string) string {
	return fmt.Sprintf("rsc:%s", uid)
}

func getObjectKeyByName(api, version, kind, name string) string {
	return fmt.Sprintf("rsc:%s:%s:%s:%s", api, version, kind, name)
}

func getActorRef(ctx context.Context) *metav1.ObjectReference {

	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return nil
	}

	hdrVal := md.Get("x-octelium-session-ref")
	if len(hdrVal) < 1 {
		return nil
	}

	actorRef := &metav1.ObjectReference{}
	if err := pbutils.UnmarshalJSON([]byte(hdrVal[0]), actorRef); err != nil {
		return nil
	}

	return actorRef
}

func getActorOp(ctx context.Context) string {

	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return ""
	}

	hdrVal := md.Get("x-octelium-req-path")
	if len(hdrVal) < 1 {
		return ""
	}

	return strings.TrimPrefix(hdrVal[0], "/")
}
