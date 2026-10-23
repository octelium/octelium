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
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/asaskevich/govalidator"
	"github.com/octelium/octelium/apis/rsc/rcachev1"
	"github.com/octelium/octelium/apis/rsc/rcorev1"
	"github.com/octelium/octelium/cluster/common/vutils"
	"github.com/octelium/octelium/pkg/apiutils/ucorev1"
	"github.com/octelium/octelium/pkg/apiutils/umetav1"
	"github.com/octelium/octelium/pkg/common/pbutils"
	"github.com/octelium/octelium/pkg/grpcerr"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/structpb"
	"net"

	"fmt"

	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/apis/main/metav1"
	"github.com/octelium/octelium/apis/rsc/rmetav1"

	"os"

	"github.com/octelium/octelium/pkg/utils/ldflags"
	"github.com/octelium/octelium/pkg/utils/utilrand"

	"github.com/octelium/octelium/cluster/common/postgresutils"
)

type T struct {
	dbName string
}

func initTest() (*T, error) {
	zapCfg := zap.Config{
		Level:            zap.NewAtomicLevelAt(zap.DebugLevel),
		Development:      true,
		Encoding:         "console",
		EncoderConfig:    zap.NewDevelopmentEncoderConfig(),
		OutputPaths:      []string{"stderr"},
		ErrorOutputPaths: []string{"stderr"},
	}

	logger, err := zapCfg.Build()
	if err != nil {
		return nil, err
	}

	zap.ReplaceGlobals(logger)

	dbName := fmt.Sprintf("octelium%s", utilrand.GetRandomStringLowercase(6))

	os.Setenv("OCTELIUM_POSTGRES_NOSSL", "true")

	os.Setenv("OCTELIUM_POSTGRES_HOST", "localhost")
	os.Setenv("OCTELIUM_POSTGRES_USERNAME", "postgres")
	os.Setenv("OCTELIUM_POSTGRES_PASSWORD", "postgres")
	os.Setenv("OCTELIUM_TEST_RSCSERVER_PORT", fmt.Sprintf("%d", utilrand.GetRandomRangeMath(20000, 60000)))

	ldflags.PrivateRegistry = "false"
	ldflags.Mode = "production"
	ldflags.TestMode = "true"

	db, err := postgresutils.NewDBWithNODB()
	if err != nil {
		return nil, err
	}

	defer db.Close()

	// ctx := context.Background()
	// c := newFakeClient()

	if _, err := db.Exec(fmt.Sprintf("CREATE DATABASE %s;", dbName)); err != nil {
		return nil, err
	}

	os.Setenv("OCTELIUM_POSTGRES_DATABASE", dbName)

	/*
		octeliumC, err := octeliumc.NewClient(ctx)
		if err != nil {
			return nil, err
		}
	*/

	// c.OcteliumC = octeliumC

	return &T{
		// C:      c,
		dbName: dbName,
	}, nil

}

func (t *T) Destroy() error {

	db, err := postgresutils.NewDB()
	if err != nil {
		return err
	}

	if _, err := db.Exec(fmt.Sprintf("DROP DATABASE IF EXISTS %s;", t.dbName)); err != nil {
		return err
	}

	return nil
}

func newTestResource(kind string) umetav1.ResourceObjectI {

	switch kind {
	case ucorev1.KindUser:
		return &corev1.User{
			Metadata: &metav1.Metadata{},
			Spec:     &corev1.User_Spec{},
			Status:   &corev1.User_Status{},
		}
	case ucorev1.KindGroup:
		return &corev1.Group{
			Metadata: &metav1.Metadata{},
			Spec:     &corev1.Group_Spec{},
			Status:   &corev1.Group_Status{},
		}
	case ucorev1.KindNamespace:
		return &corev1.Namespace{
			Metadata: &metav1.Metadata{},
			Spec:     &corev1.Namespace_Spec{},
			Status:   &corev1.Namespace_Status{},
		}
	case ucorev1.KindService:
		return &corev1.Service{
			Metadata: &metav1.Metadata{},
			Spec:     &corev1.Service_Spec{},
			Status:   &corev1.Service_Status{},
		}

	case ucorev1.KindCredential:
		return &corev1.Credential{
			Metadata: &metav1.Metadata{},
			Spec:     &corev1.Credential_Spec{},
			Status:   &corev1.Credential_Status{},
		}
	case ucorev1.KindDevice:
		return &corev1.Device{
			Metadata: &metav1.Metadata{},
			Spec:     &corev1.Device_Spec{},
			Status:   &corev1.Device_Status{},
		}
	case ucorev1.KindSession:
		return &corev1.Session{
			Metadata: &metav1.Metadata{},
			Spec:     &corev1.Session_Spec{},
			Status:   &corev1.Session_Status{},
		}
	case ucorev1.KindPolicy:
		return &corev1.Policy{
			Metadata: &metav1.Metadata{},
			Spec:     &corev1.Policy_Spec{},
			Status:   &corev1.Policy_Status{},
		}
	case ucorev1.KindSecret:
		return &corev1.Secret{
			Metadata: &metav1.Metadata{},
			Spec:     &corev1.Secret_Spec{},
			Status:   &corev1.Secret_Status{},
			Data:     &corev1.Secret_Data{},
		}
	default:
		panic("Unknown resource type")
	}

}

func TestCommon(t *testing.T) {

	tst, err := initTest()
	assert.Nil(t, err)

	ctx := context.Background()

	srv, err := NewServer(ctx, nil)
	assert.Nil(t, err)

	t.Cleanup(func() {
		tst.Destroy()
	})

	kinds := []string{
		ucorev1.KindUser,
		ucorev1.KindGroup,
		ucorev1.KindNamespace,
		ucorev1.KindService,
		ucorev1.KindSession,
		ucorev1.KindDevice,
		ucorev1.KindCredential,
		ucorev1.KindSecret,
		ucorev1.KindPolicy,
	}

	t.Run("default", func(t *testing.T) {

		api := "core"
		version := "v1"

		for _, kind := range kinds {
			obj := newTestResource(kind)
			md := obj.GetMetadata()
			md.Name = utilrand.GetRandomStringLowercase(8)
			rscOut, err := srv.doCreate(ctx, obj, api, version, kind)
			assert.Nil(t, err)
			assert.True(t, rscOut.GetMetadata().CreatedAt.IsValid())
			assert.True(t, rscOut.GetMetadata().CreatedAt.AsTime().Before(time.Now()))
			assert.True(t, govalidator.IsUUIDv4(rscOut.GetMetadata().Uid))
			assert.True(t, len(rscOut.GetMetadata().ResourceVersion) > 0)

			rscGet, err := srv.doGet(ctx,
				&rmetav1.GetOptions{Name: md.Name}, api, version, kind)
			assert.Nil(t, err)
			assert.True(t, proto.Equal(rscGet, rscOut))

			rscGet, err = srv.doGet(ctx, &rmetav1.GetOptions{Uid: rscOut.GetMetadata().Uid}, api, version, kind)
			assert.Nil(t, err)
			assert.True(t, proto.Equal(rscGet, rscOut))

			rscGet, _, err = srv.doUpdate(ctx, rscGet, api, version, kind)
			assert.Nil(t, err)
			assert.True(t, proto.Equal(rscGet, rscOut))

			rscGet, err = srv.doGet(ctx, &rmetav1.GetOptions{Uid: rscOut.GetMetadata().Uid}, api, version, kind)
			assert.Nil(t, err)
			assert.True(t, proto.Equal(rscGet, rscOut))

			rscGet.GetMetadata().Labels = map[string]string{
				"key1": "val1",
			}

			rscUpdate, _, err := srv.doUpdate(ctx, rscGet, api, version, kind)
			assert.Nil(t, err)
			assert.False(t, proto.Equal(rscUpdate, rscOut))

			rscGet, err = srv.doGet(ctx, &rmetav1.GetOptions{Uid: rscOut.GetMetadata().Uid}, api, version, kind)
			assert.Nil(t, err)
			assert.True(t, proto.Equal(rscGet, rscUpdate))

			_, err = srv.doDelete(ctx, &rmetav1.DeleteOptions{Name: md.Name},
				api, version, kind)
			assert.Nil(t, err)

			_, err = srv.doGet(ctx, &rmetav1.GetOptions{Name: md.Name}, api, version, kind)
			assert.NotNil(t, err)
			assert.True(t, grpcerr.IsNotFound(err))

			_, err = srv.doGet(ctx, &rmetav1.GetOptions{Uid: rscOut.GetMetadata().Uid}, api, version, kind)
			assert.NotNil(t, err)
			assert.True(t, grpcerr.IsNotFound(err))
		}

		for _, kind := range kinds {
			obj := newTestResource(kind)
			md := obj.GetMetadata()
			md.Name = utilrand.GetRandomStringLowercase(8)
			rscOut, err := srv.doCreate(ctx, obj, api, version, kind)
			assert.Nil(t, err)

			rscGet, err := srv.doGet(ctx,
				&rmetav1.GetOptions{Name: md.Name}, api, version, kind)
			assert.Nil(t, err)
			assert.True(t, proto.Equal(rscGet, rscOut))

			rscGet, err = srv.doGet(ctx, &rmetav1.GetOptions{Uid: rscOut.GetMetadata().Uid}, api, version, kind)
			assert.Nil(t, err)
			assert.True(t, proto.Equal(rscGet, rscOut))

			_, err = srv.doDelete(ctx, &rmetav1.DeleteOptions{Uid: rscOut.GetMetadata().Uid}, api, version, kind)
			assert.Nil(t, err)

			_, err = srv.doGet(ctx, &rmetav1.GetOptions{Name: md.Name}, api, version, kind)
			assert.NotNil(t, err)
			assert.True(t, grpcerr.IsNotFound(err))

			_, err = srv.doGet(ctx, &rmetav1.GetOptions{Uid: rscOut.GetMetadata().Uid}, api, version, kind)
			assert.NotNil(t, err)
			assert.True(t, grpcerr.IsNotFound(err))
		}
	})

	t.Run("list", func(t *testing.T) {

		api := "core"
		version := "v1"

		kind := ucorev1.KindService

		n := utilrand.GetRandomRangeMath(100, 500)

		for i := 0; i < n; i++ {
			obj := newTestResource(kind)
			md := obj.GetMetadata()
			md.Name = utilrand.GetRandomStringLowercase(8)
			_, err := srv.doCreate(ctx, obj, api, version, kind)
			assert.Nil(t, err)
		}

		for i := 0; i < 500; i++ {
			otherKind := kinds[utilrand.GetRandomRangeMath(0, len(kinds)-1)]
			if otherKind == ucorev1.KindService {
				continue
			}
			obj := newTestResource(otherKind)
			md := obj.GetMetadata()
			md.Name = utilrand.GetRandomStringLowercase(8)
			_, err := srv.doCreate(ctx, obj, api, version, otherKind)
			assert.Nil(t, err)
		}

		lst, _, err := srv.doList(ctx, &rmetav1.ListOptions{}, api, version, kind)
		assert.Nil(t, err)

		assert.Equal(t, n, len(lst))

	})

	t.Run("secret", func(t *testing.T) {

		api := "core"
		version := "v1"

		{

			sec := &corev1.Secret{
				ApiVersion: ucorev1.APIVersion,
				Kind:       ucorev1.KindSecret,
				Metadata: &metav1.Metadata{
					Name: utilrand.GetRandomStringCanonical(8),
				},
				Spec:   &corev1.Secret_Spec{},
				Status: &corev1.Secret_Status{},
				Data: &corev1.Secret_Data{
					Type: &corev1.Secret_Data_Value{
						Value: utilrand.GetRandomString(32),
					},
				},
			}

			rscOut, err := srv.doCreate(ctx, sec, api, version, ucorev1.KindSecret)
			assert.Nil(t, err)

			assert.True(t, pbutils.IsEqual(rscOut.(*corev1.Secret).Data, sec.Data))
		}

	})

}

func TestPaginate(t *testing.T) {

	tst, err := initTest()
	assert.Nil(t, err)

	ctx := context.Background()

	srv, err := NewServer(ctx, nil)
	assert.Nil(t, err)

	t.Cleanup(func() {
		tst.Destroy()
	})

	kinds := []string{
		ucorev1.KindUser,
		ucorev1.KindGroup,
		ucorev1.KindNamespace,
		ucorev1.KindService,
		ucorev1.KindSession,
		ucorev1.KindDevice,
		ucorev1.KindCredential,
		ucorev1.KindSecret,
		ucorev1.KindPolicy,
	}

	api := "core"
	version := "v1"

	kind := ucorev1.KindService

	n := utilrand.GetRandomRangeMath(1000, 5000)

	for i := 0; i < n; i++ {
		obj := newTestResource(kind)
		md := obj.GetMetadata()
		md.Name = utilrand.GetRandomStringLowercase(8)
		_, err := srv.doCreate(ctx, obj, api, version, kind)
		assert.Nil(t, err)
	}

	for i := 0; i < 500; i++ {
		otherKind := kinds[utilrand.GetRandomRangeMath(0, len(kinds)-1)]
		if otherKind == ucorev1.KindService {
			continue
		}
		obj := newTestResource(otherKind)
		md := obj.GetMetadata()
		md.Name = utilrand.GetRandomStringLowercase(8)
		_, err := srv.doCreate(ctx, obj, api, version, otherKind)
		assert.Nil(t, err)
	}

	{

		itemsPerPage := 200

		pages := n / itemsPerPage

		for i := 0; i < pages; i++ {
			lst, lstMeta, err := srv.doList(ctx, &rmetav1.ListOptions{
				Paginate:     true,
				ItemsPerPage: uint32(itemsPerPage),
				Page:         uint32(i),
			}, api, version, kind)

			if n%itemsPerPage == 0 && i <= pages {
				assert.Nil(t, err)
			} else if i <= (pages + 1) {
				assert.Nil(t, err)
			} else {
				assert.NotNil(t, err)
				continue
			}
			assert.Nil(t, err)

			if n%itemsPerPage == 0 {
				assert.Equal(t, itemsPerPage, len(lst))
				assert.Equal(t, n, int(lstMeta.TotalCount))
				assert.Equal(t, i != pages-1, lstMeta.HasMore)
			} else {
				assert.Equal(t, itemsPerPage, len(lst))
				assert.Equal(t, n, int(lstMeta.TotalCount))
				assert.Equal(t, true, lstMeta.HasMore)
			}

		}

		if n%itemsPerPage != 0 {
			lst, lstMeta, err := srv.doList(ctx, &rmetav1.ListOptions{
				Paginate:     true,
				ItemsPerPage: uint32(itemsPerPage),
				Page:         uint32(pages),
			}, api, version, kind)
			assert.Nil(t, err)
			assert.Equal(t, n%itemsPerPage, len(lst))
			assert.Equal(t, n, int(lstMeta.TotalCount))
			assert.Equal(t, false, lstMeta.HasMore)
		}

		{
			_, _, err := srv.doList(ctx, &rmetav1.ListOptions{
				Paginate:     true,
				ItemsPerPage: uint32(itemsPerPage),
				Page:         uint32(pages + 4),
			}, api, version, kind)
			assert.NotNil(t, err)
			assert.True(t, grpcerr.IsNotFound(err))
		}

	}

}

func TestOrder(t *testing.T) {

	tst, err := initTest()
	assert.Nil(t, err)

	ctx := context.Background()

	srv, err := NewServer(ctx, nil)
	assert.Nil(t, err)

	t.Cleanup(func() {
		tst.Destroy()
	})

	{
		n := utilrand.GetRandomRangeMath(100, 200)

		var objList []umetav1.ResourceObjectI
		for i := 0; i < n; i++ {
			obj := newTestResource(ucorev1.KindUser)
			md := obj.GetMetadata()
			md.Name = utilrand.GetRandomStringLowercase(8)
			obj, err := srv.doCreate(ctx, obj, "core", "v1", ucorev1.KindUser)
			assert.Nil(t, err)

			objList = append(objList, obj)
		}

		lst, respMeta, err := srv.doList(ctx, &rmetav1.ListOptions{
			OrderBy: []*rmetav1.ListOptions_OrderBy{
				{
					Type: rmetav1.ListOptions_OrderBy_TYPE_CREATED_AT,
					Mode: rmetav1.ListOptions_OrderBy_MODE_DESC,
				},
			},
		}, "core", "v1", ucorev1.KindUser)
		assert.Nil(t, err)
		assert.Equal(t, len(objList), len(lst))
		assert.Equal(t, int(respMeta.TotalCount), len(lst))

		for i := 0; i < n; i++ {
			assert.Equal(t, objList[n-i-1].GetMetadata().Uid, lst[i].GetMetadata().Uid)
		}
	}
}

func TestOrderName(t *testing.T) {

	tst, err := initTest()
	assert.Nil(t, err)

	ctx := context.Background()

	srv, err := NewServer(ctx, nil)
	assert.Nil(t, err)

	t.Cleanup(func() {
		tst.Destroy()
	})

	n := utilrand.GetRandomRangeMath(100, 200)

	var objList []umetav1.ResourceObjectI
	for i := 0; i < n; i++ {
		obj := newTestResource(ucorev1.KindUser)
		md := obj.GetMetadata()
		md.Name = utilrand.GetRandomStringLowercase(8)
		obj, err := srv.doCreate(ctx, obj, "core", "v1", ucorev1.KindUser)
		assert.Nil(t, err)

		objList = append(objList, obj)
	}

	{
		lst, respMeta, err := srv.doList(ctx, &rmetav1.ListOptions{
			OrderBy: []*rmetav1.ListOptions_OrderBy{
				{
					Type: rmetav1.ListOptions_OrderBy_TYPE_NAME,
					Mode: rmetav1.ListOptions_OrderBy_MODE_ASC,
				},
			},
		}, "core", "v1", ucorev1.KindUser)
		assert.Nil(t, err)
		assert.Equal(t, len(objList), len(lst))
		assert.Equal(t, int(respMeta.TotalCount), len(lst))

		var names []string
		for _, itm := range lst {
			names = append(names, itm.GetMetadata().Name)
		}

		assert.True(t, slices.IsSorted(names))
	}

	{
		lst, respMeta, err := srv.doList(ctx, &rmetav1.ListOptions{
			OrderBy: []*rmetav1.ListOptions_OrderBy{
				{
					Type: rmetav1.ListOptions_OrderBy_TYPE_NAME,
					Mode: rmetav1.ListOptions_OrderBy_MODE_DESC,
				},
			},
		}, "core", "v1", ucorev1.KindUser)
		assert.Nil(t, err)
		assert.Equal(t, len(objList), len(lst))
		assert.Equal(t, int(respMeta.TotalCount), len(lst))

		slices.Reverse(lst)
		var names []string
		for _, itm := range lst {
			names = append(names, itm.GetMetadata().Name)
		}

		assert.True(t, slices.IsSorted(names))
	}
}

func TestRgx(t *testing.T) {
	assert.True(t, rgxName.MatchString("sys:abc"))
	assert.True(t, rgxName.MatchString(utilrand.GetRandomStringCanonical(3)))
	assert.True(t, rgxName.MatchString(utilrand.GetRandomStringCanonical(32)))

	assert.False(t, rgxName.MatchString(utilrand.GetRandomStringCanonical(1)))
	assert.False(t, rgxName.MatchString(utilrand.GetRandomStringCanonical(129)))
	assert.False(t, rgxName.MatchString(utilrand.GetRandomStringCanonical(500)))
}

func TestNameKind(t *testing.T) {

	tst, err := initTest()
	assert.Nil(t, err)

	ctx := context.Background()

	srv, err := NewServer(ctx, nil)
	assert.Nil(t, err)

	t.Cleanup(func() {
		tst.Destroy()
	})

	name := utilrand.GetRandomStringLowercase(8)
	{
		obj := newTestResource(ucorev1.KindUser)
		md := obj.GetMetadata()
		md.Name = name
		obj, err := srv.doCreate(ctx, obj, "core", "v1", ucorev1.KindUser)
		assert.Nil(t, err)
	}
	{
		obj := newTestResource(ucorev1.KindUser)
		md := obj.GetMetadata()
		md.Name = name
		obj, err := srv.doCreate(ctx, obj, "core", "v1", ucorev1.KindUser)
		assert.NotNil(t, err)
		assert.True(t, grpcerr.AlreadyExists(err))
	}
	{
		obj := newTestResource(ucorev1.KindUser)
		md := obj.GetMetadata()
		md.Name = name
		obj, err := srv.doCreate(ctx, obj, "core", "v2", ucorev1.KindUser)
		assert.Nil(t, err)
	}
	{
		obj := newTestResource(ucorev1.KindGroup)
		md := obj.GetMetadata()
		md.Name = name
		obj, err := srv.doCreate(ctx, obj, "core", "v1", ucorev1.KindGroup)
		assert.Nil(t, err)
	}
}

func TestCheckName(t *testing.T) {

	tst, err := initTest()
	assert.Nil(t, err)

	t.Cleanup(func() {
		tst.Destroy()
	})

	invalids := []string{
		"",
		"a",
		"Abcd",
		"a.b",
		"a.b.c",
		"abc.def.abc.def.abc.def.abc.def",
		"abc.",
		"abc_",
		"abc-",
		"abc^",
		".abc",
		"_abc",
		utilrand.GetRandomStringCanonical(55),
		utilrand.GetRandomStringCanonical(100),
		utilrand.GetRandomStringCanonical(150),
		utilrand.GetRandomStringCanonical(1500),
	}

	for _, invalid := range invalids {
		err := checkName(invalid)
		assert.NotNil(t, err, "%s %+v", invalid, err)
	}

	valids := []string{
		"ab",
		"abc",
		"abc.def",
		"abc.def.abc",
		"abc.def.abc.def",
		"abc.def.abc.def.abc",
		utilrand.GetRandomStringCanonical(5),
		utilrand.GetRandomStringCanonical(36),
	}

	for _, valid := range valids {
		err := checkName(valid)
		assert.Nil(t, err)
	}
}

func TestFilter(t *testing.T) {

	tst, err := initTest()
	assert.Nil(t, err)

	ctx := context.Background()

	srv, err := NewServer(ctx, nil)
	assert.Nil(t, err)

	t.Cleanup(func() {
		tst.Destroy()
	})

	{

		usr := newTestResource(ucorev1.KindUser).(*corev1.User)
		md := usr.GetMetadata()
		md.Name = utilrand.GetRandomStringLowercase(8)
		usrT, err := srv.doCreate(ctx, usr, "core", "v1", ucorev1.KindUser)
		assert.Nil(t, err)

		{
			usr := newTestResource(ucorev1.KindUser).(*corev1.User)
			md := usr.GetMetadata()
			md.Name = utilrand.GetRandomStringLowercase(8)
			_, err := srv.doCreate(ctx, usr, "core", "v1", ucorev1.KindUser)
			assert.Nil(t, err)
		}

		dev := newTestResource(ucorev1.KindDevice).(*corev1.Device)
		md = dev.GetMetadata()
		md.Name = utilrand.GetRandomStringLowercase(8)

		dev.Status.UserRef = umetav1.GetObjectReference(usrT)
		devT, err := srv.doCreate(ctx, dev, "core", "v1", ucorev1.KindDevice)
		assert.Nil(t, err)

		lst, _, err := srv.doList(ctx, &rmetav1.ListOptions{
			Filters: []*rmetav1.ListOptions_Filter{
				{
					Field: "status.userRef.uid",
					Op:    rmetav1.ListOptions_Filter_OP_EQ,
					Value: &structpb.Value{
						Kind: &structpb.Value_StringValue{
							StringValue: usrT.GetMetadata().Uid,
						},
					},
				},
			},
		}, "core", "v1", ucorev1.KindDevice)
		assert.Nil(t, err, "%+v", err)
		assert.Equal(t, 1, len(lst))
		assert.Equal(t, lst[0].GetMetadata().Uid, devT.GetMetadata().Uid)
	}

	{
		req := &corev1.Service{
			Metadata: &metav1.Metadata{
				Name: fmt.Sprintf("%s.default", utilrand.GetRandomStringCanonical(8)),
			},
			Spec: &corev1.Service_Spec{
				IsTLS: true,
				Deployment: &corev1.Service_Spec_Deployment{
					Replicas: uint32(utilrand.GetRandomRangeMath(10, 1000)),
				},
			},
		}
		svc, err := srv.doCreate(ctx, req, "core", "v1", ucorev1.KindService)
		assert.Nil(t, err)

		req2 := &corev1.Service{
			Metadata: &metav1.Metadata{
				Name: fmt.Sprintf("%s.default", utilrand.GetRandomStringCanonical(8)),
			},
			Spec: &corev1.Service_Spec{
				IsTLS: false,
				Deployment: &corev1.Service_Spec_Deployment{
					Replicas: 0,
				},
			},
		}
		svc2, err := srv.doCreate(ctx, req2, "core", "v1", ucorev1.KindService)
		assert.Nil(t, err)

		{
			lst, _, err := srv.doList(ctx, &rmetav1.ListOptions{
				Filters: []*rmetav1.ListOptions_Filter{
					{
						Field: "spec.isTLS",
						Op:    rmetav1.ListOptions_Filter_OP_EQ,
						Value: &structpb.Value{
							Kind: &structpb.Value_BoolValue{
								BoolValue: true,
							},
						},
					},
				},
			}, "core", "v1", ucorev1.KindService)
			assert.Nil(t, err, "%+v", err)
			zap.L().Debug("lst", zap.Any("lst", lst))
			assert.Equal(t, 1, len(lst))
			assert.Equal(t, lst[0].GetMetadata().Uid, svc.GetMetadata().Uid)
		}

		{
			lst, _, err := srv.doList(ctx, &rmetav1.ListOptions{
				Filters: []*rmetav1.ListOptions_Filter{
					{
						Field: "spec.isTLS",
						Op:    rmetav1.ListOptions_Filter_OP_EQ,
						Value: &structpb.Value{
							Kind: &structpb.Value_BoolValue{
								BoolValue: false,
							},
						},
					},
				},
			}, "core", "v1", ucorev1.KindService)
			assert.Nil(t, err, "%+v", err)
			zap.L().Debug("lst", zap.Any("lst", lst))
			assert.Equal(t, 1, len(lst))
			assert.Equal(t, lst[0].GetMetadata().Uid, svc2.GetMetadata().Uid)
		}

		{
			lst, _, err := srv.doList(ctx, &rmetav1.ListOptions{
				Filters: []*rmetav1.ListOptions_Filter{
					{
						Field: "spec.deployment.replicas",
						Op:    rmetav1.ListOptions_Filter_OP_EQ,
						Value: &structpb.Value{
							Kind: &structpb.Value_NumberValue{
								NumberValue: float64(req.Spec.Deployment.Replicas),
							},
						},
					},
				},
			}, "core", "v1", ucorev1.KindService)
			assert.Nil(t, err, "%+v", err)
			zap.L().Debug("lst", zap.Any("lst", lst))
			assert.Equal(t, 1, len(lst))
			assert.Equal(t, lst[0].GetMetadata().Uid, svc.GetMetadata().Uid)
		}

		{
			lst, _, err := srv.doList(ctx, &rmetav1.ListOptions{
				Filters: []*rmetav1.ListOptions_Filter{
					{
						Field: "spec.deployment.replicas",
						Op:    rmetav1.ListOptions_Filter_OP_EQ,
						Value: &structpb.Value{
							Kind: &structpb.Value_NumberValue{
								NumberValue: 0,
							},
						},
					},
				},
			}, "core", "v1", ucorev1.KindService)
			assert.Nil(t, err, "%+v", err)
			zap.L().Debug("lst", zap.Any("lst", lst))
			assert.Equal(t, 1, len(lst))
			assert.Equal(t, lst[0].GetMetadata().Uid, svc2.GetMetadata().Uid)
		}
	}

	{
		req := &corev1.Service{
			Metadata: &metav1.Metadata{
				Name: fmt.Sprintf("%s.default", utilrand.GetRandomStringCanonical(8)),
			},
			Spec: &corev1.Service_Spec{
				Authorization: &corev1.Service_Spec_Authorization{
					Policies: []string{utilrand.GetRandomStringCanonical(8)},
				},
			},
		}
		svc, err := srv.doCreate(ctx, req, "core", "v1", ucorev1.KindService)
		assert.Nil(t, err)

		req2 := &corev1.Service{
			Metadata: &metav1.Metadata{
				Name: fmt.Sprintf("%s.default", utilrand.GetRandomStringCanonical(8)),
			},
			Spec: &corev1.Service_Spec{
				Authorization: &corev1.Service_Spec_Authorization{
					Policies: []string{utilrand.GetRandomStringCanonical(8)},
				},
			},
		}
		svc2, err := srv.doCreate(ctx, req2, "core", "v1", ucorev1.KindService)
		assert.Nil(t, err)

		{
			lst, _, err := srv.doList(ctx, &rmetav1.ListOptions{
				Filters: []*rmetav1.ListOptions_Filter{
					{
						Field: "spec.authorization.policies",
						Op:    rmetav1.ListOptions_Filter_OP_INCLUDES,
						Value: &structpb.Value{
							Kind: &structpb.Value_StringValue{
								StringValue: utilrand.GetRandomStringCanonical(8),
							},
						},
					},
				},
			}, "core", "v1", ucorev1.KindService)
			assert.Nil(t, err, "%+v", err)
			zap.L().Debug("lst", zap.Any("lst", lst))
			assert.Equal(t, 0, len(lst))
		}

		{
			lst, _, err := srv.doList(ctx, &rmetav1.ListOptions{
				Filters: []*rmetav1.ListOptions_Filter{
					{
						Field: "spec.authorization.policies",
						Op:    rmetav1.ListOptions_Filter_OP_INCLUDES,
						Value: &structpb.Value{
							Kind: &structpb.Value_StringValue{
								StringValue: req.Spec.Authorization.Policies[0],
							},
						},
					},
				},
			}, "core", "v1", ucorev1.KindService)
			assert.Nil(t, err, "%+v", err)
			zap.L().Debug("lst", zap.Any("lst", lst))
			assert.Equal(t, 1, len(lst))
			assert.Equal(t, lst[0].GetMetadata().Uid, svc.GetMetadata().Uid)
		}

		{
			lst, _, err := srv.doList(ctx, &rmetav1.ListOptions{
				Filters: []*rmetav1.ListOptions_Filter{
					{
						Field: "spec.authorization.policies",
						Op:    rmetav1.ListOptions_Filter_OP_INCLUDES,
						Value: &structpb.Value{
							Kind: &structpb.Value_StringValue{
								StringValue: req2.Spec.Authorization.Policies[0],
							},
						},
					},
				},
			}, "core", "v1", ucorev1.KindService)
			assert.Nil(t, err, "%+v", err)
			zap.L().Debug("lst", zap.Any("lst", lst))
			assert.Equal(t, 1, len(lst))
			assert.Equal(t, lst[0].GetMetadata().Uid, svc2.GetMetadata().Uid)
		}

	}
}

func TestDoListAfterID(t *testing.T) {

	tst, err := initTest()
	assert.Nil(t, err)

	ctx := context.Background()

	srv, err := NewServer(ctx, nil)
	assert.Nil(t, err)

	t.Cleanup(func() {
		tst.Destroy()
	})

	api := ucorev1.API
	version := ucorev1.Version
	kind := ucorev1.KindUser

	{
		itms, lastID, hasMore, err := srv.doListAfterID(ctx, api, version, kind, 0, 3)
		assert.Nil(t, err, "%+v", err)
		assert.Equal(t, 0, len(itms))
		assert.Equal(t, int64(0), lastID)
		assert.False(t, hasMore)
	}

	var uids []string

	for range 7 {
		obj := newTestResource(kind)
		obj.GetMetadata().Name = utilrand.GetRandomStringLowercase(8)
		out, err := srv.doCreate(ctx, obj, api, version, kind)
		assert.Nil(t, err)
		uids = append(uids, out.GetMetadata().Uid)
	}

	getUIDs := func(itms []umetav1.ResourceObjectI) []string {
		var ret []string
		for _, itm := range itms {
			ret = append(ret, itm.GetMetadata().Uid)
		}
		return ret
	}

	{
		itms, lastID, hasMore, err := srv.doListAfterID(ctx, api, version, kind, 0, 3)
		assert.Nil(t, err, "%+v", err)
		assert.Equal(t, uids[0:3], getUIDs(itms))
		assert.True(t, hasMore)
		assert.True(t, lastID > 0)

		_, err = srv.doDelete(ctx, &rmetav1.DeleteOptions{Uid: uids[0]}, api, version, kind)
		assert.Nil(t, err)

		itms, lastID, hasMore, err = srv.doListAfterID(ctx, api, version, kind, lastID, 3)
		assert.Nil(t, err, "%+v", err)
		assert.Equal(t, uids[3:6], getUIDs(itms))
		assert.True(t, hasMore)

		_, err = srv.doDelete(ctx, &rmetav1.DeleteOptions{Uid: uids[3]}, api, version, kind)
		assert.Nil(t, err)

		itms, lastID, hasMore, err = srv.doListAfterID(ctx, api, version, kind, lastID, 3)
		assert.Nil(t, err, "%+v", err)
		assert.Equal(t, uids[6:7], getUIDs(itms))
		assert.False(t, hasMore)

		itms, prevLastID, hasMore, err := srv.doListAfterID(ctx, api, version, kind, lastID, 3)
		assert.Nil(t, err, "%+v", err)
		assert.Equal(t, 0, len(itms))
		assert.Equal(t, lastID, prevLastID)
		assert.False(t, hasMore)
	}

	{
		itms, lastID, hasMore, err := srv.doListAfterID(ctx, api, version, kind, 0, 5)
		assert.Nil(t, err, "%+v", err)
		assert.Equal(t, []string{uids[1], uids[2], uids[4], uids[5], uids[6]}, getUIDs(itms))
		assert.True(t, hasMore)

		itms, _, hasMore, err = srv.doListAfterID(ctx, api, version, kind, lastID, 5)
		assert.Nil(t, err, "%+v", err)
		assert.Equal(t, 0, len(itms))
		assert.False(t, hasMore)
	}

	{
		itms, _, hasMore, err := srv.doListAfterID(ctx, api, version, ucorev1.KindGroup, 0, 100)
		assert.Nil(t, err, "%+v", err)
		assert.Equal(t, 0, len(itms))
		assert.False(t, hasMore)
	}
}

func TestUpdateConflict(t *testing.T) {

	tst, err := initTest()
	assert.Nil(t, err)

	ctx := context.Background()

	srv, err := NewServer(ctx, nil)
	assert.Nil(t, err)

	t.Cleanup(func() {
		tst.Destroy()
	})

	api := "core"
	version := "v1"
	kind := ucorev1.KindService

	newObj := func() umetav1.ResourceObjectI {
		obj := newTestResource(kind)
		obj.GetMetadata().Name = utilrand.GetRandomStringLowercase(8)
		ret, err := srv.doCreate(ctx, obj, api, version, kind)
		assert.Nil(t, err)
		return ret
	}

	getObj := func(uid string) umetav1.ResourceObjectI {
		ret, err := srv.doGet(ctx, &rmetav1.GetOptions{Uid: uid}, api, version, kind)
		assert.Nil(t, err)
		return ret
	}

	t.Run("stale", func(t *testing.T) {
		obj := newObj()
		uid := obj.GetMetadata().Uid

		first := getObj(uid)
		stale := getObj(uid)

		first.GetMetadata().Labels = map[string]string{"key": "first"}
		updated, _, err := srv.doUpdate(ctx, first, api, version, kind)
		assert.Nil(t, err)

		stale.GetMetadata().Labels = map[string]string{"key": "stale"}
		_, _, err = srv.doUpdate(ctx, stale, api, version, kind)
		assert.NotNil(t, err)
		assert.True(t, grpcerr.IsResourceChanged(err), "%+v", err)

		cur := getObj(uid)
		assert.True(t, proto.Equal(updated, cur))
		assert.Equal(t, "first", cur.GetMetadata().Labels["key"])
	})

	t.Run("concurrent", func(t *testing.T) {
		obj := newObj()
		uid := obj.GetMetadata().Uid

		racers := 32

		var objs []umetav1.ResourceObjectI
		for i := range racers {
			itm := getObj(uid)
			itm.GetMetadata().Labels = map[string]string{"racer": fmt.Sprintf("%d", i)}
			objs = append(objs, itm)
		}

		var wg sync.WaitGroup
		var mu sync.Mutex
		var winners []umetav1.ResourceObjectI
		var conflicts int

		start := make(chan struct{})
		for _, itm := range objs {
			wg.Add(1)
			go func() {
				defer wg.Done()
				<-start

				ret, _, err := srv.doUpdate(ctx, itm, api, version, kind)

				mu.Lock()
				defer mu.Unlock()

				switch {
				case err == nil:
					winners = append(winners, ret)
				case grpcerr.IsResourceChanged(err):
					conflicts++
				default:
					t.Errorf("Unexpected error: %+v", err)
				}
			}()
		}

		close(start)
		wg.Wait()

		assert.Equal(t, 1, len(winners), "only one of the racing updates of the same version can win")
		assert.Equal(t, racers-1, conflicts)

		if len(winners) == 1 {
			cur := getObj(uid)
			assert.True(t, proto.Equal(winners[0], cur))
			assert.Equal(t, obj.GetMetadata().ResourceVersion, cur.GetMetadata().LastResourceVersion)
		}
	})

	t.Run("deleted", func(t *testing.T) {
		obj := newObj()
		uid := obj.GetMetadata().Uid

		itm := getObj(uid)

		_, err := srv.doDelete(ctx, &rmetav1.DeleteOptions{Uid: uid}, api, version, kind)
		assert.Nil(t, err)

		itm.GetMetadata().Labels = map[string]string{"key": "val"}
		_, _, err = srv.doUpdate(ctx, itm, api, version, kind)
		assert.NotNil(t, err)
		assert.True(t, grpcerr.IsNotFound(err), "%+v", err)

		err = srv.getUpdateConflictErr(ctx, itm, api, version, kind)
		assert.True(t, grpcerr.IsNotFound(err), "%+v", err)

		exists, err := srv.doExistsByUID(ctx, uid)
		assert.Nil(t, err)
		assert.False(t, exists)
	})

	t.Run("conflict-err", func(t *testing.T) {
		obj := newObj()

		err := srv.getUpdateConflictErr(ctx, obj, api, version, kind)
		assert.True(t, grpcerr.IsResourceChanged(err), "%+v", err)

		exists, err := srv.doExistsByUID(ctx, obj.GetMetadata().Uid)
		assert.Nil(t, err)
		assert.True(t, exists)
	})

	t.Run("stale-cache", func(t *testing.T) {
		obj := newObj()
		uid := obj.GetMetadata().Uid

		stale := getObj(uid)

		cur := getObj(uid)
		cur.GetMetadata().Labels = map[string]string{"key": "cur"}
		_, _, err := srv.doUpdate(ctx, cur, api, version, kind)
		assert.Nil(t, err)

		srv.doSetCache(ctx, stale, api, version, kind)
		_, found, err := srv.doGetCache(ctx, &rmetav1.GetOptions{Uid: uid}, api, version, kind)
		assert.Nil(t, err)
		assert.True(t, found)

		stale.GetMetadata().Labels = map[string]string{"key": "stale"}
		_, _, err = srv.doUpdate(ctx, stale, api, version, kind)
		assert.True(t, grpcerr.IsResourceChanged(err), "%+v", err)

		_, found, err = srv.doGetCache(ctx, &rmetav1.GetOptions{Uid: uid}, api, version, kind)
		assert.Nil(t, err)
		assert.False(t, found, "a conflict must drop the cached object so that the retry reads the store")

		_, found, err = srv.doGetCache(ctx, &rmetav1.GetOptions{Name: stale.GetMetadata().Name}, api, version, kind)
		assert.Nil(t, err)
		assert.False(t, found)

		srv.doSetCache(ctx, stale, api, version, kind)
		err = srv.getUpdateConflictErr(ctx, stale, api, version, kind)
		assert.True(t, grpcerr.IsResourceChanged(err), "%+v", err)

		_, found, err = srv.doGetCache(ctx, &rmetav1.GetOptions{Uid: uid}, api, version, kind)
		assert.Nil(t, err)
		assert.False(t, found)
	})

	t.Run("no-resource-version", func(t *testing.T) {
		obj := newObj()
		uid := obj.GetMetadata().Uid

		_, err := srv.db.ExecContext(ctx,
			`UPDATE octelium_resources SET resource = resource #- '{metadata,resourceVersion}' WHERE uid = $1`, uid)
		assert.Nil(t, err)

		itm := getObj(uid)
		assert.Equal(t, "", itm.GetMetadata().ResourceVersion)

		itm.GetMetadata().Labels = map[string]string{"key": "val"}
		updated, _, err := srv.doUpdate(ctx, itm, api, version, kind)
		assert.Nil(t, err, "%+v", err)
		assert.True(t, len(updated.GetMetadata().ResourceVersion) > 0)

		cur := getObj(uid)
		assert.True(t, proto.Equal(updated, cur))
	})
}

func newTestServer(t *testing.T, opts *Opts) *Server {
	t.Helper()
	for _, key := range []string{
		"OCTELIUM_POSTGRES_NOSSL", "OCTELIUM_POSTGRES_HOST", "OCTELIUM_POSTGRES_USERNAME",
		"OCTELIUM_POSTGRES_PASSWORD", "OCTELIUM_POSTGRES_DATABASE", "OCTELIUM_TEST_RSCSERVER_PORT",
	} {
		t.Setenv(key, os.Getenv(key))
	}
	privateRegistry, mode, testMode := ldflags.PrivateRegistry, ldflags.Mode, ldflags.TestMode
	t.Cleanup(func() {
		ldflags.PrivateRegistry, ldflags.Mode, ldflags.TestMode = privateRegistry, mode, testMode
	})
	tst, err := initTest()
	require.Nil(t, err)
	t.Cleanup(func() {
		db, err := postgresutils.NewDBWithNODB()
		if !assert.Nil(t, err) {
			return
		}
		defer db.Close()
		_, err = db.Exec(fmt.Sprintf("DROP DATABASE IF EXISTS %s WITH (FORCE)", tst.dbName))
		assert.Nil(t, err)
	})
	srv, err := NewServer(t.Context(), opts)
	require.Nil(t, err)
	t.Cleanup(srv.Stop)
	return srv
}

func TestResourceInvalidRequests(t *testing.T) {
	srv := newTestServer(t, nil)
	ctx := t.Context()
	for _, req := range []*rmetav1.GetOptions{
		{}, {Name: "a"}, {Name: "user' OR '1'='1"}, {Uid: "invalid"},
		{Uid: vutils.UUIDv7()}, {Name: "valid", Uid: "invalid"},
	} {
		_, err := srv.GetResource(ctx, req, "core", "v1", ucorev1.KindUser)
		assert.Equal(t, codes.InvalidArgument, status.Code(err))
		_, err = srv.doDelete(ctx, &rmetav1.DeleteOptions{Name: req.Name, Uid: req.Uid}, "core", "v1", ucorev1.KindUser)
		assert.Equal(t, codes.InvalidArgument, status.Code(err))
	}
	for _, req := range []*corev1.User{{}, {Metadata: &metav1.Metadata{}}, {Metadata: &metav1.Metadata{Name: "invalid/name"}}} {
		_, err := srv.CreateResource(ctx, req, "core", "v1", ucorev1.KindUser)
		assert.Equal(t, codes.InvalidArgument, status.Code(err))
		_, _, err = srv.doUpdate(ctx, req, "core", "v1", ucorev1.KindUser)
		assert.Equal(t, codes.InvalidArgument, status.Code(err))
	}
	uid := vutils.UUIDv4()
	_, err := srv.GetResource(ctx, &rmetav1.GetOptions{Uid: uid}, "core", "v1", ucorev1.KindUser)
	assert.Equal(t, codes.NotFound, status.Code(err))
	assert.Contains(t, err.Error(), uid)
	_, err = srv.doDelete(ctx, &rmetav1.DeleteOptions{Uid: uid}, "core", "v1", ucorev1.KindUser)
	assert.Equal(t, codes.NotFound, status.Code(err))
	_, _, err = srv.doUpdate(ctx, &corev1.User{Metadata: &metav1.Metadata{Uid: uid}}, "core", "v1", ucorev1.KindUser)
	assert.Equal(t, codes.NotFound, status.Code(err))

	items, _, err := srv.doList(ctx, &rmetav1.ListOptions{}, "core", "v1", ucorev1.KindUser)
	require.Nil(t, err)
	assert.Empty(t, items)
}

func TestResourceMetadataActor(t *testing.T) {
	srv := newTestServer(t, nil)
	actor := &metav1.ObjectReference{Uid: vutils.UUIDv4(), Kind: "Session", ApiVersion: "core/v1", Name: "actor"}
	data, err := pbutils.MarshalJSON(actor, false)
	require.Nil(t, err)
	ctx := metadata.NewIncomingContext(t.Context(), metadata.Pairs(
		"x-octelium-session-ref", string(data), "x-octelium-req-path", "/create"))
	req := &corev1.User{Metadata: &metav1.Metadata{Name: "actor-test", Uid: vutils.UUIDv4()}}
	original := proto.Clone(req)
	created, err := srv.CreateResource(ctx, req, "core", "v1", ucorev1.KindUser)
	require.Nil(t, err)
	assert.True(t, proto.Equal(original, req))
	assert.NotEqual(t, req.Metadata.Uid, created.GetMetadata().Uid)
	assert.True(t, proto.Equal(actor, created.GetMetadata().ActorRef))
	assert.Equal(t, "create", created.GetMetadata().ActorOperation)
	assert.Equal(t, "core/v1", created.GetApiVersion())
	assert.Equal(t, ucorev1.KindUser, created.GetKind())
	assert.NotNil(t, created.(*corev1.User).Spec)
	assert.NotNil(t, created.(*corev1.User).Status)

	ctx = metadata.NewIncomingContext(t.Context(), metadata.Pairs(
		"x-octelium-session-ref", string(data), "x-octelium-req-path", "/update"))
	update := proto.Clone(created).(*corev1.User)
	update.Metadata.DisplayName = "updated"
	updated, old, err := srv.doUpdate(ctx, update, "core", "v1", ucorev1.KindUser)
	require.Nil(t, err)
	assert.True(t, proto.Equal(created, old))
	assert.Equal(t, created.GetMetadata().ResourceVersion, updated.GetMetadata().LastResourceVersion)
	assert.Equal(t, created.GetMetadata().Uid, updated.GetMetadata().Uid)
	assert.True(t, proto.Equal(created.GetMetadata().CreatedAt, updated.GetMetadata().CreatedAt))
	assert.Equal(t, "update", updated.GetMetadata().ActorOperation)

	ctx = metadata.NewIncomingContext(t.Context(), metadata.Pairs("x-octelium-req-path", "delete"))
	deleted, err := srv.doDelete(ctx, &rmetav1.DeleteOptions{Uid: updated.GetMetadata().Uid}, "core", "v1", ucorev1.KindUser)
	require.Nil(t, err)
	assert.Equal(t, updated.GetMetadata().ResourceVersion, deleted.GetMetadata().LastResourceVersion)
	assert.NotEqual(t, updated.GetMetadata().ResourceVersion, deleted.GetMetadata().ResourceVersion)
	assert.Equal(t, "delete", deleted.GetMetadata().ActorOperation)
	assert.Nil(t, deleted.GetMetadata().ActorRef)

	for _, md := range []metadata.MD{
		{}, {"x-octelium-session-ref": {}}, {"x-octelium-session-ref": {"invalid"}},
		{"x-octelium-session-ref": {`{"uid": 42}`}},
	} {
		ctx := metadata.NewIncomingContext(t.Context(), md)
		assert.Nil(t, getActorRef(ctx))
		assert.Empty(t, getActorOp(ctx))
	}
}

func TestResourceCacheLifecycle(t *testing.T) {
	srv := newTestServer(t, nil)
	ctx := t.Context()
	obj, err := srv.CreateResource(ctx, newTestUser(utilrand.GetRandomStringCanonical(12)), "core", "v1", ucorev1.KindUser)
	require.Nil(t, err)
	md := obj.GetMetadata()
	t.Cleanup(func() { srv.doDeleteCache(context.Background(), obj, "core", "v1", ucorev1.KindUser) })
	for _, req := range []*rmetav1.GetOptions{{Name: md.Name}, {Uid: md.Uid}} {
		got, found, err := srv.doGetCache(ctx, req, "core", "v1", ucorev1.KindUser)
		require.Nil(t, err)
		require.True(t, found)
		assert.True(t, proto.Equal(obj, got))
		got.GetMetadata().DisplayName = "local mutation"
		again, found, err := srv.doGetCache(ctx, req, "core", "v1", ucorev1.KindUser)
		require.Nil(t, err)
		require.True(t, found)
		assert.True(t, proto.Equal(obj, again))
	}
	for _, key := range []string{getObjectKeyByUID(md.Uid), getObjectKeyByName("core", "v1", ucorev1.KindUser, md.Name)} {
		ttl, err := srv.redisC.PTTL(ctx, key).Result()
		require.Nil(t, err)
		assert.Greater(t, ttl, cacheResourceTTL-time.Second)
		assert.LessOrEqual(t, ttl, cacheResourceTTL)
	}

	previous := ldflags.TestMode
	ldflags.TestMode = "false"
	t.Cleanup(func() { ldflags.TestMode = previous })
	got, err := srv.GetResource(ctx, &rmetav1.GetOptions{Uid: md.Uid}, "core", "v1", ucorev1.KindUser)
	require.Nil(t, err)
	assert.True(t, proto.Equal(obj, got))

	for _, req := range []*rmetav1.GetOptions{{Name: md.Name}, {Uid: md.Uid}} {
		key := getObjectKeyByUID(md.Uid)
		if req.Name != "" {
			key = getObjectKeyByName("core", "v1", ucorev1.KindUser, md.Name)
		}
		require.Nil(t, srv.redisC.Set(ctx, key, []byte{255}, time.Minute).Err())
		_, found, err := srv.doGetCache(ctx, req, "core", "v1", ucorev1.KindUser)
		assert.False(t, found)
		assert.Equal(t, codes.Internal, status.Code(err))
		got, err := srv.GetResource(ctx, req, "core", "v1", ucorev1.KindUser)
		require.Nil(t, err)
		assert.True(t, proto.Equal(obj, got))
	}
	srv.doDeleteCache(ctx, obj, "core", "v1", ucorev1.KindUser)
	got, err = srv.GetResource(ctx, &rmetav1.GetOptions{Name: md.Name}, "core", "v1", ucorev1.KindUser)
	require.Nil(t, err)
	assert.True(t, proto.Equal(obj, got))

	_, _, err = srv.doGetCache(ctx, &rmetav1.GetOptions{}, "core", "v1", ucorev1.KindUser)
	assert.Equal(t, codes.InvalidArgument, status.Code(err))
	srv.opts.NewResourceObject = func(string, string, string) (umetav1.ResourceObjectI, error) {
		return nil, fmt.Errorf("factory failed")
	}
	_, found, err := srv.doGetCache(ctx, &rmetav1.GetOptions{Uid: md.Uid}, "core", "v1", ucorev1.KindUser)
	assert.False(t, found)
	assert.Equal(t, codes.Internal, status.Code(err))
}

func TestResourceCacheUnavailable(t *testing.T) {
	srv := newTestServer(t, nil)
	ctx := t.Context()
	obj, err := srv.CreateResource(ctx, newTestUser(utilrand.GetRandomStringCanonical(12)), "core", "v1", ucorev1.KindUser)
	require.Nil(t, err)
	realRedis := srv.redisC
	srv.doDeleteCache(ctx, obj, "core", "v1", ucorev1.KindUser)
	srv.redisC = redis.NewClient(realRedis.Options())
	require.Nil(t, srv.redisC.Close())
	t.Cleanup(func() { srv.redisC = realRedis })
	previous := ldflags.TestMode
	ldflags.TestMode = "false"
	t.Cleanup(func() { ldflags.TestMode = previous })

	got, err := srv.GetResource(ctx, &rmetav1.GetOptions{Uid: obj.GetMetadata().Uid}, "core", "v1", ucorev1.KindUser)
	require.Nil(t, err)
	assert.True(t, proto.Equal(obj, got))
}

func TestResourceListSelectors(t *testing.T) {
	srv := newTestServer(t, nil)
	ctx := t.Context()
	for _, entry := range []struct {
		name         string
		systemHidden bool
		userHidden   bool
		specLabels   map[string]string
		systemLabels map[string]string
	}{
		{
			"aa",
			false,
			false,
			map[string]string{"team": "red", "env": "prod"},
			map[string]string{"region": "west"},
		},
		{
			"bb",
			true,
			false,
			map[string]string{"team": "blue", "env": "prod"},
			map[string]string{"region": "east"},
		},
		{
			"cc",
			false,
			true,
			map[string]string{"team": "red", "env": "test"},
			map[string]string{"region": "east"},
		},
		{"dd", true, true, nil, nil},
	} {
		_, err := srv.doCreate(ctx, &corev1.User{Metadata: &metav1.Metadata{
			Name: entry.name, IsSystemHidden: entry.systemHidden, IsUserHidden: entry.userHidden,
			SpecLabels: entry.specLabels, SystemLabels: entry.systemLabels,
		}}, "core", "v1", ucorev1.KindUser)
		require.Nil(t, err)
	}
	for _, entry := range []struct {
		name  string
		req   *rmetav1.ListOptions
		names []string
	}{
		{"all", &rmetav1.ListOptions{}, []string{"aa", "bb", "cc", "dd"}},
		{"system-hidden", &rmetav1.ListOptions{ExcludeSystemHidden: true}, []string{"aa", "cc"}},
		{"user-hidden", &rmetav1.ListOptions{ExcludeUserHidden: true}, []string{"aa", "bb"}},
		{
			"both-hidden",
			&rmetav1.ListOptions{ExcludeSystemHidden: true, ExcludeUserHidden: true},
			[]string{"aa"},
		},
		{
			"spec-and",
			&rmetav1.ListOptions{SpecLabels: map[string]string{"team": "red", "env": "prod"}},
			[]string{"aa"},
		},
		{
			"spec-or",
			&rmetav1.ListOptions{SpecLabelsORed: map[string]string{"team": "blue", "env": "test"}},
			[]string{"bb", "cc"},
		},
		{
			"system-and",
			&rmetav1.ListOptions{SystemLabels: map[string]string{"region": "east"}},
			[]string{"bb", "cc"},
		},
		{
			"system-or",
			&rmetav1.ListOptions{SystemLabelsORed: map[string]string{"region": "west", "other": "yes"}},
			[]string{"aa"},
		},
		{
			"combined",
			&rmetav1.ListOptions{
				SpecLabels:       map[string]string{"team": "red"},
				SystemLabelsORed: map[string]string{"region": "east"},
			},
			[]string{"cc"},
		},
		{"escaped-key", &rmetav1.ListOptions{SpecLabels: map[string]string{"x' OR '1'='1": "value"}}, nil},
		{
			"escaped-value",
			&rmetav1.ListOptions{SystemLabelsORed: map[string]string{"region": "east' OR '1'='1"}},
			nil,
		},
	} {
		t.Run(entry.name, func(t *testing.T) {
			items, meta, err := srv.doList(ctx, entry.req, "core", "v1", ucorev1.KindUser)
			require.Nil(t, err)
			var names []string
			for _, item := range items {
				names = append(names, item.GetMetadata().Name)
			}
			assert.Equal(t, entry.names, names)
			assert.Equal(t, uint32(len(entry.names)), meta.TotalCount)
		})
	}
	for _, limit := range []uint32{0, maxItemsPerPage + 1} {
		_, meta, err := srv.doList(ctx, &rmetav1.ListOptions{Paginate: true, ItemsPerPage: limit}, "core", "v1", ucorev1.KindUser)
		require.Nil(t, err)
		expected := uint32(defaultItemsPerPage)
		if limit > maxItemsPerPage {
			expected = maxItemsPerPage
		}
		assert.Equal(t, expected, meta.ItemsPerPage)
		assert.False(t, meta.HasMore)
	}
	_, _, err := srv.doList(ctx, &rmetav1.ListOptions{Paginate: true, Page: 10001}, "core", "v1", ucorev1.KindUser)
	assert.Equal(t, codes.InvalidArgument, status.Code(err))
	_, _, err = srv.doList(ctx, &rmetav1.ListOptions{Filters: []*rmetav1.ListOptions_Filter{nil}}, "core", "v1", ucorev1.KindUser)
	assert.Equal(t, codes.InvalidArgument, status.Code(err))
}

func TestResourceStorageErrors(t *testing.T) {
	srv := newTestServer(t, nil)
	ctx := t.Context()
	obj, err := srv.doCreate(ctx, newTestUser("storage-errors"), "core", "v1", ucorev1.KindUser)
	require.Nil(t, err)
	uid := obj.GetMetadata().Uid

	require.Nil(t, srv.db.Close())
	_, err = srv.doGet(ctx, &rmetav1.GetOptions{Uid: uid}, "core", "v1", ucorev1.KindUser)
	assert.Equal(t, codes.Internal, status.Code(err))
	_, _, err = srv.doList(ctx, &rmetav1.ListOptions{}, "core", "v1", ucorev1.KindUser)
	assert.Equal(t, codes.Internal, status.Code(err))
	_, _, _, err = srv.doListAfterID(ctx, "core", "v1", ucorev1.KindUser, 0, 10)
	assert.Equal(t, codes.Internal, status.Code(err))
	_, err = srv.doExistsByUID(ctx, uid)
	assert.NotNil(t, err)
	assert.True(t, grpcerr.IsResourceChanged(srv.getUpdateConflictErr(ctx, obj, "core", "v1", ucorev1.KindUser)))
	_, err = srv.doCreate(ctx, newTestUser("another-user"), "core", "v1", ucorev1.KindUser)
	assert.Equal(t, codes.Internal, status.Code(err))
}

func TestResourceMalformedStorage(t *testing.T) {
	srv := newTestServer(t, nil)
	ctx := t.Context()
	obj, err := srv.doCreate(ctx, newTestUser("malformed-storage"), "core", "v1", ucorev1.KindUser)
	require.Nil(t, err)
	_, err = srv.db.ExecContext(ctx, `UPDATE octelium_resources SET resource = jsonb_set(resource, '{metadata,name}', '42') WHERE uid = $1`, obj.GetMetadata().Uid)
	require.Nil(t, err)
	_, err = srv.doGet(ctx, &rmetav1.GetOptions{Uid: obj.GetMetadata().Uid}, "core", "v1", ucorev1.KindUser)
	assert.Equal(t, codes.Internal, status.Code(err))
	_, _, err = srv.doList(ctx, &rmetav1.ListOptions{}, "core", "v1", ucorev1.KindUser)
	assert.Equal(t, codes.Internal, status.Code(err))
	_, _, _, err = srv.doListAfterID(ctx, "core", "v1", ucorev1.KindUser, 0, 10)
	assert.Equal(t, codes.Internal, status.Code(err))

	srv.opts.NewResourceObject = func(string, string, string) (umetav1.ResourceObjectI, error) {
		return nil, fmt.Errorf("factory failed")
	}
	_, err = srv.doGet(ctx, &rmetav1.GetOptions{Uid: obj.GetMetadata().Uid}, "core", "v1", ucorev1.KindUser)
	assert.EqualError(t, err, "factory failed")
	_, _, err = srv.doList(ctx, &rmetav1.ListOptions{}, "core", "v1", ucorev1.KindUser)
	assert.Equal(t, codes.Internal, status.Code(err))
	_, _, _, err = srv.doListAfterID(ctx, "core", "v1", ucorev1.KindUser, 0, 10)
	assert.Equal(t, codes.Internal, status.Code(err))
	_, err = srv.doCreate(ctx, newTestUser("factory-errors"), "core", "v1", ucorev1.KindUser)
	assert.EqualError(t, err, "factory failed")
}

func TestResourceNameBoundaries(t *testing.T) {
	for _, name := range []string{
		"ab",
		"aa:bb",
		strings.Repeat("a", 54),
		strings.Repeat("a", 54) + "." + strings.Repeat("b", 54) + "." + strings.Repeat("c", 30),
	} {
		assert.Nil(t, checkName(name), name)
	}
	for _, name := range []string{
		strings.Repeat("a", 55),
		strings.Repeat("a", 54) + "." + strings.Repeat("b", 54) + "." + strings.Repeat("c", 31),
		"aa..bb",
		"aa\x00bb",
		"aa\nbb",
		"aa/../bb",
		"aa.世界",
	} {
		assert.NotNil(t, checkName(name), name)
	}
}

func TestResourceServerLifecycle(t *testing.T) {
	t.Setenv("OCTELIUM_ENABLE_SPIFFE_CSI", "false")
	t.Setenv("SPIFFE_ENDPOINT_SOCKET", "")
	srv := newTestServer(t, nil)
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancel()
	assert.Same(t, srv.db, srv.GetDB())
	assert.Same(t, srv.redisC, srv.GetRedisC())
	require.Nil(t, srv.Run(ctx))
	addr := net.JoinHostPort("127.0.0.1", os.Getenv("OCTELIUM_TEST_RSCSERVER_PORT"))
	conn, err := grpc.NewClient(addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	require.Nil(t, err)
	defer conn.Close()
	client := rcorev1.NewResourceServiceClient(conn)
	created, err := client.CreateUser(ctx, &corev1.User{Metadata: &metav1.Metadata{Name: "server-lifecycle"}})
	require.Nil(t, err)
	assert.NotEmpty(t, created.Metadata.Uid)
	cacheClient := rcachev1.NewMainServiceClient(conn)
	key := utilrand.GetRandomBytesMust(32)
	_, err = cacheClient.SetCache(ctx, &rcachev1.SetCacheRequest{Key: key, Data: []byte("data"), Duration: durSeconds(30)})
	require.Nil(t, err)
	got, err := cacheClient.GetCache(ctx, &rcachev1.GetCacheRequest{Key: key, Delete: true})
	require.Nil(t, err)
	assert.Equal(t, []byte("data"), got.Data)
	srv.Stop()
	_, err = client.GetUser(ctx, &rmetav1.GetOptions{Uid: created.Metadata.Uid})
	assert.Equal(t, codes.Unavailable, status.Code(err))
}

func TestResourceServerRegistrationError(t *testing.T) {
	t.Setenv("OCTELIUM_ENABLE_SPIFFE_CSI", "false")
	t.Setenv("SPIFFE_ENDPOINT_SOCKET", "")
	srv := newTestServer(t, &Opts{RegisterResourceFn: func(grpc.ServiceRegistrar) error { return fmt.Errorf("registration failed") }})
	assert.EqualError(t, srv.Run(t.Context()), "registration failed")
}

func TestResourceHooks(t *testing.T) {
	for _, op := range []string{"get", "create", "update", "delete", "list"} {
		t.Run(op, func(t *testing.T) {
			srv := newTestServer(t, nil)
			ctx := t.Context()
			created, err := srv.doCreate(ctx, newTestUser("hook-test"), "core", "v1", ucorev1.KindUser)
			require.Nil(t, err)
			uid := created.GetMetadata().Uid
			hookErr := status.Error(codes.PermissionDenied, "hook rejected the request")
			switch op {
			case "get":
				srv.opts.PostGet = func(context.Context, umetav1.ResourceObjectI, string, string, string) error { return hookErr }
				_, err = srv.doGet(ctx, &rmetav1.GetOptions{Uid: uid}, "core", "v1", ucorev1.KindUser)
			case "create":
				srv.opts.PreCreate = func(context.Context, umetav1.ResourceObjectI, string, string, string) error { return hookErr }
				_, err = srv.doCreate(ctx, newTestUser("rejected-create"), "core", "v1", ucorev1.KindUser)
			case "update":
				srv.opts.PreUpdate = func(context.Context, umetav1.ResourceObjectI, umetav1.ResourceObjectI, string, string, string) error {
					return hookErr
				}
				updated := proto.Clone(created).(*corev1.User)
				updated.Metadata.DisplayName = "rejected-update"
				_, _, err = srv.doUpdate(ctx, updated, "core", "v1", ucorev1.KindUser)
			case "delete":
				srv.opts.PreDelete = func(context.Context, umetav1.ResourceObjectI, string, string, string) error { return hookErr }
				_, err = srv.doDelete(ctx, &rmetav1.DeleteOptions{Uid: uid}, "core", "v1", ucorev1.KindUser)
			case "list":
				srv.opts.PostList = func(context.Context, *ObjectList, string, string, string) error { return hookErr }
				_, _, err = srv.doList(ctx, &rmetav1.ListOptions{}, "core", "v1", ucorev1.KindUser)
				assert.ErrorIs(t, err, hookErr)
				_, _, _, err = srv.doListAfterID(ctx, "core", "v1", ucorev1.KindUser, 0, 10)
			}
			assert.ErrorIs(t, err, hookErr)
			srv.opts = &Opts{NewResourceObject: vutils.NewResourceObject}
			items, _, err := srv.doList(ctx, &rmetav1.ListOptions{}, "core", "v1", ucorev1.KindUser)
			require.Nil(t, err)
			require.Len(t, items, 1)
			assert.True(t, proto.Equal(created, items[0]))
		})
	}
}
