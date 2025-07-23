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
	"testing"
	"time"

	"github.com/asaskevich/govalidator"
	"github.com/octelium/octelium/pkg/apiutils/ucorev1"
	"github.com/octelium/octelium/pkg/apiutils/umetav1"
	"github.com/octelium/octelium/pkg/common/pbutils"
	"github.com/octelium/octelium/pkg/grpcerr"
	"github.com/stretchr/testify/assert"
	"go.uber.org/zap"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/structpb"

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
