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

package admin

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/apis/main/metav1"
	"github.com/octelium/octelium/apis/rsc/rmetav1"
	"github.com/octelium/octelium/cluster/common/tests"
	"github.com/octelium/octelium/pkg/grpcerr"
	"github.com/octelium/octelium/pkg/utils/utilrand"
	"github.com/stretchr/testify/assert"
	"google.golang.org/protobuf/types/known/structpb"
)

func genTestConfigName() string {
	return fmt.Sprintf("cfg-%s", utilrand.GetRandomStringLowercase(8))
}

func genTestConfig(data *corev1.Config_Data) *corev1.Config {
	return &corev1.Config{
		Metadata: &metav1.Metadata{
			Name: genTestConfigName(),
		},
		Spec: &corev1.Config_Spec{},
		Data: data,
	}
}

func TestConfig(t *testing.T) {
	ctx := context.Background()

	tst, err := tests.Initialize(nil)
	assert.Nil(t, err)
	t.Cleanup(func() {
		tst.Destroy()
	})
	srv := newFakeServer(tst.C)

	sizes := []int{10, 10 * 1024, 2 * 1024 * 1024}

	for _, sz := range sizes {

		val := utilrand.GetRandomBytesMust(sz)

		cfg, err := srv.CreateConfig(ctx, &corev1.Config{
			Metadata: &metav1.Metadata{
				Name: fmt.Sprintf("cfg-%s", utilrand.GetRandomStringLowercase(4)),
			},
			Spec: &corev1.Config_Spec{},
			Data: &corev1.Config_Data{
				Type: &corev1.Config_Data_ValueBytes{
					ValueBytes: val,
				},
			},
		})
		assert.Nil(t, err, "%+v", err)
		assert.Nil(t, cfg.Data)

		cfg, err = srv.octeliumC.CoreC().GetConfig(ctx, &rmetav1.GetOptions{Name: cfg.Metadata.Name})
		assert.Nil(t, err, "%+v", err)
		assert.Equal(t, val, cfg.Data.GetValueBytes())

		secI, err := srv.GetConfig(ctx, &metav1.GetOptions{Uid: cfg.Metadata.Uid})
		assert.Nil(t, err)
		assert.Equal(t, cfg.Metadata.Name, secI.Metadata.Name)
		assert.Nil(t, secI.Data)

		secList, err := srv.ListConfig(ctx, &corev1.ListConfigOptions{})
		assert.Nil(t, err)

		for _, sec := range secList.Items {
			assert.Nil(t, sec.Data)
		}

		_, err = srv.DeleteConfig(ctx, &metav1.DeleteOptions{Name: cfg.Metadata.Name})
		assert.Nil(t, err)
	}

	{
		val := utilrand.GetRandomBytesMust(4 * 1024 * 1024)
		_, err := srv.CreateConfig(ctx, &corev1.Config{
			Metadata: &metav1.Metadata{
				Name: fmt.Sprintf("cfg-%s", utilrand.GetRandomStringLowercase(4)),
			},
			Spec: &corev1.Config_Spec{},
			Data: &corev1.Config_Data{
				Type: &corev1.Config_Data_ValueBytes{
					ValueBytes: val,
				},
			},
		})
		assert.NotNil(t, err, "%+v", err)
	}

	{
		_, err = srv.GetConfig(ctx, &metav1.GetOptions{})
		assert.NotNil(t, err)
		assert.True(t, grpcerr.IsInvalidArg(err))
	}

	{
		_, err = srv.GetConfig(ctx, &metav1.GetOptions{Name: genTestConfigName()})
		assert.NotNil(t, err)
		assert.True(t, grpcerr.IsNotFound(err))
	}

	{
		_, err = srv.DeleteConfig(ctx, &metav1.DeleteOptions{Name: genTestConfigName()})
		assert.NotNil(t, err)
		assert.True(t, grpcerr.IsNotFound(err))
	}

	{
		_, err = srv.ListConfig(ctx, nil)
		assert.NotNil(t, err)
	}
}

func TestConfigDataTypes(t *testing.T) {
	ctx := context.Background()

	tst, err := tests.Initialize(nil)
	assert.Nil(t, err)
	t.Cleanup(func() {
		tst.Destroy()
	})
	srv := newFakeServer(tst.C)

	{
		val := utilrand.GetRandomString(32)
		cfg, err := srv.CreateConfig(ctx, genTestConfig(&corev1.Config_Data{
			Type: &corev1.Config_Data_Value{
				Value: val,
			},
		}))
		assert.Nil(t, err, "%+v", err)
		assert.Nil(t, cfg.Data)

		cfgV, err := srv.octeliumC.CoreC().GetConfig(ctx, &rmetav1.GetOptions{Uid: cfg.Metadata.Uid})
		assert.Nil(t, err, "%+v", err)
		assert.Equal(t, val, cfgV.Data.GetValue())
	}

	{
		dataMap := map[string][]byte{
			"key1": utilrand.GetRandomBytesMust(64),
			"key2": utilrand.GetRandomBytesMust(64),
		}

		cfg, err := srv.CreateConfig(ctx, genTestConfig(&corev1.Config_Data{
			Type: &corev1.Config_Data_DataMap_{
				DataMap: &corev1.Config_Data_DataMap{
					Map: dataMap,
				},
			},
		}))
		assert.Nil(t, err, "%+v", err)
		assert.Nil(t, cfg.Data)

		cfgV, err := srv.octeliumC.CoreC().GetConfig(ctx, &rmetav1.GetOptions{Uid: cfg.Metadata.Uid})
		assert.Nil(t, err, "%+v", err)
		assert.Equal(t, 2, len(cfgV.Data.GetDataMap().Map))
		assert.Equal(t, dataMap["key1"], cfgV.Data.GetDataMap().Map["key1"])
	}

	{
		attrs, err := structpb.NewStruct(map[string]any{
			"myKey":    "myValue",
			"otherKey": float64(42),
		})
		assert.Nil(t, err, "%+v", err)

		cfg, err := srv.CreateConfig(ctx, genTestConfig(&corev1.Config_Data{
			Type: &corev1.Config_Data_Attrs{
				Attrs: attrs,
			},
		}))
		assert.Nil(t, err, "%+v", err)
		assert.Nil(t, cfg.Data)

		cfgV, err := srv.octeliumC.CoreC().GetConfig(ctx, &rmetav1.GetOptions{Uid: cfg.Metadata.Uid})
		assert.Nil(t, err, "%+v", err)
		assert.Equal(t, "myValue", cfgV.Data.GetAttrs().GetFields()["myKey"].GetStringValue())
	}
}

func TestValidateConfig(t *testing.T) {
	ctx := context.Background()

	tst, err := tests.Initialize(nil)
	assert.Nil(t, err)
	t.Cleanup(func() {
		tst.Destroy()
	})
	srv := newFakeServer(tst.C)

	invalids := []*corev1.Config{
		{},
		{
			Metadata: &metav1.Metadata{Name: genTestConfigName()},
		},
		{
			Spec: &corev1.Config_Spec{},
			Data: &corev1.Config_Data{
				Type: &corev1.Config_Data_Value{
					Value: utilrand.GetRandomString(8),
				},
			},
		},
		{
			Metadata: &metav1.Metadata{Name: genTestConfigName()},
			Data: &corev1.Config_Data{
				Type: &corev1.Config_Data_Value{
					Value: utilrand.GetRandomString(8),
				},
			},
		},
		{
			Metadata: &metav1.Metadata{Name: genTestConfigName()},
			Spec:     &corev1.Config_Spec{},
		},
		{
			Metadata: &metav1.Metadata{Name: genTestConfigName()},
			Spec:     &corev1.Config_Spec{},
			Data:     &corev1.Config_Data{},
		},
		genTestConfig(&corev1.Config_Data{
			Type: &corev1.Config_Data_Value{
				Value: "",
			},
		}),
		genTestConfig(&corev1.Config_Data{
			Type: &corev1.Config_Data_ValueBytes{
				ValueBytes: []byte{},
			},
		}),
		genTestConfig(&corev1.Config_Data{
			Type: &corev1.Config_Data_Value{
				Value: strings.Repeat("a", cfgMaxDataSize+1),
			},
		}),
		genTestConfig(&corev1.Config_Data{
			Type: &corev1.Config_Data_DataMap_{
				DataMap: &corev1.Config_Data_DataMap{},
			},
		}),
		genTestConfig(&corev1.Config_Data{
			Type: &corev1.Config_Data_DataMap_{
				DataMap: &corev1.Config_Data_DataMap{
					Map: map[string][]byte{
						"": utilrand.GetRandomBytesMust(8),
					},
				},
			},
		}),
		genTestConfig(&corev1.Config_Data{
			Type: &corev1.Config_Data_DataMap_{
				DataMap: &corev1.Config_Data_DataMap{
					Map: map[string][]byte{
						"key1": {},
					},
				},
			},
		}),
		genTestConfig(&corev1.Config_Data{
			Type: &corev1.Config_Data_DataMap_{
				DataMap: &corev1.Config_Data_DataMap{
					Map: map[string][]byte{
						strings.Repeat("a", cfgMaxDataMapKey+1): utilrand.GetRandomBytesMust(8),
					},
				},
			},
		}),
		genTestConfig(&corev1.Config_Data{
			Type: &corev1.Config_Data_Attrs{},
		}),
		genTestConfig(&corev1.Config_Data{
			Type: &corev1.Config_Data_Attrs{
				Attrs: &structpb.Struct{},
			},
		}),
	}

	for _, invalid := range invalids {
		_, err = srv.CreateConfig(ctx, invalid)
		assert.NotNil(t, err)
		assert.True(t, grpcerr.IsInvalidArg(err), "%+v", err)
	}

	{
		dataMap := make(map[string][]byte, cfgMaxDataMapKeys+1)
		for i := 0; i < cfgMaxDataMapKeys+1; i++ {
			dataMap[fmt.Sprintf("key-%d", i)] = utilrand.GetRandomBytesMust(8)
		}

		_, err = srv.CreateConfig(ctx, genTestConfig(&corev1.Config_Data{
			Type: &corev1.Config_Data_DataMap_{
				DataMap: &corev1.Config_Data_DataMap{
					Map: dataMap,
				},
			},
		}))
		assert.NotNil(t, err)
		assert.True(t, grpcerr.IsInvalidArg(err), "%+v", err)
	}

	valids := []*corev1.Config{
		genTestConfig(&corev1.Config_Data{
			Type: &corev1.Config_Data_Value{
				Value: utilrand.GetRandomString(32),
			},
		}),
		genTestConfig(&corev1.Config_Data{
			Type: &corev1.Config_Data_ValueBytes{
				ValueBytes: utilrand.GetRandomBytesMust(32),
			},
		}),
		genTestConfig(&corev1.Config_Data{
			Type: &corev1.Config_Data_DataMap_{
				DataMap: &corev1.Config_Data_DataMap{
					Map: map[string][]byte{
						"key1": utilrand.GetRandomBytesMust(32),
					},
				},
			},
		}),
	}

	for _, valid := range valids {
		item, err := srv.CreateConfig(ctx, valid)
		assert.Nil(t, err, "%+v", err)
		assert.Nil(t, item.Data)

		_, err = srv.CreateConfig(ctx, valid)
		assert.NotNil(t, err)
		assert.True(t, grpcerr.AlreadyExists(err), "%+v", err)
	}
}

func TestUpdateConfig(t *testing.T) {
	ctx := context.Background()

	tst, err := tests.Initialize(nil)
	assert.Nil(t, err)
	t.Cleanup(func() {
		tst.Destroy()
	})
	srv := newFakeServer(tst.C)

	cfg, err := srv.CreateConfig(ctx, genTestConfig(&corev1.Config_Data{
		Type: &corev1.Config_Data_Value{
			Value: utilrand.GetRandomString(32),
		},
	}))
	assert.Nil(t, err, "%+v", err)

	{
		val := utilrand.GetRandomString(64)
		cfg.Data = &corev1.Config_Data{
			Type: &corev1.Config_Data_Value{
				Value: val,
			},
		}
		cfg.Metadata.DisplayName = "new display name"
		cfg.Metadata.Description = "description"

		updated, err := srv.UpdateConfig(ctx, cfg)
		assert.Nil(t, err, "%+v", err)
		assert.Nil(t, updated.Data)
		assert.Equal(t, "new display name", updated.Metadata.DisplayName)
		assert.Equal(t, "description", updated.Metadata.Description)

		cfgV, err := srv.octeliumC.CoreC().GetConfig(ctx, &rmetav1.GetOptions{Uid: cfg.Metadata.Uid})
		assert.Nil(t, err, "%+v", err)
		assert.Equal(t, val, cfgV.Data.GetValue())
	}

	{
		_, err = srv.UpdateConfig(ctx, genTestConfig(&corev1.Config_Data{
			Type: &corev1.Config_Data_Value{
				Value: utilrand.GetRandomString(32),
			},
		}))
		assert.NotNil(t, err)
		assert.True(t, grpcerr.IsNotFound(err), "%+v", err)
	}

	{
		item := genTestConfig(nil)
		item.Metadata.Uid = cfg.Metadata.Uid
		item.Metadata.Name = cfg.Metadata.Name
		_, err = srv.UpdateConfig(ctx, item)
		assert.NotNil(t, err)
		assert.True(t, grpcerr.IsInvalidArg(err), "%+v", err)
	}
}
