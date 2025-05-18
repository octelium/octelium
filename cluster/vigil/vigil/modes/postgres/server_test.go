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

package postgres

import (
	"fmt"
	"testing"
	"time"

	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/apis/main/metav1"
	"github.com/octelium/octelium/apis/rsc/rmetav1"
	"github.com/octelium/octelium/cluster/apiserver/apiserver/admin"
	"github.com/octelium/octelium/cluster/apiserver/apiserver/user"
	"github.com/octelium/octelium/cluster/common/tests"
	"github.com/octelium/octelium/cluster/common/tests/tstuser"
	"github.com/octelium/octelium/cluster/vigil/vigil/loadbalancer"
	"github.com/octelium/octelium/cluster/vigil/vigil/modes"
	"github.com/octelium/octelium/cluster/vigil/vigil/octovigilc"
	"github.com/octelium/octelium/cluster/vigil/vigil/secretman"
	"github.com/octelium/octelium/cluster/vigil/vigil/vcache"
	"github.com/octelium/octelium/pkg/utils/utilrand"
	"github.com/stretchr/testify/assert"
	"go.uber.org/zap"
	"golang.org/x/net/context"

	"database/sql"

	_ "github.com/lib/pq"
)

func TestServer(t *testing.T) {

	ctx := context.Background()

	tst, err := tests.Initialize(nil)
	assert.Nil(t, err, "%+v", err)
	t.Cleanup(func() {
		tst.Destroy()
	})
	fakeC := tst.C

	{
		cc, err := fakeC.OcteliumC.CoreV1Utils().GetClusterConfig(ctx)
		assert.Nil(t, err)

		cc.Status.Network.ClusterNetwork = &metav1.DualStackNetwork{
			V4: "127.0.0.0/8",
			V6: "::1/128",
		}
		_, err = fakeC.OcteliumC.CoreC().UpdateClusterConfig(ctx, cc)
		assert.Nil(t, err)
	}

	adminSrv := admin.NewServer(&admin.Opts{
		OcteliumC:  fakeC.OcteliumC,
		IsEmbedded: true,
	})
	usrSrv := user.NewServer(fakeC.OcteliumC)

	upstreamPort := 5432

	sec, err := adminSrv.CreateSecret(ctx, &corev1.Secret{
		Metadata: &metav1.Metadata{
			Name: utilrand.GetRandomStringCanonical(6),
		},
		Spec: &corev1.Secret_Spec{},
		Data: &corev1.Secret_Data{
			Type: &corev1.Secret_Data_Value{
				Value: "postgres",
			},
		},
	})
	assert.Nil(t, err)

	svc, err := adminSrv.CreateService(ctx, &corev1.Service{
		Metadata: &metav1.Metadata{
			Name: utilrand.GetRandomStringCanonical(6),
		},
		Spec: &corev1.Service_Spec{
			Port: 5433,
			Mode: corev1.Service_Spec_POSTGRES,

			Authorization: &corev1.Service_Spec_Authorization{
				InlinePolicies: []*corev1.InlinePolicy{
					{
						Spec: &corev1.Policy_Spec{
							Rules: []*corev1.Policy_Spec_Rule{
								{
									Effect: corev1.Policy_Spec_Rule_ALLOW,
									Condition: &corev1.Condition{
										Type: &corev1.Condition_MatchAny{
											MatchAny: true,
										},
									},
								},
							},
						},
					},
				},
			},
			Config: &corev1.Service_Spec_Config{
				Upstream: &corev1.Service_Spec_Config_Upstream{
					Type: &corev1.Service_Spec_Config_Upstream_Url{
						Url: fmt.Sprintf("postgres://localhost:%d", upstreamPort),
					},
				},
				Type: &corev1.Service_Spec_Config_Postgres_{
					Postgres: &corev1.Service_Spec_Config_Postgres{
						User:     "postgres",
						Database: "postgres",
						Auth: &corev1.Service_Spec_Config_Postgres_Auth{
							Type: &corev1.Service_Spec_Config_Postgres_Auth_Password_{
								Password: &corev1.Service_Spec_Config_Postgres_Auth_Password{
									Type: &corev1.Service_Spec_Config_Postgres_Auth_Password_FromSecret{
										FromSecret: sec.Metadata.Name,
									},
								},
							},
						},
					},
				},
			},
		},
	})
	assert.Nil(t, err, "")
	svcV, err := fakeC.OcteliumC.CoreC().GetService(ctx, &rmetav1.GetOptions{Uid: svc.Metadata.Uid})
	assert.Nil(t, err)

	vCache, err := vcache.NewCache(ctx)
	assert.Nil(t, err)
	vCache.SetService(svcV)

	octovigilC, err := octovigilc.NewClient(ctx, &octovigilc.Opts{
		VCache:    vCache,
		OcteliumC: fakeC.OcteliumC,
	})
	assert.Nil(t, err)

	secretMan, err := secretman.New(ctx, fakeC.OcteliumC, vCache)
	assert.Nil(t, err)

	secretMan.Set(sec)

	srv, err := New(ctx, &modes.Opts{
		OcteliumC:  fakeC.OcteliumC,
		VCache:     vCache,
		OctovigilC: octovigilC,
		SecretMan:  secretMan,
		LBManager:  loadbalancer.NewLbManager(fakeC.OcteliumC, vCache),
	})
	assert.Nil(t, err)
	err = srv.Run(ctx)
	assert.Nil(t, err)

	usr, err := tstuser.NewUser(fakeC.OcteliumC, adminSrv, usrSrv, nil)
	assert.Nil(t, err)
	err = usr.Connect()
	assert.Nil(t, err, "%+v", err)

	usr.Session.Status.Connection = &corev1.Session_Status_Connection{
		Addresses: []*metav1.DualStackNetwork{
			{
				V4: "127.0.0.1/32",
				V6: "::1/128",
			},
		},
		Type:   corev1.Session_Status_Connection_WIREGUARD,
		L3Mode: corev1.Session_Status_Connection_V4,
	}

	usr.Session, err = fakeC.OcteliumC.CoreC().UpdateSession(ctx, usr.Session)
	assert.Nil(t, err)
	usr.Resync()

	srv.octovigilC.GetCache().SetSession(usr.Session)
	usr.Resync()

	time.Sleep(1 * time.Second)

	db, err := sql.Open("postgres", fmt.Sprintf("postgres://postgres:postgres@localhost:%d/postgres?sslmode=disable", svc.Spec.Port))
	assert.Nil(t, err)

	{
		res, err := db.Exec("SELECT datname FROM pg_database LIMIT 5;")
		assert.Nil(t, err)
		zap.S().Debugf("Res: %+v", res)
	}

	{
		res, err := db.Exec(`
		CREATE OR REPLACE FUNCTION helloWorld(name text) RETURNS void AS $helloWorld$
		DECLARE
		BEGIN
				RAISE LOG 'Hello, %', name;
		END;
		$helloWorld$ LANGUAGE plpgsql;
		`)
		assert.Nil(t, err)
		zap.S().Debugf("Res: %+v", res)
	}

	{
		res, err := db.Exec(`
		SELECT "helloworld"('myname');
		`)
		assert.Nil(t, err)
		zap.S().Debugf("Res: %+v", res)
	}

	{
		res, err := db.Prepare(`
		SELECT "helloworld"('myname');
		`)
		assert.Nil(t, err)
		zap.S().Debugf("Res: %+v", res)

		res1, err := res.Exec()
		assert.Nil(t, err)
		zap.S().Debugf("Res: %+v", res1)

		err = res.Close()
		assert.Nil(t, err)
	}

	{
		tx, err := db.BeginTx(ctx, &sql.TxOptions{
			ReadOnly: true,
		})
		assert.Nil(t, err)
		res, err := tx.Exec("SELECT datname FROM pg_database LIMIT 5;")
		assert.Nil(t, err)
		zap.S().Debugf("Res: %+v", res)

		err = tx.Commit()
		assert.Nil(t, err)
		zap.S().Debugf("Res: %+v", res)
	}

	{
		err := db.Ping()
		assert.Nil(t, err)
	}

	err = srv.Close()
	zap.L().Debug("close err", zap.Error(err))
}
