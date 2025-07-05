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

package rscutils

import (
	"testing"

	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/cluster/common/tests"
	"github.com/octelium/octelium/pkg/common/pbutils"
	"github.com/octelium/octelium/pkg/utils/utilrand"
	"github.com/stretchr/testify/assert"
)

func TestGetMergedServiceConfig(t *testing.T) {

	tst, err := tests.Initialize(nil)
	assert.Nil(t, err)
	t.Cleanup(func() {
		tst.Destroy()
	})

	{
		svc := &corev1.Service{
			Spec: &corev1.Service_Spec{

				DynamicConfig: &corev1.Service_Spec_DynamicConfig{
					Configs: []*corev1.Service_Spec_Config{
						{
							Name: utilrand.GetRandomStringCanonical(7),
							Type: &corev1.Service_Spec_Config_Http{
								Http: &corev1.Service_Spec_Config_HTTP{
									Auth: &corev1.Service_Spec_Config_HTTP_Auth{
										Type: &corev1.Service_Spec_Config_HTTP_Auth_Basic_{
											Basic: &corev1.Service_Spec_Config_HTTP_Auth_Basic{
												Password: &corev1.Service_Spec_Config_HTTP_Auth_Basic_Password{
													Type: &corev1.Service_Spec_Config_HTTP_Auth_Basic_Password_FromSecret{
														FromSecret: utilrand.GetRandomStringCanonical(8),
													},
												},
											},
										},
									},
								},
							},
						},
					},
				},
			},
		}

		cfg := svc.Spec.DynamicConfig.Configs[0]
		res := GetMergedServiceConfig(cfg, svc)

		assert.True(t, pbutils.IsEqual(res, cfg))
	}

	{
		svc := &corev1.Service{
			Spec: &corev1.Service_Spec{

				DynamicConfig: &corev1.Service_Spec_DynamicConfig{
					Configs: []*corev1.Service_Spec_Config{
						{
							Name:   utilrand.GetRandomStringCanonical(7),
							Parent: "default",
							Type: &corev1.Service_Spec_Config_Http{
								Http: &corev1.Service_Spec_Config_HTTP{
									Auth: &corev1.Service_Spec_Config_HTTP_Auth{
										Type: &corev1.Service_Spec_Config_HTTP_Auth_Basic_{
											Basic: &corev1.Service_Spec_Config_HTTP_Auth_Basic{
												Password: &corev1.Service_Spec_Config_HTTP_Auth_Basic_Password{
													Type: &corev1.Service_Spec_Config_HTTP_Auth_Basic_Password_FromSecret{
														FromSecret: utilrand.GetRandomStringCanonical(8),
													},
												},
											},
										},
									},
								},
							},
						},
					},
				},
			},
		}

		cfg := svc.Spec.DynamicConfig.Configs[0]
		res := GetMergedServiceConfig(cfg, svc)

		assert.True(t, pbutils.IsEqual(res, cfg))
	}

	{
		svc := &corev1.Service{
			Spec: &corev1.Service_Spec{
				Config: &corev1.Service_Spec_Config{
					Type: &corev1.Service_Spec_Config_Http{
						Http: &corev1.Service_Spec_Config_HTTP{
							Auth: &corev1.Service_Spec_Config_HTTP_Auth{
								Type: &corev1.Service_Spec_Config_HTTP_Auth_Basic_{
									Basic: &corev1.Service_Spec_Config_HTTP_Auth_Basic{
										Username: utilrand.GetRandomStringCanonical(12),
									},
								},
							},
						},
					},
				},

				DynamicConfig: &corev1.Service_Spec_DynamicConfig{
					Configs: []*corev1.Service_Spec_Config{
						{
							Name:   utilrand.GetRandomStringCanonical(7),
							Parent: "default",
							Type: &corev1.Service_Spec_Config_Http{
								Http: &corev1.Service_Spec_Config_HTTP{
									Auth: &corev1.Service_Spec_Config_HTTP_Auth{
										Type: &corev1.Service_Spec_Config_HTTP_Auth_Basic_{
											Basic: &corev1.Service_Spec_Config_HTTP_Auth_Basic{
												Password: &corev1.Service_Spec_Config_HTTP_Auth_Basic_Password{
													Type: &corev1.Service_Spec_Config_HTTP_Auth_Basic_Password_FromSecret{
														FromSecret: utilrand.GetRandomStringCanonical(8),
													},
												},
											},
										},
									},
								},
							},
						},
					},
				},
			},
		}

		cfg := svc.Spec.DynamicConfig.Configs[0]
		res := GetMergedServiceConfig(cfg, svc)

		assert.Equal(t, svc.Spec.Config.GetHttp().GetAuth().GetBasic().Username,
			res.GetHttp().GetAuth().GetBasic().Username)

		assert.Equal(t, cfg.GetHttp().GetAuth().GetBasic().Password.GetFromSecret(),
			res.GetHttp().GetAuth().GetBasic().Password.GetFromSecret())
	}

	{
		svc := &corev1.Service{
			Spec: &corev1.Service_Spec{

				DynamicConfig: &corev1.Service_Spec_DynamicConfig{
					Configs: []*corev1.Service_Spec_Config{

						{
							Name: "root",
							Type: &corev1.Service_Spec_Config_Http{
								Http: &corev1.Service_Spec_Config_HTTP{
									Auth: &corev1.Service_Spec_Config_HTTP_Auth{
										Type: &corev1.Service_Spec_Config_HTTP_Auth_Basic_{
											Basic: &corev1.Service_Spec_Config_HTTP_Auth_Basic{
												Username: utilrand.GetRandomStringCanonical(12),
											},
										},
									},
								},
							},
						},
						{
							Name:   utilrand.GetRandomStringCanonical(7),
							Parent: "root",
							Type: &corev1.Service_Spec_Config_Http{
								Http: &corev1.Service_Spec_Config_HTTP{
									Auth: &corev1.Service_Spec_Config_HTTP_Auth{
										Type: &corev1.Service_Spec_Config_HTTP_Auth_Basic_{
											Basic: &corev1.Service_Spec_Config_HTTP_Auth_Basic{
												Password: &corev1.Service_Spec_Config_HTTP_Auth_Basic_Password{
													Type: &corev1.Service_Spec_Config_HTTP_Auth_Basic_Password_FromSecret{
														FromSecret: utilrand.GetRandomStringCanonical(8),
													},
												},
											},
										},
									},
								},
							},
						},
					},
				},
			},
		}

		cfg := svc.Spec.DynamicConfig.Configs[1]
		root := svc.Spec.DynamicConfig.Configs[0]
		res := GetMergedServiceConfig(cfg, svc)

		assert.Equal(t, root.GetHttp().GetAuth().GetBasic().Username,
			res.GetHttp().GetAuth().GetBasic().Username)

		assert.Equal(t, cfg.GetHttp().GetAuth().GetBasic().Password.GetFromSecret(),
			res.GetHttp().GetAuth().GetBasic().Password.GetFromSecret())
	}
}
