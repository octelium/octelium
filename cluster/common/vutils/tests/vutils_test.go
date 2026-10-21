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

package vutils

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/apis/main/metav1"
	"github.com/octelium/octelium/cluster/common/tests"
	"github.com/octelium/octelium/cluster/common/vutils"
	"github.com/octelium/octelium/pkg/apiutils/ucorev1"
	utils_cert "github.com/octelium/octelium/pkg/utils/cert"
	"github.com/octelium/octelium/pkg/utils/utilrand"
	"github.com/stretchr/testify/assert"
)

func TestServiceNamesAndAddresses(t *testing.T) {
	for _, namespace := range []string{"default", "namespace"} {
		svc := &corev1.Service{Metadata: &metav1.Metadata{Name: "service." + namespace}, Status: &corev1.Service_Status{NamespaceRef: &metav1.ObjectReference{Name: namespace}}}
		prefix := "service"
		if namespace != "default" {
			prefix += "." + namespace
		}
		assert.Equal(t, prefix+".example.com", vutils.GetServicePublicFQDN(svc, "example.com"))
		assert.Equal(t, prefix+".local.example.com", vutils.GetServicePrivateFQDN(svc, "example.com"))
		assert.Equal(t, svc.Metadata.Name, vutils.GetServiceFullName(svc))
	}
	assert.Empty(t, vutils.GetServiceFullNameFromName("service.namespace.extra"))
	for _, tc := range []struct {
		network *metav1.DualStackNetwork
		index   int
		v4, v6  string
	}{
		{&metav1.DualStackNetwork{V4: "10.0.0.0/30", V6: "fd00::/126"}, 1, "10.0.0.1", "fd00::1"},
		{&metav1.DualStackNetwork{V4: "10.0.0.0/30"}, 3, "10.0.0.3", ""},
		{&metav1.DualStackNetwork{V6: "fd00::/126"}, 0, "", "fd00::"},
		{&metav1.DualStackNetwork{}, 1, "", ""},
	} {
		res, err := vutils.GetDualStackIPByIndex(tc.network, tc.index)
		assert.Nil(t, err)
		assert.Equal(t, tc.v4, res.Ipv4)
		assert.Equal(t, tc.v6, res.Ipv6)
	}
	for _, network := range []*metav1.DualStackNetwork{
		{V4: "invalid"}, {V6: "invalid"}, {V4: "10.0.0.0/30"}, {V6: "fd00::/126"},
	} {
		res, err := vutils.GetDualStackIPByIndex(network, 4)
		assert.NotNil(t, err)
		assert.Nil(t, res)
	}
}

func TestResourceAndHashHelpers(t *testing.T) {
	assert.Equal(t, "core/v1", vutils.GetApiVersion("core", "v1"))
	api, version := vutils.SplitApiVersion("core/v1")
	assert.Equal(t, "core", api)
	assert.Equal(t, "v1", version)
	api, version = vutils.SplitApiVersion("core")
	assert.Equal(t, "core", api)
	assert.Empty(t, version)
	obj, err := vutils.NewResourceObject(ucorev1.API, "v1", ucorev1.KindUser)
	assert.Nil(t, err)
	assert.IsType(t, &corev1.User{}, obj)
	list, err := vutils.NewResourceObjectList(ucorev1.API, "v1", ucorev1.KindUser)
	assert.Nil(t, err)
	assert.IsType(t, &corev1.UserList{}, list)
	_, err = vutils.NewResourceObject("invalid", "v1", "User")
	assert.NotNil(t, err)
	_, err = vutils.NewResourceObjectList("invalid", "v1", "User")
	assert.NotNil(t, err)
	assert.Empty(t, vutils.GetResourceName(nil))
	assert.Empty(t, vutils.GetResourceName(&corev1.User{}))
	assert.Equal(t, "user", vutils.GetResourceName(&corev1.User{Metadata: &metav1.Metadata{Name: "user"}}))
	assert.Equal(t, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad", vutils.Sha256SumHex([]byte("abc")))
	assert.Equal(t, fmt.Sprintf("%x", vutils.Sha256Sum([]byte("abc"))), vutils.Sha256SumHex([]byte("abc")))
	for _, tc := range []struct {
		uid     string
		version uuid.Version
	}{{vutils.UUIDv4(), 4}, {vutils.UUIDv7(), 7}} {
		uid, err := uuid.Parse(tc.uid)
		assert.Nil(t, err)
		assert.Equal(t, tc.version, uid.Version())
	}
	log := vutils.GenerateLog()
	assert.Equal(t, ucorev1.KindAccessLog, log.Kind)
	assert.NotEmpty(t, log.Metadata.Id)
	assert.True(t, log.Metadata.CreatedAt.IsValid())
	assert.NotEqual(t, log.Metadata.Id, vutils.GenerateLogID())
	assert.NotNil(t, log.Entry)
	assert.True(t, vutils.MustParseTime("invalid").IsZero())
	_, err = time.Parse(time.RFC3339Nano, vutils.NowRFC3339Nano())
	assert.Nil(t, err)
	assert.Equal(t, "X-Octelium-Client-Address", vutils.GetDownstreamIPHeaderCanonical())
}

func TestFilesystemHelpers(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "file")
	assert.Nil(t, os.WriteFile(path, []byte("data"), 0600))
	assert.True(t, vutils.DirExists(dir))
	assert.False(t, vutils.FileExists(dir))
	assert.True(t, vutils.FileExists(path))
	assert.False(t, vutils.DirExists(path))
	assert.True(t, vutils.FSPathExists(path))
	exists, err := vutils.FSPathExistent(path)
	assert.Nil(t, err)
	assert.True(t, exists)
	missing := filepath.Join(dir, "missing")
	assert.False(t, vutils.FSPathExists(missing))
	assert.False(t, vutils.FileExists(missing))
	assert.False(t, vutils.DirExists(missing))
	exists, err = vutils.FSPathExistent(missing)
	assert.Nil(t, err)
	assert.False(t, exists)
	exists, err = vutils.FSPathExistent("\x00")
	assert.NotNil(t, err)
	assert.False(t, exists)
}

func TestCertificateReadiness(t *testing.T) {
	sec := &corev1.Secret{Metadata: &metav1.Metadata{Name: vutils.ClusterCertSecretName, SystemLabels: map[string]string{"octelium-cert": "true"}}}
	assert.False(t, vutils.IsCertReady(sec))
	crt, err := utils_cert.GenerateSelfSignedCert("example.com", []string{"example.com"}, time.Hour)
	assert.Nil(t, err)
	ucorev1.ToSecret(sec).SetCertificate(string(crt.MustGetCertPEM()), string(crt.MustGetPrivateKeyPEM()))
	assert.True(t, vutils.IsCertReady(sec))
	assert.True(t, vutils.IsClusterCertAndReady(sec))
	assert.True(t, vutils.IsClusterCertAndReadyWithNamespace(sec, "default"))
	assert.True(t, vutils.IsOcteliumCert(sec))
	assert.False(t, vutils.IsClusterCertAndReadyWithNamespace(sec, "other"))
	sec.Metadata.Name = "other"
	assert.False(t, vutils.IsClusterCertAndReady(sec))
	sec.Metadata.SystemLabels = nil
	assert.False(t, vutils.IsOcteliumCert(sec))
	ucorev1.ToSecret(sec).SetCertificate("invalid", string(crt.MustGetPrivateKeyPEM()))
	assert.False(t, vutils.IsCertReady(sec))
	ucorev1.ToSecret(sec).SetCertificate(string(crt.MustGetCertPEM()), "invalid")
	assert.False(t, vutils.IsCertReady(sec))
}

func TestGetServiceFullNameFromName(t *testing.T) {

	tst, err := tests.Initialize(nil)
	assert.Nil(t, err)
	t.Cleanup(func() {
		tst.Destroy()
	})

	{
		assert.Equal(t, "nginx.default", vutils.GetServiceFullNameFromName("nginx"))
		assert.Equal(t, "nginx.test", vutils.GetServiceFullNameFromName("nginx.test"))

		assert.Equal(t, "", vutils.GetServiceFullNameFromName(""))
	}
	{
		svc := utilrand.GetRandomStringCanonical(8)
		ns := utilrand.GetRandomStringCanonical(8)

		assert.Equal(t, fmt.Sprintf("%s.default", svc), vutils.GetServiceFullNameFromName(svc))
		assert.Equal(t, fmt.Sprintf("%s.%s", svc, ns), vutils.GetServiceFullNameFromName(fmt.Sprintf("%s.%s", svc, ns)))
	}
}

func TestSetRegionPublicHostName(t *testing.T) {
	{
		r := &corev1.Region{
			Metadata: &metav1.Metadata{
				Name: "aws-eu-1",
				Uid:  "0b5e6d0e-6a1f-4c1d-9b3e-3f2a9c1b7e4d",
			},
			Status: &corev1.Region_Status{PublicHostname: "_r-aws-eu-1"},
		}
		vutils.SetRegionPublicHostName(r)
		assert.Equal(t, "octelium-region-3f2a9c1b7e4d", r.Status.PublicHostname)

		vutils.SetRegionPublicHostName(r)
		assert.Equal(t, "octelium-region-3f2a9c1b7e4d", r.Status.PublicHostname)
	}
	{
		name := utilrand.GetRandomStringCanonical(40)
		uid := vutils.UUIDv4()
		r := &corev1.Region{
			Metadata: &metav1.Metadata{Name: name, Uid: uid},
			Status:   &corev1.Region_Status{},
		}
		vutils.SetRegionPublicHostName(r)
		assert.Equal(t, fmt.Sprintf("octelium-region-%s", strings.Split(uid, "-")[4]), r.Status.PublicHostname)
		assert.False(t, strings.Contains(r.Status.PublicHostname, name))
		assert.False(t, strings.Contains(r.Status.PublicHostname, "_"))
		assert.Equal(t, 28, len(r.Status.PublicHostname))
	}
}
