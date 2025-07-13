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

package saml

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/crewjam/saml/samlidp"
	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/apis/main/metav1"
	"github.com/octelium/octelium/cluster/apiserver/apiserver/admin"
	"github.com/octelium/octelium/cluster/authserver/authserver/providers/utils"
	"github.com/octelium/octelium/cluster/common/tests"
	utils_cert "github.com/octelium/octelium/pkg/utils/cert"
	utils_types "github.com/octelium/octelium/pkg/utils/types"
	"github.com/octelium/octelium/pkg/utils/utilrand"
	"github.com/stretchr/testify/assert"
	"golang.org/x/net/html"
)

func TestProvider(t *testing.T) {

	ctx := context.Background()

	tst, err := tests.Initialize(nil)
	assert.Nil(t, err)
	t.Cleanup(func() {
		tst.Destroy()
	})
	fakeC := tst.C

	cc, err := tst.C.OcteliumC.CoreV1Utils().GetClusterConfig(ctx)
	assert.Nil(t, err)

	adminSrv := admin.NewServer(&admin.Opts{
		OcteliumC:  fakeC.OcteliumC,
		IsEmbedded: true,
	})

	ca, err := utils_cert.GenerateCARoot()
	assert.Nil(t, err)

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	assert.Nil(t, err)

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"Example Corp"},
			CommonName:   "example.com",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	crt, err := utils_cert.GenerateCertificate(&template, ca.Certificate, ca.PrivateKey, true)
	assert.Nil(t, err)

	samlIDP, err := samlidp.New(samlidp.Options{
		Certificate: crt.Certificate,
		Key:         privateKey,

		Store: &samlidp.MemoryStore{},
		URL:   url.URL{Scheme: "https", Host: "idp.example.com"},
	})
	assert.Nil(t, err)

	md, err := xml.Marshal(samlIDP.IDP.Metadata())
	assert.Nil(t, err)

	idp, err := adminSrv.CreateIdentityProvider(ctx, &corev1.IdentityProvider{
		Metadata: &metav1.Metadata{
			Name: utilrand.GetRandomStringCanonical(8),
		},
		Spec: &corev1.IdentityProvider_Spec{
			Type: &corev1.IdentityProvider_Spec_Saml{
				Saml: &corev1.IdentityProvider_Spec_SAML{
					MetadataType: &corev1.IdentityProvider_Spec_SAML_Metadata{
						Metadata: string(md),
					},
				},
			},
		},
	})
	assert.Nil(t, err)

	provider, err := NewConnector(ctx, &utils.ProviderOpts{
		OcteliumC:     fakeC.OcteliumC,
		ClusterConfig: cc,
		Provider:      idp,
	})
	assert.Nil(t, err)

	state := utilrand.GetRandomStringCanonical(32)
	loginURL, reqID, err := provider.LoginURL(state)
	assert.Nil(t, err)

	myUser := &samlidp.User{
		Name:              utilrand.GetRandomStringCanonical(8),
		Email:             fmt.Sprintf("%s@example.com", utilrand.GetRandomStringCanonical(8)),
		PlaintextPassword: utils_types.StrToPtr(utilrand.GetRandomString(32)),
	}
	{

		myUsrJSON, err := json.Marshal(myUser)
		assert.Nil(t, err)

		req := httptest.NewRequest(http.MethodPut,
			fmt.Sprintf("https://idp.example.com/users/%s", myUser.Name),
			bytes.NewBuffer(myUsrJSON))
		rw := httptest.NewRecorder()
		samlIDP.ServeHTTP(rw, req)
		assert.Equal(t, http.StatusNoContent, rw.Code)
	}

	{

		samlSP := &samlidp.Service{
			Name:     utilrand.GetRandomStringCanonical(8),
			Metadata: *provider.sp.Metadata(),
		}

		md, err := xml.Marshal(provider.sp.Metadata())
		assert.Nil(t, err)

		req := httptest.NewRequest(http.MethodPut,
			fmt.Sprintf("https://idp.example.com/services/%s", samlSP.Name),
			bytes.NewBuffer(md))
		rw := httptest.NewRecorder()
		samlIDP.ServeHTTP(rw, req)
		assert.Equal(t, http.StatusNoContent, rw.Code)
	}
	{

	}

	var cookie string
	{
		req := httptest.NewRequest(http.MethodPost, "https://idp.example.com/login",
			bytes.NewBuffer([]byte(fmt.Sprintf("user=%s&password=%s", myUser.Name, *myUser.PlaintextPassword))))

		req.Header.Set("Content-type", "application/x-www-form-urlencoded")
		rw := httptest.NewRecorder()
		samlIDP.ServeHTTP(rw, req)
		assert.Equal(t, http.StatusOK, rw.Code)

		cookie = rw.Header().Get("Set-Cookie")
	}

	myShortCut := &samlidp.Shortcut{
		Name:              utilrand.GetRandomStringCanonical(8),
		ServiceProviderID: provider.sp.EntityID,
	}

	{
		jsn, err := json.Marshal(myShortCut)
		assert.Nil(t, err)
		req := httptest.NewRequest(http.MethodPut, fmt.Sprintf("https://idp.example.com/shortcuts/%s", myShortCut.Name),
			bytes.NewBuffer([]byte(jsn)))

		rw := httptest.NewRecorder()
		samlIDP.ServeHTTP(rw, req)
		assert.Equal(t, http.StatusNoContent, rw.Code)

	}
	var body []byte
	{

		req := httptest.NewRequest(http.MethodGet, loginURL,
			nil)
		req.Header.Set("Cookie", cookie)
		rw := httptest.NewRecorder()
		samlIDP.ServeHTTP(rw, req)
		assert.Equal(t, http.StatusOK, rw.Code)

		bb, err := io.ReadAll(rw.Result().Body)
		assert.Nil(t, err)
		rw.Result().Body.Close()
		body = bb

	}

	{

		samlResponse, relayState, err := extractFormFields(body)
		assert.Nil(t, err)

		req := httptest.NewRequest(http.MethodPost, "https://example.com/callback",
			bytes.NewBuffer([]byte(fmt.Sprintf("SAMLResponse=%s&RelayState=%s", samlResponse, relayState))))
		req.Header.Set("Content-type", "application/x-www-form-urlencoded")
		_, _ = provider.HandleCallback(req, reqID)
	}

}

func extractFormFields(htmlBody []byte) (samlResponse, relayState string, err error) {
	doc, err := html.Parse(bytes.NewReader(htmlBody))
	if err != nil {
		return "", "", err
	}

	var traverse func(*html.Node)
	traverse = func(n *html.Node) {
		if n.Type == html.ElementNode && n.Data == "input" {
			var name, value string
			for _, attr := range n.Attr {
				if attr.Key == "name" {
					name = attr.Val
				}
				if attr.Key == "value" {
					value = attr.Val
				}
			}
			switch name {
			case "SAMLResponse":
				samlResponse = value
			case "RelayState":
				relayState = value
			}
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			traverse(c)
		}
	}

	traverse(doc)
	return
}
