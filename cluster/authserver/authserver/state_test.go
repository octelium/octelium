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

package authserver

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/octelium/octelium/cluster/apiserver/apiserver/admin"
	"github.com/octelium/octelium/cluster/common/tests"
	"github.com/octelium/octelium/cluster/common/tests/tstuser"
	"github.com/octelium/octelium/cluster/common/vutils"
	"github.com/octelium/octelium/pkg/utils/utilrand"
	"github.com/stretchr/testify/assert"
)

func TestAuthenticatorCallbackState(t *testing.T) {
	ctx := context.Background()

	tst, err := tests.Initialize(nil)
	assert.Nil(t, err)
	t.Cleanup(func() {
		tst.Destroy()
	})
	fakeC := tst.C
	cc, err := tst.C.OcteliumC.CoreV1Utils().GetClusterConfig(ctx)
	assert.Nil(t, err)

	srv, err := initServer(ctx, fakeC.OcteliumC, cc)
	assert.Nil(t, err)

	adminSrv := admin.NewServer(&admin.Opts{
		OcteliumC:  fakeC.OcteliumC,
		IsEmbedded: true,
	})

	{

		usrT, err := tstuser.NewUserWeb(srv.octeliumC, adminSrv, nil, nil)
		assert.Nil(t, err)

		callbackURL := fmt.Sprintf("https://example.com/%s", utilrand.GetRandomString(32))

		err = srv.saveAuthenticatorCallbackState(ctx, usrT.Session, &loginState{
			CallbackURL: callbackURL,
			IsApp:       true,
		})
		assert.Nil(t, err)

		res, err := srv.loadAuthenticatorCallbackState(ctx, usrT.Session)
		assert.Nil(t, err)

		assert.Equal(t, callbackURL, res.CallbackURL)
		assert.True(t, res.IsApp)

		_, err = srv.loadAuthenticatorCallbackState(ctx, usrT.Session)
		assert.NotNil(t, err)
	}
}

func newStateID() string {
	return utilrand.GetRandomStringCanonical(36)
}

func TestRgxStateID(t *testing.T) {

	valids := []string{
		utilrand.GetRandomStringCanonical(36),
		strings.Repeat("a", 36),
		strings.Repeat("A", 36),
		strings.Repeat("0", 36),
		"aA0" + strings.Repeat("z", 33),
	}

	for _, valid := range valids {
		assert.True(t, rgxStateID.MatchString(valid), "%s", valid)
	}

	invalids := []string{
		"",
		strings.Repeat("a", 35),
		strings.Repeat("a", 37),
		strings.Repeat("-", 36),
		strings.Repeat("a", 35) + "-",
		strings.Repeat("a", 35) + "_",
		strings.Repeat("a", 35) + " ",
		vutils.UUIDv4(),
		fmt.Sprintf("%s\n", strings.Repeat("a", 36)),
	}

	for _, invalid := range invalids {
		assert.False(t, rgxStateID.MatchString(invalid), "%q", invalid)
	}
}

func TestAuthKeys(t *testing.T) {

	ctx := context.Background()

	tst, err := tests.Initialize(nil)
	assert.Nil(t, err)
	t.Cleanup(func() {
		tst.Destroy()
	})
	fakeC := tst.C
	cc, err := tst.C.OcteliumC.CoreV1Utils().GetClusterConfig(ctx)
	assert.Nil(t, err)

	srv, err := initServer(ctx, fakeC.OcteliumC, cc)
	assert.Nil(t, err)

	adminSrv := admin.NewServer(&admin.Opts{
		OcteliumC:  fakeC.OcteliumC,
		IsEmbedded: true,
	})

	{
		assert.Equal(t, "authserver.ls.abc", getAuthKey("abc"))
		assert.Equal(t, getAuthKey("abc"), getAuthKey("abc"))
		assert.NotEqual(t, getAuthKey("abc"), getAuthKey("abd"))
	}

	{
		usrT, err := tstuser.NewUserWeb(srv.octeliumC, adminSrv, nil, nil)
		assert.Nil(t, err)

		usr2T, err := tstuser.NewUserWeb(srv.octeliumC, adminSrv, nil, nil)
		assert.Nil(t, err)

		key := getAuthenticatorCallbackKey(usrT.Session)

		assert.Equal(t, fmt.Sprintf("authserver.ls.authn.%s", usrT.Session.Metadata.Uid), key)
		assert.Equal(t, key, getAuthenticatorCallbackKey(usrT.Session))
		assert.NotEqual(t, key, getAuthenticatorCallbackKey(usr2T.Session))

		assert.NotEqual(t, getAuthKey(usrT.Session.Metadata.Uid), key)
	}
}

func TestLoginStateSaveLoad(t *testing.T) {

	ctx := context.Background()

	tst, err := tests.Initialize(nil)
	assert.Nil(t, err)
	t.Cleanup(func() {
		tst.Destroy()
	})
	fakeC := tst.C
	cc, err := tst.C.OcteliumC.CoreV1Utils().GetClusterConfig(ctx)
	assert.Nil(t, err)

	srv, err := initServer(ctx, fakeC.OcteliumC, cc)
	assert.Nil(t, err)

	{
		stateID := newStateID()

		err := srv.saveLoginState(ctx, &loginState{
			ID:          stateID,
			UID:         vutils.UUIDv4(),
			CallbackURL: "https://example.com/cb",
			IsApp:       true,
		})
		assert.Nil(t, err)

		state, err := srv.getLoginStateFromStateID(ctx, stateID)
		assert.Nil(t, err, "%+v", err)
		assert.Equal(t, stateID, state.ID)
		assert.Equal(t, "https://example.com/cb", state.CallbackURL)
		assert.True(t, state.IsApp)

		_, err = srv.getLoginStateFromStateID(ctx, stateID)
		assert.NotNil(t, err)
	}

	{
		_, err := srv.getLoginStateFromStateID(ctx, newStateID())
		assert.NotNil(t, err)
	}

	{
		stateID1 := newStateID()
		stateID2 := newStateID()

		assert.Nil(t, srv.saveLoginState(ctx, &loginState{
			ID:          stateID1,
			CallbackURL: "https://example.com/one",
		}))
		assert.Nil(t, srv.saveLoginState(ctx, &loginState{
			ID:          stateID2,
			CallbackURL: "https://example.com/two",
		}))

		state1, err := srv.getLoginStateFromStateID(ctx, stateID1)
		assert.Nil(t, err)
		assert.Equal(t, "https://example.com/one", state1.CallbackURL)

		state2, err := srv.getLoginStateFromStateID(ctx, stateID2)
		assert.Nil(t, err)
		assert.Equal(t, "https://example.com/two", state2.CallbackURL)
	}
}

func TestGetStateIDFromCookie(t *testing.T) {

	{
		req := httptest.NewRequest("GET", "http://localhost/callback", nil)
		_, err := getStateIDFromCookie(req)
		assert.NotNil(t, err)
	}

	{
		req := httptest.NewRequest("GET", "http://localhost/callback", nil)
		req.AddCookie(&http.Cookie{
			Name:  "octelium_login_state",
			Value: "",
		})
		_, err := getStateIDFromCookie(req)
		assert.NotNil(t, err)
	}

	{
		req := httptest.NewRequest("GET", "http://localhost/callback", nil)
		req.AddCookie(&http.Cookie{
			Name:  "octelium_login_state",
			Value: strings.Repeat("a", 35),
		})
		_, err := getStateIDFromCookie(req)
		assert.NotNil(t, err)
	}

	{
		req := httptest.NewRequest("GET", "http://localhost/callback", nil)
		req.AddCookie(&http.Cookie{
			Name:  "octelium_other",
			Value: newStateID(),
		})
		_, err := getStateIDFromCookie(req)
		assert.NotNil(t, err)
	}

	{
		stateID := newStateID()

		req := httptest.NewRequest("GET", "http://localhost/callback", nil)
		req.AddCookie(&http.Cookie{
			Name:  "octelium_login_state",
			Value: stateID,
		})

		ret, err := getStateIDFromCookie(req)
		assert.Nil(t, err)
		assert.Equal(t, stateID, ret)
	}
}

func TestGetLoginStateFromCallback(t *testing.T) {

	ctx := context.Background()

	tst, err := tests.Initialize(nil)
	assert.Nil(t, err)
	t.Cleanup(func() {
		tst.Destroy()
	})
	fakeC := tst.C
	cc, err := tst.C.OcteliumC.CoreV1Utils().GetClusterConfig(ctx)
	assert.Nil(t, err)

	srv, err := initServer(ctx, fakeC.OcteliumC, cc)
	assert.Nil(t, err)

	newGetReq := func(query string, cookieVal string) *http.Request {
		req := httptest.NewRequest("GET",
			fmt.Sprintf("http://localhost/callback?%s", query), nil)
		if cookieVal != "" {
			req.AddCookie(&http.Cookie{
				Name:  "octelium_login_state",
				Value: cookieVal,
			})
		}
		return req
	}

	newPostReq := func(vals url.Values, cookieVal string) *http.Request {
		req := httptest.NewRequest("POST", "http://localhost/callback",
			strings.NewReader(vals.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		if cookieVal != "" {
			req.AddCookie(&http.Cookie{
				Name:  "octelium_login_state",
				Value: cookieVal,
			})
		}
		return req
	}

	{
		req := httptest.NewRequest("PUT", "http://localhost/callback", nil)
		_, err := srv.getLoginStateFromCallback(req)
		assert.NotNil(t, err)
	}

	{
		_, err := srv.getLoginStateFromCallback(
			newGetReq("error=access_denied&error_description=nope", ""))
		assert.NotNil(t, err)
	}

	{
		_, err := srv.getLoginStateFromCallback(newGetReq("", ""))
		assert.NotNil(t, err)
	}

	{
		_, err := srv.getLoginStateFromCallback(
			newGetReq(fmt.Sprintf("state=%s", strings.Repeat("a", 20)), ""))
		assert.NotNil(t, err)
	}

	{
		stateID := newStateID()
		_, err := srv.getLoginStateFromCallback(
			newGetReq(fmt.Sprintf("state=%s", stateID), ""))
		assert.NotNil(t, err)
	}

	{
		stateID := newStateID()
		otherStateID := newStateID()

		assert.Nil(t, srv.saveLoginState(ctx, &loginState{
			ID:          stateID,
			CallbackURL: "https://example.com/cb",
		}))

		_, err := srv.getLoginStateFromCallback(
			newGetReq(fmt.Sprintf("state=%s", stateID), otherStateID))
		assert.NotNil(t, err)
	}

	{
		stateID := newStateID()

		_, err := srv.getLoginStateFromCallback(
			newGetReq(fmt.Sprintf("state=%s", stateID), stateID))
		assert.NotNil(t, err)
	}

	{
		stateID := newStateID()

		assert.Nil(t, srv.saveLoginState(ctx, &loginState{
			ID:          stateID,
			UID:         vutils.UUIDv4(),
			CallbackURL: "https://example.com/cb",
			IsApp:       true,
		}))

		state, err := srv.getLoginStateFromCallback(
			newGetReq(fmt.Sprintf("state=%s", stateID), stateID))
		assert.Nil(t, err, "%+v", err)
		assert.Equal(t, stateID, state.ID)
		assert.Equal(t, "https://example.com/cb", state.CallbackURL)
		assert.True(t, state.IsApp)

		_, err = srv.getLoginStateFromCallback(
			newGetReq(fmt.Sprintf("state=%s", stateID), stateID))
		assert.NotNil(t, err)
	}

	{
		_, err := srv.getLoginStateFromCallback(newPostReq(url.Values{}, ""))
		assert.NotNil(t, err)
	}

	{
		stateID := newStateID()

		assert.Nil(t, srv.saveLoginState(ctx, &loginState{
			ID:          stateID,
			CallbackURL: "https://example.com/saml",
		}))

		vals := url.Values{}
		vals.Set("RelayState", stateID)

		state, err := srv.getLoginStateFromCallback(newPostReq(vals, stateID))
		assert.Nil(t, err, "%+v", err)
		assert.Equal(t, "https://example.com/saml", state.CallbackURL)
	}

	{
		stateID := newStateID()
		otherStateID := newStateID()

		assert.Nil(t, srv.saveLoginState(ctx, &loginState{
			ID: stateID,
		}))

		vals := url.Values{}
		vals.Set("RelayState", stateID)

		_, err := srv.getLoginStateFromCallback(newPostReq(vals, otherStateID))
		assert.NotNil(t, err)
	}
}
