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

package harness

import (
	"net/url"
	"testing"
	"time"

	"github.com/pquerna/otp"
	otptotp "github.com/pquerna/otp/totp"
)

const totpPeriodSeconds = 30

func TOTPSecret(t *testing.T, otpauthURL string) string {
	t.Helper()

	u, err := url.Parse(otpauthURL)
	if err != nil {
		t.Fatalf("Could not parse the TOTP registration url %q: %+v", otpauthURL, err)
	}

	secret := u.Query().Get("secret")
	if secret == "" {
		t.Fatalf("The TOTP registration url %q carries no shared secret", otpauthURL)
	}

	return secret
}

func TOTPStep(at time.Time) int64 {
	return at.Unix() / totpPeriodSeconds
}

func TOTPCode(t *testing.T, secret string, step int64) string {
	t.Helper()

	code, err := otptotp.GenerateCodeCustom(secret,
		time.Unix(step*totpPeriodSeconds, 0).UTC(),
		otptotp.ValidateOpts{
			Period:    totpPeriodSeconds,
			Digits:    otp.DigitsSix,
			Algorithm: otp.AlgorithmSHA1,
		})
	if err != nil {
		t.Fatalf("Could not generate a TOTP code: %+v", err)
	}

	return code
}
