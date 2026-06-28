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

package wrdpgw

import (
	"context"
	"encoding/hex"
	"strings"

	"github.com/octelium/octelium/pkg/apiutils/ucorev1"
	"github.com/pkg/errors"
	"go.uber.org/zap"
)

func (s *server) getInjectedCredential(ctx context.Context) (*injectedCredential, error) {
	svc := s.vCache.GetService()
	if svc == nil {
		return nil, errors.Errorf("could not get Service from vcache")
	}

	cfg := svc.Spec.GetConfig()
	if cfg == nil {
		return nil, nil
	}

	rdp := cfg.GetRdp()
	if rdp == nil {
		return nil, nil
	}

	auth := rdp.GetAuth()
	if auth == nil {
		return nil, nil
	}

	pwd := auth.GetPassword()
	if pwd == nil || pwd.GetFromSecret() == "" {
		return nil, nil
	}

	if auth.GetUser() == "" {
		return nil, errors.Errorf("RDP injected credential is missing a username")
	}

	secret, err := s.secretMan.GetByName(ctx, pwd.GetFromSecret())
	if err != nil {
		return nil, err
	}

	return &injectedCredential{
		Domain:   auth.GetDomain(),
		Username: auth.GetUser(),
		Password: ucorev1.ToSecret(secret).GetValueStr(),
	}, nil
}

func (s *server) getUpstreamTLSTrust() (*tlsTrustPolicy, error) {
	svc := s.vCache.GetService()
	if svc == nil {
		return nil, errors.Errorf("could not get Service from vcache")
	}

	cfg := svc.Spec.GetConfig()
	if cfg == nil {
		return &tlsTrustPolicy{allowAnyCert: true}, nil
	}

	rdp := cfg.GetRdp()
	if rdp == nil {
		return &tlsTrustPolicy{allowAnyCert: true}, nil
	}

	upstreamTLS := rdp.GetUpstreamTLS()
	if upstreamTLS == nil {
		zap.L().Warn("wrdpgw upstream TLS trust is not configured, accepting any upstream certificate")
		return &tlsTrustPolicy{allowAnyCert: true}, nil
	}

	var pins [][32]byte
	for _, raw := range upstreamTLS.GetPinnedCertSHA256() {
		pin, err := parseSHA256Pin(raw)
		if err != nil {
			return nil, err
		}
		pins = append(pins, pin)
	}

	if len(pins) == 0 {
		if upstreamTLS.GetAllowAnyCert() {
			zap.L().Warn("wrdpgw upstream TLS trust allows any upstream certificate")
			return &tlsTrustPolicy{allowAnyCert: true}, nil
		}
		return nil, errors.Errorf("wrdpgw upstream TLS trust has neither pinned fingerprints nor allowAnyCert")
	}

	return &tlsTrustPolicy{pinnedSHA256: pins}, nil
}

func parseSHA256Pin(raw string) ([32]byte, error) {
	var pin [32]byte

	cleaned := strings.ReplaceAll(strings.TrimSpace(raw), ":", "")
	cleaned = strings.TrimPrefix(cleaned, "sha256/")

	decoded, err := hex.DecodeString(cleaned)
	if err != nil {
		return pin, errors.Errorf("invalid SHA256 certificate pin")
	}

	if len(decoded) != 32 {
		return pin, errors.Errorf("SHA256 certificate pin must be 32 bytes")
	}

	copy(pin[:], decoded)
	return pin, nil
}
