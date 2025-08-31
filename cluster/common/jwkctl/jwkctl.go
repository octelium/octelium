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

package jwkctl

import (
	"context"
	"crypto"
	"crypto/ed25519"
	"encoding/base64"
	"regexp"
	"sync"
	"time"

	"github.com/asaskevich/govalidator"
	"github.com/google/uuid"
	"github.com/octelium/octelium/apis/main/authv1"
	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/apis/rsc/rmetav1"
	"github.com/octelium/octelium/cluster/common/jwkctl/jwkutils"
	"github.com/octelium/octelium/cluster/common/octeliumc"
	"github.com/octelium/octelium/cluster/common/watchers"
	"github.com/octelium/octelium/pkg/apiutils/ucorev1"
	"github.com/octelium/octelium/pkg/apiutils/umetav1"
	"github.com/octelium/octelium/pkg/common/pbutils"
	utils_cert "github.com/octelium/octelium/pkg/utils/cert"
	"github.com/pkg/errors"
	"go.uber.org/zap"
)

type Controller struct {
	octeliumC octeliumc.ClientInterface
	ctl       *ctl
	domain    string
}

type jwtKey struct {
	key crypto.Signer

	createdAt time.Time
	uid       string
}

func NewJWKController(ctx context.Context, octeliumC octeliumc.ClientInterface) (*Controller, error) {
	ret := &Controller{
		octeliumC: octeliumC,
		ctl: &ctl{
			octeliumC: octeliumC,
			keyMap:    make(map[string]*jwtKey),
		},
	}

	secrets, err := octeliumC.CoreC().ListSecret(ctx, &rmetav1.ListOptions{
		SystemLabels: map[string]string{
			"octelium-root-secret": "true",
		},
	})
	if err != nil {
		return nil, err
	}

	if len(secrets.Items) < 1 {
		if _, err := jwkutils.CreateJWKSecret(ctx, octeliumC); err != nil {
			return nil, err
		}

		secrets, err = octeliumC.CoreC().ListSecret(ctx, &rmetav1.ListOptions{
			SystemLabels: map[string]string{
				"octelium-root-secret": "true",
			},
		})
		if err != nil {
			return nil, err
		}
	}

	for _, s := range secrets.Items {
		if err := ret.ctl.setKey(s); err != nil {
			return nil, err
		}
	}

	cc, err := octeliumC.CoreV1Utils().GetClusterConfig(ctx)
	if err != nil {
		return nil, err
	}

	ret.domain = cc.Status.Domain

	return ret, nil
}

func (c *Controller) Run(ctx context.Context) error {
	if err := watchers.NewCoreV1(c.octeliumC).Secret(ctx,
		nil, c.ctl.onAddSecret, c.ctl.onUpdateSecret, c.ctl.onDeleteSecret); err != nil {
		return err
	}

	return nil
}

type ctl struct {
	octeliumC octeliumc.ClientInterface
	keyMap    map[string]*jwtKey
	sync.RWMutex
}

func (c *ctl) isJWKSecret(s *corev1.Secret) bool {
	if s.Metadata.SystemLabels == nil {
		return false
	}
	if s.Metadata.SystemLabels["octelium-root-secret"] == "true" {
		return true
	}
	return false
}

func (c *ctl) onAddSecret(ctx context.Context, s *corev1.Secret) error {
	return c.setKey(s)
}

func (c *ctl) setKey(s *corev1.Secret) error {
	if !c.isJWKSecret(s) {
		return nil
	}

	zap.L().Debug("Setting root Secret in jwkCtl", zap.Any("secretMetadata", s.Metadata))

	key, err := utils_cert.ParsePrivateKeyPEM(ucorev1.ToSecret(s).GetValueBytes())
	if err != nil {
		return err
	}

	c.Lock()
	c.keyMap[s.Metadata.Uid] = &jwtKey{
		key:       key,
		createdAt: s.Metadata.CreatedAt.AsTime(),
		uid:       s.Metadata.Uid,
	}
	c.Unlock()

	zap.L().Debug("Successfully root Secret in jwkCtl", zap.Any("secretMetadata", s.Metadata))

	return nil
}

func (c *ctl) onUpdateSecret(ctx context.Context, new, old *corev1.Secret) error {
	return c.setKey(new)
}

func (c *ctl) onDeleteSecret(ctx context.Context, s *corev1.Secret) error {
	if !c.isJWKSecret(s) {
		return nil
	}

	zap.L().Debug("Deleting root Secret in jwkCtl", zap.Any("secretMetadata", s.Metadata))

	c.Lock()
	delete(c.keyMap, s.Metadata.Uid)
	c.Unlock()

	return nil
}

func (c *Controller) chooseJWK() (*jwtKey, error) {

	c.ctl.RLock()
	defer c.ctl.RUnlock()

	if len(c.ctl.keyMap) < 1 {
		return nil, errors.Errorf("Could not find a JWK")
	}

	var ret *jwtKey

	for _, jwk := range c.ctl.keyMap {
		if ret == nil {
			ret = jwk
		} else if jwk.createdAt.After(ret.createdAt) {
			ret = jwk
		}
	}

	if ret == nil {
		return nil, errors.Errorf("Could not find a JWK")
	}

	return ret, nil
}

func (c *Controller) findKeyByUID(uid string) (*jwtKey, error) {
	if !govalidator.IsUUIDv4(uid) {
		return nil, errors.Errorf("Invalid uid: %s", uid)
	}

	c.ctl.RLock()
	defer c.ctl.RUnlock()

	if k, ok := c.ctl.keyMap[uid]; ok {
		return k, nil
	}

	return nil, errors.Errorf("Cannot find key of kid: %s", uid)
}

func (c *Controller) createToken(content *authv1.TokenT0_Content) (string, error) {
	key, err := c.chooseJWK()
	if err != nil {
		return "", err
	}

	ret := &authv1.TokenT0{
		Content: content,
	}
	ret.Content.KeyID = c.uidToBytes(key.uid)

	if ret.Content.ExpiresAt.IsValid() {
		if time.Now().After(ret.Content.ExpiresAt.AsTime()) {
			return "", errors.Errorf("expiresAt is already exceeded")
		}

		ret.Content.ExpiresAt.Nanos = 0
	}

	contentBytes, err := pbutils.Marshal(ret.Content)
	if err != nil {
		return "", err
	}

	ret.Signature = ed25519.Sign(key.key.(ed25519.PrivateKey), contentBytes)

	tknBytes, err := pbutils.Marshal(ret)
	if err != nil {
		return "", err
	}

	finalTknBytes := make([]byte, len(tknBytes)+1)
	finalTknBytes[0] = 0x1
	copy(finalTknBytes[1:], tknBytes)

	return base64.RawURLEncoding.EncodeToString(finalTknBytes), nil
}

func (c *Controller) CreateAccessToken(sess *corev1.Session) (string, error) {
	if sess == nil || sess.Status.Authentication == nil || sess.Status.Authentication.TokenID == "" ||
		!sess.Status.Authentication.SetAt.IsValid() {
		return "", errors.Errorf("Session authentication field is not set")
	}

	return c.createToken(&authv1.TokenT0_Content{
		Type:    authv1.TokenT0_Content_ACCESS_TOKEN,
		Subject: c.uidToBytes(sess.Metadata.Uid),
		TokenID: c.uidToBytes(sess.Status.Authentication.TokenID),
		ExpiresAt: pbutils.Timestamp(sess.Status.Authentication.SetAt.AsTime().
			Add(umetav1.ToDuration(sess.Status.Authentication.AccessTokenDuration).ToGo())),
	})
}

func (c *Controller) CreateRefreshToken(sess *corev1.Session) (string, error) {
	if sess == nil || sess.Status.Authentication == nil || sess.Status.Authentication.TokenID == "" ||
		!sess.Status.Authentication.SetAt.IsValid() {
		return "", errors.Errorf("Session authentication field is not set")
	}

	return c.createToken(&authv1.TokenT0_Content{
		Type:    authv1.TokenT0_Content_REFRESH_TOKEN,
		Subject: c.uidToBytes(sess.Metadata.Uid),
		TokenID: c.uidToBytes(sess.Status.Authentication.TokenID),
		ExpiresAt: pbutils.Timestamp(sess.Status.Authentication.SetAt.AsTime().
			Add(umetav1.ToDuration(sess.Status.Authentication.RefreshTokenDuration).ToGo())),
	})
}

func (c *Controller) CreateCredential(cred *corev1.Credential) (string, error) {
	if cred == nil || cred.Status.TokenID == "" {
		return "", errors.Errorf("tokenID must be set")
	}

	return c.createToken(&authv1.TokenT0_Content{
		Type:      authv1.TokenT0_Content_CREDENTIAL,
		Subject:   c.uidToBytes(cred.Metadata.Uid),
		TokenID:   c.uidToBytes(cred.Status.TokenID),
		ExpiresAt: cred.Spec.ExpiresAt,
	})
}

func (c *Controller) uidToBytes(uid string) []byte {
	ret, _ := uuid.MustParse(uid).MarshalBinary()
	return ret
}

var rgxT0 = regexp.MustCompile(`^[A-Za-z0-9-_]{150,220}$`)

func (c *Controller) parseToken(tknStr string) (*authv1.TokenT0, error) {
	strLen := len(tknStr)
	if strLen == 0 {
		return nil, errors.Errorf("Empty token")
	}

	if strLen < 140 {
		return nil, errors.Errorf("Token is too short")
	}

	if strLen > 300 {
		return nil, errors.Errorf("Token is too large")
	}

	if !rgxT0.MatchString(tknStr) {
		return nil, errors.Errorf("Invalid token")
	}

	totalTknBytes, err := base64.RawURLEncoding.DecodeString(tknStr)
	if err != nil {
		return nil, errors.Errorf("Could not decode token")
	}

	lenTotalTknBytes := len(totalTknBytes)

	if lenTotalTknBytes < 100 || lenTotalTknBytes > 200 {
		return nil, errors.Errorf("Invalid token bytes")
	}

	switch totalTknBytes[0] {
	case 0x1:
	default:
		return nil, errors.Errorf("Invalid token type")
	}

	tkn := &authv1.TokenT0{}
	if err := pbutils.Unmarshal(totalTknBytes[1:], tkn); err != nil {
		return nil, err
	}

	if len(tkn.Signature) == 0 {
		return nil, errors.Errorf("No signature")
	}
	if tkn.Content == nil {
		return nil, errors.Errorf("No content")
	}

	keyUID, err := c.getUID(tkn.Content.KeyID)
	if err != nil {
		return nil, err
	}

	key, err := c.findKeyByUID(keyUID)
	if err != nil {
		return nil, err
	}

	contentByte, err := pbutils.Marshal(tkn.Content)
	if err != nil {
		return nil, err
	}

	if isValid := ed25519.Verify(key.key.(ed25519.PrivateKey).Public().(ed25519.PublicKey), contentByte, tkn.Signature); !isValid {
		return nil, errors.Errorf("Invalid signature")
	}

	if _, err := c.getUID(tkn.Content.Subject); err != nil {
		return nil, err
	}

	if _, err := c.getUID(tkn.Content.TokenID); err != nil {
		return nil, err
	}

	if tkn.Content.Type == authv1.TokenT0_Content_TYPE_UNKNOWN {
		return nil, errors.Errorf("Unknown token type")
	}

	if tkn.Content.ExpiresAt.IsValid() && time.Now().After(tkn.Content.ExpiresAt.AsTime()) {
		return nil, errors.Errorf("Token is expired")
	}

	return tkn, nil
}

func (c *Controller) getUID(b []byte) (string, error) {
	if len(b) != 16 {
		return "", errors.Errorf("Invalid uid")
	}
	uid, err := uuid.FromBytes(b)
	if err != nil {
		return "", err
	}
	ret := uid.String()
	if !govalidator.IsUUIDv4(ret) {
		return "", errors.Errorf("Invalid uid")
	}

	return ret, nil
}

type AccessTokenClaims struct {
	SessionUID string
	TokenID    string
}

type RefreshTokenClaims struct {
	SessionUID string
	TokenID    string
}

type CredentialClaims struct {
	UID     string
	TokenID string
}

type tokenClaims struct {
	subject string
	tokenID string
	tkn     *authv1.TokenT0
}

func (c *Controller) verifyToken(tknStr string, typ authv1.TokenT0_Content_Type) (*tokenClaims, error) {
	tkn, err := c.parseToken(tknStr)
	if err != nil {
		return nil, err
	}

	subject, err := c.getUID(tkn.Content.Subject)
	if err != nil {
		return nil, err
	}
	tokenID, err := c.getUID(tkn.Content.TokenID)
	if err != nil {
		return nil, err
	}

	if tkn.Content.Type != typ {
		return nil, errors.Errorf("The token type is not %s", typ.String())
	}

	ret := &tokenClaims{
		subject: subject,
		tokenID: tokenID,
		tkn:     tkn,
	}

	return ret, nil
}

func (c *Controller) VerifyAccessToken(tknStr string) (*AccessTokenClaims, error) {
	tokenClaims, err := c.verifyToken(tknStr, authv1.TokenT0_Content_ACCESS_TOKEN)
	if err != nil {
		return nil, err
	}

	return &AccessTokenClaims{
		SessionUID: tokenClaims.subject,
		TokenID:    tokenClaims.tokenID,
	}, nil
}

func (c *Controller) VerifyRefreshToken(tknStr string) (*RefreshTokenClaims, error) {
	tokenClaims, err := c.verifyToken(tknStr, authv1.TokenT0_Content_REFRESH_TOKEN)
	if err != nil {
		return nil, err
	}

	return &RefreshTokenClaims{
		SessionUID: tokenClaims.subject,
		TokenID:    tokenClaims.tokenID,
	}, nil
}

func (c *Controller) VerifyCredential(tknStr string) (*CredentialClaims, error) {
	tokenClaims, err := c.verifyToken(tknStr, authv1.TokenT0_Content_CREDENTIAL)
	if err != nil {
		return nil, err
	}

	return &CredentialClaims{
		UID:     tokenClaims.subject,
		TokenID: tokenClaims.tokenID,
	}, nil
}
