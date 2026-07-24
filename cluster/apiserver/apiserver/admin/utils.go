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
	"strings"

	"github.com/asaskevich/govalidator"
	"github.com/octelium/octelium/apis/rsc/rmetav1"
	"github.com/octelium/octelium/cluster/apiserver/apiserver/serr"
	"github.com/octelium/octelium/cluster/common/apivalidation"
	"github.com/octelium/octelium/cluster/common/celengine"
	"github.com/octelium/octelium/cluster/common/grpcutils"
	"github.com/octelium/octelium/pkg/grpcerr"
)

const (
	maxGenStrLen = 256
)

func checkCELExpression(ctx context.Context, arg string) error {
	if strings.TrimSpace(arg) == "" {
		return grpcutils.InvalidArg("Empty CEL expression")
	}

	if len(arg) > maxCELExpressionLen {
		return grpcutils.InvalidArg("CEL expression is too long")
	}

	engine, err := celengine.New(ctx, &celengine.Opts{})
	if err != nil {
		return grpcutils.InternalWithErr(err)
	}
	if err := engine.AddPolicy(ctx, arg); err != nil {
		return grpcutils.InvalidArgWithErr(err)
	}

	return nil
}

func checkOPAMapAny(ctx context.Context, arg string) error {
	if strings.TrimSpace(arg) == "" {
		return grpcutils.InvalidArg("Empty OPA script")
	}

	if len(arg) > maxOPAScriptLen {
		return grpcutils.InvalidArg("OPA script is too large")
	}

	engine, err := celengine.New(ctx, &celengine.Opts{})
	if err != nil {
		return grpcutils.InternalWithErr(err)
	}

	if err := engine.AddPolicyMapAnyOPA(ctx, arg); err != nil {
		return grpcutils.InvalidArgWithErr(err)
	}

	return nil
}

func checkOPACondition(ctx context.Context, arg string) error {
	if strings.TrimSpace(arg) == "" {
		return grpcutils.InvalidArg("Empty OPA script")
	}

	if len(arg) > maxOPAScriptLen {
		return grpcutils.InvalidArg("OPA script is too large")
	}

	engine, err := celengine.New(ctx, &celengine.Opts{})
	if err != nil {
		return grpcutils.InternalWithErr(err)
	}

	if err := engine.AddPolicyOPA(ctx, arg); err != nil {
		return grpcutils.InvalidArgWithErr(err)
	}

	return nil
}

func getNamespace(name string) (string, error) {

	if name == "" {
		return "", serr.InvalidArg("Empty Service name")
	}

	args := strings.Split(name, ".")

	for _, arg := range args {
		if arg == "" {
			return "", serr.InvalidArg("Invalid Namespace name")
		}
	}

	if len(args) == 1 {
		return "default", nil
	}
	if len(args) == 2 {
		return args[1], nil
	}
	return "", serr.InvalidArg("Invalid Namespace name")
}

type secretOwner interface {
	GetFromSecret() string
}

func (s *Server) validateSecretOwner(ctx context.Context, secOwner secretOwner) error {
	if secOwner == nil {
		return grpcutils.InvalidArg("You must set fromSecret")
	}

	if err := apivalidation.ValidateName(secOwner.GetFromSecret(), 0, 0); err != nil {
		return grpcutils.InvalidArg("Invalid Secret name")
	}

	_, err := s.octeliumC.CoreC().GetSecret(ctx, &rmetav1.GetOptions{Name: secOwner.GetFromSecret()})
	if err == nil {
		return nil
	}
	if grpcerr.IsNotFound(err) || grpcerr.IsInvalidArg(err) {
		return grpcutils.InvalidArg("The Secret %s is not found", secOwner.GetFromSecret())

	}

	return grpcutils.InternalWithErr(err)
}

func (s *Server) validateGenStr(arg string, required bool, name string) error {
	if arg == "" {
		if required {
			return grpcutils.InvalidArg("%s is required", name)
		}
		return nil
	}

	if len(arg) > maxGenStrLen {
		return grpcutils.InvalidArg("%s is too long", name)
	}
	if !govalidator.IsASCII(arg) {
		return grpcutils.InvalidArg("%s is invalid", name)
	}

	return nil
}
