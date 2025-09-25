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
	"github.com/octelium/octelium/cluster/common/celengine"
	"github.com/octelium/octelium/cluster/common/grpcutils"
	"github.com/octelium/octelium/pkg/grpcerr"
)

func checkCELExpression(ctx context.Context, arg string) error {
	engine, err := celengine.New(ctx, &celengine.Opts{})
	if err != nil {
		return grpcutils.InternalWithErr(err)
	}
	if err := engine.AddPolicy(ctx, arg); err != nil {
		return grpcutils.InvalidArgWithErr(err)
	}

	return nil
}

func getNamespace(name string) (string, error) {

	args := strings.Split(name, ".")
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
	if secOwner.GetFromSecret() == "" {
		return grpcutils.InvalidArg("Empty Secret name")
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

	if len(arg) > 256 {
		return grpcutils.InvalidArg("%s is too long", arg)
	}
	if !govalidator.IsASCII(arg) {
		return grpcutils.InvalidArg("%s is invalid", arg)
	}

	return nil
}
