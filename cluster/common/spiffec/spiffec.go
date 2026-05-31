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

package spiffec

import (
	"context"
	"errors"
	"os"
	"strings"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
)

var ErrNotFound = errors.New("Octelium: SPIFFE socket not found")

func GetSPIFFEEndpointSocket() string {
	if val := strings.TrimSpace(os.Getenv("SPIFFE_ENDPOINT_SOCKET")); val != "" {
		if strings.HasPrefix(val, "unix://") {
			return val
		}
		return "unix://" + val
	}

	csiPaths := []string{
		"/run/spire/sockets/spire-agent.sock",
		"/run/spire/sockets/agent.sock",
	}

	for _, p := range csiPaths {
		st, err := os.Stat(p)
		if err == nil && st.Mode()&os.ModeSocket != 0 {
			return "unix://" + p
		}
	}

	return ""
}

func GetWorkloadC(ctx context.Context) (*workloadapi.Client, error) {
	socketAddr := GetSPIFFEEndpointSocket()
	if socketAddr == "" {
		return nil, ErrNotFound
	}

	return workloadapi.New(ctx, workloadapi.WithAddr(socketAddr))
}

func GetSPIFFESource(ctx context.Context) (*workloadapi.X509Source, error) {
	c, err := GetWorkloadC(ctx)
	if err != nil {
		return nil, err
	}

	source, err := workloadapi.NewX509Source(ctx, workloadapi.WithClient(c))
	if err != nil {
		_ = c.Close()
		return nil, err
	}

	return source, nil
}

func getAuthorizer(ctx context.Context, source *workloadapi.X509Source) (tlsconfig.Authorizer, error) {
	if val := strings.TrimSpace(os.Getenv("OCTELIUM_SPIFFE_TRUST_DOMAIN")); val != "" {
		td, err := spiffeid.TrustDomainFromString(val)
		if err != nil {
			return nil, err
		}

		return tlsconfig.AuthorizeMemberOf(td), nil
	}

	svid, err := source.GetX509SVID()
	if err != nil {
		return nil, err
	}

	return tlsconfig.AuthorizeMemberOf(svid.ID.TrustDomain()), nil
}

func logSVID(msg string, source *workloadapi.X509Source) {
	svid, err := source.GetX509SVID()
	if err != nil {
		zap.L().Debug(msg, zap.Error(err))
		return
	}

	fields := []zap.Field{
		zap.String("spiffeID", svid.ID.String()),
	}
	if len(svid.Certificates) > 0 {
		fields = append(fields, zap.String("subject", svid.Certificates[0].Subject.String()))
	}

	zap.L().Debug(msg, fields...)
}

type GetGRPCClientCredOpts struct {
}

func GetGRPCClientCred(ctx context.Context, o *GetGRPCClientCredOpts) (grpc.DialOption, error) {
	source, err := GetSPIFFESource(ctx)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			zap.L().Debug("SPIFFE socket not found; using insecure gRPC client credentials")
			return grpc.WithTransportCredentials(insecure.NewCredentials()), nil
		}
		return nil, err
	}

	authz, err := getAuthorizer(ctx, source)
	if err != nil {
		source.Close()
		return nil, err
	}

	logSVID("SPIFFE is enabled. Setting client credentials", source)

	tlsConfig := tlsconfig.MTLSClientConfig(source, source, authz)
	return grpc.WithTransportCredentials(credentials.NewTLS(tlsConfig)), nil
}

type GetGRPCServerCredOpts struct {
}

func GetGRPCServerCred(ctx context.Context, o *GetGRPCServerCredOpts) (grpc.ServerOption, error) {
	source, err := GetSPIFFESource(ctx)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			zap.L().Debug("SPIFFE socket not found; using insecure gRPC server credentials")
			return grpc.Creds(insecure.NewCredentials()), nil
		}
		return nil, err
	}

	authz, err := getAuthorizer(ctx, source)
	if err != nil {
		source.Close()
		return nil, err
	}

	logSVID("SPIFFE is enabled. Setting server credentials", source)

	tlsConfig := tlsconfig.MTLSServerConfig(source, source, authz)
	return grpc.Creds(credentials.NewTLS(tlsConfig)), nil
}
