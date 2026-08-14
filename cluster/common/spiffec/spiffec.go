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
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
)

var ErrNotFound = errors.New("Octelium: SPIFFE socket not found")

const (
	socketWaitTimeout  = 3 * time.Minute
	socketPollInterval = 2 * time.Second
	svidWaitTimeout    = 3 * time.Minute
)

func IsEnabled() bool {
	return strings.TrimSpace(os.Getenv("OCTELIUM_ENABLE_SPIFFE_CSI")) == "true"
}

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

func waitForEndpointSocket(ctx context.Context) (string, error) {
	if addr := GetSPIFFEEndpointSocket(); addr != "" {
		return addr, nil
	}

	if !IsEnabled() {
		return "", ErrNotFound
	}

	zap.L().Info("SPIFFE is enabled but the Workload API socket is not there yet. Waiting for it",
		zap.Duration("timeout", socketWaitTimeout))

	waitCtx, cancel := context.WithTimeout(ctx, socketWaitTimeout)
	defer cancel()

	ticker := time.NewTicker(socketPollInterval)
	defer ticker.Stop()

	for {
		select {
		case <-waitCtx.Done():
			if ctx.Err() != nil {
				return "", ctx.Err()
			}
			return "", fmt.Errorf(
				"Octelium: this Cluster is installed with SPIFFE but no SPIFFE Workload API "+
					"socket showed up under /run/spire/sockets after %s. The SPIRE agent is "+
					"not running on this node, or the SPIFFE CSI driver is not the one the "+
					"Cluster was installed with", socketWaitTimeout)
		case <-ticker.C:
			if addr := GetSPIFFEEndpointSocket(); addr != "" {
				return addr, nil
			}
		}
	}
}

func GetWorkloadC(ctx context.Context) (*workloadapi.Client, error) {
	addr, err := waitForEndpointSocket(ctx)
	if err != nil {
		return nil, err
	}

	return workloadapi.New(ctx, workloadapi.WithAddr(addr))
}

func GetSPIFFESource(ctx context.Context) (*workloadapi.X509Source, error) {
	addr, err := waitForEndpointSocket(ctx)
	if err != nil {
		return nil, err
	}

	c, err := workloadapi.New(ctx, workloadapi.WithAddr(addr))
	if err != nil {
		return nil, err
	}

	svidCtx, cancel := context.WithTimeout(ctx, svidWaitTimeout)
	defer cancel()

	source, err := workloadapi.NewX509Source(svidCtx, workloadapi.WithClient(c))
	if err != nil {
		_ = c.Close()

		if svidCtx.Err() != nil && ctx.Err() == nil {
			return nil, fmt.Errorf(
				"Octelium: the SPIFFE Workload API at %s did not hand out an X509-SVID "+
					"after %s. SPIRE has no registration entry matching this workload: %w",
				addr, svidWaitTimeout, err)
		}

		return nil, err
	}

	return source, nil
}

func getAuthorizer(ctx context.Context, source *workloadapi.X509Source) (tlsconfig.Authorizer, error) {
	svid, err := source.GetX509SVID()
	if err != nil {
		return nil, err
	}

	return authorizerFor(strings.TrimSpace(os.Getenv("OCTELIUM_SPIFFE_TRUST_DOMAIN")), svid.ID)
}

func authorizerFor(configured string, svidID spiffeid.ID) (tlsconfig.Authorizer, error) {
	if configured == "" {
		return tlsconfig.AuthorizeMemberOf(svidID.TrustDomain()), nil
	}

	td, err := spiffeid.TrustDomainFromString(configured)
	if err != nil {
		return nil, err
	}

	if svidID.TrustDomain() != td {
		return nil, fmt.Errorf(
			"Octelium: this Cluster authorizes peers in the trust domain %q but SPIRE "+
				"issued this component an SVID in %q. Every mTLS handshake between the "+
				"Cluster components would be rejected. Install SPIRE with the trust "+
				"domain %q, or unset OCTELIUM_SPIFFE_TRUST_DOMAIN to adopt SPIRE's own",
			td, svidID.TrustDomain(), td)
	}

	return tlsconfig.AuthorizeMemberOf(td), nil
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
