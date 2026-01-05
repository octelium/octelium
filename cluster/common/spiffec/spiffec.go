package spiffec

import (
	"context"
	"errors"
	"os"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
)

func GetSPIFFEEndpointSocket() string {
	if val := os.Getenv("SPIFFE_ENDPOINT_SOCKET"); val != "" {
		return val
	}

	csiPaths := []string{
		"/run/spire/sockets/spire-agent.sock",
		"/run/spire/sockets/agent.sock",
	}

	for _, csiPath := range csiPaths {
		if _, err := os.Stat(csiPath); err == nil {
			return "unix://" + csiPath
		}
	}

	return ""
}

var ErrNotFound = errors.New("Octelium: SPIFFE socket not Found")

func GetWorkloadC(ctx context.Context) (*workloadapi.Client, error) {
	socketAddr := GetSPIFFEEndpointSocket()
	if socketAddr == "" {
		return nil, ErrNotFound
	}

	return workloadapi.New(ctx, workloadapi.WithAddr(socketAddr))
}

func GetSPIFFESource(ctx context.Context) (r *workloadapi.X509Source, err error) {
	c, err := GetWorkloadC(ctx)
	if err != nil {
		return nil, err
	}

	return workloadapi.NewX509Source(ctx, workloadapi.WithClient(c))
}

type GetGRPCClientCredOpts struct {
}

func GetGRPCClientCred(ctx context.Context, o *GetGRPCClientCredOpts) (grpc.DialOption, error) {

	if source, err := GetSPIFFESource(ctx); err == nil {
		svid, err := source.GetX509SVID()
		if err != nil {
			return nil, err
		}

		zap.L().Debug("SPIFFE is enabled. Setting client cred", zap.Any("crt", svid.Certificates[0]))
		tlsConfig := tlsconfig.MTLSClientConfig(source, source, GetAuthorizer())

		return grpc.WithTransportCredentials(credentials.NewTLS(tlsConfig)), nil
	} else if errors.Is(err, ErrNotFound) {
		return grpc.WithTransportCredentials(insecure.NewCredentials()), nil
	} else {
		return nil, err
	}
}

type GetGRPCServerCredOpts struct {
}

func GetAuthorizer() tlsconfig.Authorizer {
	if val := os.Getenv("OCTELIUM_SPIFFE_TRUST_DOMAIN"); val != "" {
		if authorizer, err := spiffeid.TrustDomainFromString(val); err == nil {
			return tlsconfig.AuthorizeMemberOf(authorizer)
		}
	}

	return tlsconfig.AuthorizeAny()
}

func GetGRPCServerCred(ctx context.Context, o *GetGRPCServerCredOpts) (grpc.ServerOption, error) {
	if source, err := GetSPIFFESource(ctx); err == nil {
		svid, err := source.GetX509SVID()
		if err != nil {
			return nil, err
		}

		zap.L().Debug("SPIFFE is enabled. Setting server cred", zap.Any("crt", svid.Certificates[0]))
		tlsConfig := tlsconfig.MTLSServerConfig(source, source, GetAuthorizer())

		return grpc.Creds(credentials.NewTLS(tlsConfig)), nil
	} else if errors.Is(err, ErrNotFound) {
		return grpc.Creds(insecure.NewCredentials()), nil
	} else {
		return nil, err
	}
}
