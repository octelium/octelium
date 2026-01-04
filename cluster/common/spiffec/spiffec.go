package spiffec

import (
	"context"
	"crypto/tls"
	"errors"
	"os"

	"github.com/octelium/octelium/pkg/utils/ldflags"
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
		defer source.Close()
		zap.L().Debug("SPIFFE is enabled. Setting client cred")
		tlsConfig := tlsconfig.MTLSClientConfig(source, source, tlsconfig.AuthorizeAny())
		tlsConfig.GetConfigForClient = func(chi *tls.ClientHelloInfo) (*tls.Config, error) {
			zap.L().Debug("SNI RECEIVED", zap.String("sni", chi.ServerName))
			return nil, nil
		}
		tlsConfig.ServerName = ""
		if ldflags.IsDev() {
			tlsConfig.InsecureSkipVerify = true
		}

		return grpc.WithTransportCredentials(credentials.NewTLS(tlsConfig)), nil
	} else if errors.Is(err, ErrNotFound) {
		return grpc.WithTransportCredentials(insecure.NewCredentials()), nil
	} else {
		return nil, err
	}
}

type GetGRPCServerCredOpts struct {
}

func GetGRPCServerCred(ctx context.Context, o *GetGRPCServerCredOpts) (grpc.ServerOption, error) {
	if source, err := GetSPIFFESource(ctx); err == nil {
		defer source.Close()
		zap.L().Debug("SPIFFE is enabled. Setting server cred")
		tlsConfig := tlsconfig.MTLSClientConfig(source, source, tlsconfig.AuthorizeAny())
		tlsConfig.GetConfigForClient = func(chi *tls.ClientHelloInfo) (*tls.Config, error) {
			zap.L().Debug("SNI RECEIVED", zap.String("sni", chi.ServerName))
			return nil, nil
		}
		if ldflags.IsDev() {
			tlsConfig.InsecureSkipVerify = true
		}
		return grpc.Creds(credentials.NewTLS(tlsConfig)), nil
	} else if errors.Is(err, ErrNotFound) {
		return grpc.Creds(insecure.NewCredentials()), nil
	} else {
		return nil, err
	}
}
