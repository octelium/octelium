package spiffec

import (
	"context"
	"errors"
	"os"

	"github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
)

func GetSPIFFEEndpointSocket() string {
	if val := os.Getenv("SPIFFE_ENDPOINT_SOCKET"); val != "" {
		return val
	}

	csiPath := "/run/spire/sockets/agent.sock"
	if _, err := os.Stat(csiPath); err == nil {
		return "unix://" + csiPath
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

func GetGRPCClientOpts(ctx context.Context, opts []grpc.DialOption) ([]grpc.DialOption, error) {

	var ret = opts
	if source, err := GetSPIFFESource(ctx); err == nil {
		defer source.Close()
		tlsConfig := tlsconfig.MTLSClientConfig(source, source, tlsconfig.AuthorizeAny())
		ret = append(ret, grpc.WithTransportCredentials(credentials.NewTLS(tlsConfig)))
	} else if errors.Is(err, ErrNotFound) {
		ret = append(ret, grpc.WithTransportCredentials(insecure.NewCredentials()))
	} else {
		return nil, err
	}

	return ret, nil
}

func GetGRPCServerCred(ctx context.Context) (grpc.ServerOption, error) {
	if source, err := GetSPIFFESource(ctx); err == nil {
		defer source.Close()
		tlsConfig := tlsconfig.MTLSClientConfig(source, source, tlsconfig.AuthorizeAny())
		return grpc.Creds(credentials.NewTLS(tlsConfig)), nil
	} else if errors.Is(err, ErrNotFound) {
		return grpc.Creds(insecure.NewCredentials()), nil
	} else {
		return nil, err
	}
}
