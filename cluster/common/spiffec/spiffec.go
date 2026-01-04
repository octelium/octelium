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
		// defer source.Close()

		svid, err := source.GetX509SVID()
		if err != nil {
			return nil, err
		}

		zap.L().Debug("SPIFFE is enabled. Setting client cred", zap.Any("crt", svid.Certificates[0]))
		tlsConfig := tlsconfig.MTLSClientConfig(source, source, tlsconfig.AuthorizeAny())

		/*
			tlsConfig.GetConfigForClient = func(chi *tls.ClientHelloInfo) (*tls.Config, error) {
				zap.L().Debug("SNI RECEIVED", zap.String("sni", chi.ServerName))
				return nil, nil
			}
		*/
		tlsConfig.ServerName = ""
		if ldflags.IsDev() {
			// tlsConfig.InsecureSkipVerify = true
			/*
				tlsConfig.VerifyPeerCertificate = func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {

					zap.L().Debug("Starting VerifyPeerCertificate",
						zap.Any("rawCerts", rawCerts), zap.Any("chains", verifiedChains))
					var certs []*x509.Certificate
					for _, rawCert := range rawCerts {
						cert, err := x509.ParseCertificate(rawCert)
						if err != nil {
							return err
						}
						certs = append(certs, cert)
					}

					for _, crt := range certs {
						zap.L().Debug("Got peer crt",
							zap.Any("crt", crt), zap.Any("subject", crt.Subject), zap.Any("issuer", crt.Issuer))
					}
					return nil
				}
			*/

			tlsConfig.GetCertificate = func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
				svid, err := source.GetX509SVID()
				if err != nil {
					return nil, err
				}
				zap.L().Debug("Got svid cert", zap.Any("crt", svid.Certificates[0]))
				return &tls.Certificate{
					Certificate: [][]byte{svid.Certificates[0].Raw},
					PrivateKey:  svid.PrivateKey,
					Leaf:        svid.Certificates[0],
				}, nil
			}
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
		// defer source.Close()
		svid, err := source.GetX509SVID()
		if err != nil {
			return nil, err
		}

		zap.L().Debug("SPIFFE is enabled. Setting server cred", zap.Any("crt", svid.Certificates[0]))
		tlsConfig := tlsconfig.MTLSClientConfig(source, source, tlsconfig.AuthorizeAny())

		/*
			tlsConfig.GetConfigForClient = func(chi *tls.ClientHelloInfo) (*tls.Config, error) {
				zap.L().Debug("SNI RECEIVED", zap.String("sni", chi.ServerName))
				return nil, nil
			}
		*/
		if ldflags.IsDev() {
			// tlsConfig.InsecureSkipVerify = true
			tlsConfig.GetCertificate = func(chi *tls.ClientHelloInfo) (*tls.Certificate, error) {
				zap.L().Debug("new getCertificate", zap.Any("chi", chi))
				svid, err := source.GetX509SVID()
				if err != nil {
					return nil, err
				}

				return &tls.Certificate{
					Certificate: [][]byte{svid.Certificates[0].Raw},
					PrivateKey:  svid.PrivateKey,
					Leaf:        svid.Certificates[0],
				}, nil
			}

			/*
				tlsConfig.VerifyPeerCertificate = func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
					var certs []*x509.Certificate
					zap.L().Debug("Starting VerifyPeerCertificate",
						zap.Any("rawCerts", rawCerts), zap.Any("chains", verifiedChains))
					for _, rawCert := range rawCerts {
						cert, err := x509.ParseCertificate(rawCert)
						if err != nil {
							return err
						}
						certs = append(certs, cert)
					}

					for _, crt := range certs {
						zap.L().Debug("Got crt",
							zap.Any("crt", crt), zap.Any("subject", crt.Subject), zap.Any("issuer", crt.Issuer))
					}
					return nil
				}
			*/
		}
		return grpc.Creds(credentials.NewTLS(tlsConfig)), nil
	} else if errors.Is(err, ErrNotFound) {
		return grpc.Creds(insecure.NewCredentials()), nil
	} else {
		return nil, err
	}
}

/*
type tracer struct {
}

func (s *tracer) GetCertificate(i tlsconfig.GetCertificateInfo) interface{} {
	return nil
}
func (s *tracer) GotCertificate(i tlsconfig.GotCertificateInfo, _ interface{}) {

}
*/
