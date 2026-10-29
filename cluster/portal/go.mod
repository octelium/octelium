module github.com/octelium/octelium/cluster/portal

go 1.27.3

require (
	github.com/Microsoft/go-winio v0.6.2 // indirect
	github.com/andybalholm/cascadia v1.3.3 // indirect
	github.com/go-jose/go-jose/v4 v4.1.6 // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/grpc-ecosystem/go-grpc-middleware/v2 v2.3.4 // indirect
	github.com/spiffe/go-spiffe/v2 v2.8.1 // indirect
	go.uber.org/multierr v1.11.0 // indirect
	go.yaml.in/yaml/v2 v2.4.4 // indirect
	go.yaml.in/yaml/v3 v3.0.5 // indirect
	golang.org/x/net v0.58.0 // indirect
	golang.org/x/sys v0.47.0 // indirect
	golang.org/x/text v0.41.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20260819154853-08b0e4226688 // indirect
	google.golang.org/grpc v1.84.0 // indirect
	google.golang.org/protobuf v1.36.12 // indirect
	k8s.io/utils v0.0.0-20260707023825-cf1189d6abe3 // indirect
	sigs.k8s.io/yaml v1.6.0 // indirect
)

replace github.com/octelium/octelium/apis => ../../apis

replace github.com/octelium/octelium/pkg => ../../pkg

replace github.com/octelium/octelium/cluster/common => ../common

replace github.com/octelium/octelium/cluster/rscserver => ../rscserver

replace github.com/octelium/octelium/cluster/apiserver => ../apiserver

replace github.com/octelium/octelium/cluster/octovigil => ../octovigil

require (
	github.com/PuerkitoBio/goquery v1.11.0
	github.com/octelium/octelium/apis v0.0.0-00010101000000-000000000000
	github.com/octelium/octelium/cluster/common v0.0.0-00010101000000-000000000000
	github.com/octelium/octelium/pkg v0.0.0-00010101000000-000000000000
	github.com/patrickmn/go-cache v2.1.0+incompatible
	github.com/pkg/errors v0.9.1
	github.com/stretchr/testify v1.12.1
	go.uber.org/zap v1.28.0
)
