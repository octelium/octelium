module github.com/octelium/octelium/octelium-go

go 1.24.7

replace github.com/octelium/octelium/apis => ../apis

require (
	github.com/grpc-ecosystem/go-grpc-middleware v1.4.0
	github.com/octelium/octelium/apis v0.0.0-00010101000000-000000000000
	github.com/octelium/octelium/pkg v0.0.0-00010101000000-000000000000
	github.com/pkg/errors v0.9.1
	golang.org/x/oauth2 v0.32.0
	google.golang.org/grpc v1.76.0
)

require (
	golang.org/x/net v0.42.0 // indirect
	golang.org/x/sys v0.34.0 // indirect
	golang.org/x/text v0.27.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20250804133106-a7a43d27e69b // indirect
	google.golang.org/protobuf v1.36.10 // indirect
)

replace github.com/octelium/octelium/pkg => ../pkg
