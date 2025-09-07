module github.com/octelium/octelium/octelium-go

go 1.24.7

replace github.com/octelium/octelium/apis => ../apis

require (
	github.com/grpc-ecosystem/go-grpc-middleware v1.4.0
	github.com/octelium/octelium/apis v0.0.0-00010101000000-000000000000
	github.com/octelium/octelium/pkg v0.0.0-00010101000000-000000000000
	github.com/pkg/errors v0.9.1
	golang.org/x/oauth2 v0.27.0
	google.golang.org/grpc v1.69.2
)

require (
	golang.org/x/net v0.40.0 // indirect
	golang.org/x/sys v0.33.0 // indirect
	golang.org/x/text v0.25.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20241015192408-796eee8c2d53 // indirect
	google.golang.org/protobuf v1.36.1 // indirect
)

replace github.com/octelium/octelium/pkg => ../pkg
