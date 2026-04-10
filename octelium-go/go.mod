module github.com/octelium/octelium/octelium-go

go 1.25.8

replace github.com/octelium/octelium/apis => ../apis

require (
	github.com/grpc-ecosystem/go-grpc-middleware v1.4.0
	github.com/octelium/octelium/apis v0.0.0-00010101000000-000000000000
	github.com/octelium/octelium/pkg v0.0.0-00010101000000-000000000000
	github.com/pkg/errors v0.9.1
	golang.org/x/oauth2 v0.35.0
	google.golang.org/grpc v1.80.0
)

require (
	golang.org/x/net v0.49.0 // indirect
	golang.org/x/sys v0.40.0 // indirect
	golang.org/x/text v0.33.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20260120221211-b8f7ae30c516 // indirect
	google.golang.org/protobuf v1.36.11 // indirect
)

replace github.com/octelium/octelium/pkg => ../pkg
