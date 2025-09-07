module github.com/octelium/octelium/pkg

go 1.24.7

require (
	github.com/ghodss/yaml v1.0.0
	github.com/octelium/octelium/apis v0.0.0-00010101000000-000000000000
	github.com/stretchr/testify v1.10.0
	google.golang.org/grpc v1.69.2
	google.golang.org/protobuf v1.36.1
)

require github.com/pkg/errors v0.9.1

require (
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/kr/text v0.2.0 // indirect
	github.com/niemeyer/pretty v0.0.0-20200227124842-a10e7caefd8e // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	golang.org/x/net v0.40.0 // indirect
	golang.org/x/sys v0.33.0 // indirect
	golang.org/x/text v0.25.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20241015192408-796eee8c2d53 // indirect
	gopkg.in/check.v1 v1.0.0-20200227125254-8fa46927fb4f // indirect
	gopkg.in/yaml.v2 v2.4.0 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)

replace github.com/octelium/octelium/cluster/apis => ../cluster/apis

replace github.com/octelium/octelium/apis => ../apis

replace github.com/octelium/octelium/cluster/common => ../cluster/common

replace github.com/octelium/octelium/cluster/rscserver => ../cluster/rscserver

replace github.com/octelium/octelium/cluster/apiserver => ../cluster/apiserver
