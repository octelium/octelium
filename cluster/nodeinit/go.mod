module github.com/octelium/octelium/cluster/nodeinit

go 1.24.7

require (
	github.com/octelium/octelium/cluster/common v0.0.0-00010101000000-000000000000
	go.uber.org/zap v1.27.0
)

require (
	github.com/octelium/octelium/pkg v0.0.0-00010101000000-000000000000 // indirect
	github.com/pkg/errors v0.9.1 // indirect
	go.uber.org/multierr v1.11.0 // indirect
)

replace github.com/octelium/octelium/apis => ../../apis

replace github.com/octelium/octelium/pkg => ../../pkg

replace github.com/octelium/octelium/cluster/common => ../common

replace github.com/octelium/octelium/cluster/rscserver => ../rscserver

replace github.com/octelium/octelium/cluster/apiserver => ../apiserver
