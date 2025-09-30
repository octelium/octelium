
export GO111MODULE=on
export PATH := $(PATH):$(shell go env GOPATH)/bin

.PHONY: gen-api build-cli build-octelium clean fmt lint test unit vendor

REPOSITORY := github.com/octelium/octelium
REGISTRY ?= ghcr.io
IMAGE_PREFIX := octelium

COMMIT := $(shell git rev-parse HEAD)
TAG := $(shell git describe --tags --exact-match --match "v*.*.*" 2>/dev/null)
BRANCH := $(shell git rev-parse --abbrev-ref HEAD)

LDFLAGS_PATH := $(REPOSITORY)/pkg/utils/ldflags

LDF_IMAGE_REGISTRY := $(LDFLAGS_PATH).ImageRegistry=$(REGISTRY)
LDF_IMAGE_REGISTRY_PREFIX := $(LDFLAGS_PATH).ImageRegistryPrefix=$(IMAGE_PREFIX)
LDF_COMMIT := $(LDFLAGS_PATH).GitCommit=$(COMMIT)
LDF_TAG := $(LDFLAGS_PATH).GitTag=$(TAG)
LDF_SEMVER := $(LDFLAGS_PATH).SemVer=$(TAG)
LDF_BRANCH := $(LDFLAGS_PATH).GitBranch=$(BRANCH)

GENERATED_API_DOCS_DIR := ./tmp/docs/apis
GENERATED_API_DOCS_TEMP := ./unsorted/protoc/template.tmpl
GO_BIN_DIR := $${HOME}/go/bin

LDFLAGS := -ldflags '-X $(LDF_COMMIT) -X $(LDF_TAG) -X $(LDF_BRANCH) -X $(LDF_SEMVER)\
-X $(LDF_IMAGE_REGISTRY) -X $(LDF_IMAGE_REGISTRY_PREFIX)'

PROTO_GO_OPT := --go_opt=paths=source_relative
PROTO_GO_OPT_GRPC := $(PROTO_GO_OPT) --go-grpc_opt=paths=source_relative
PROTO_IN_PREFIX := apis/protobuf
PROTO_IN_MAIN := $(PROTO_IN_PREFIX)/main
PROTO_IN_CLUSTER := $(PROTO_IN_PREFIX)/cluster
PROTO_IN_CLIENT := $(PROTO_IN_PREFIX)/client
PROTO_IN_RSC := $(PROTO_IN_PREFIX)/rsc

PROTOC_DOC_ARG := --doc_out=./tmp/docs --doc_opt=json

CMD_TIDY := go mod tidy

protoc-install:
	go install google.golang.org/protobuf/cmd/protoc-gen-go@v1.36.1
	go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@v1.5.1
	go install github.com/pseudomuto/protoc-gen-doc/cmd/protoc-gen-doc@latest
	mkdir -p $(GENERATED_API_DOCS_DIR)

build-nocturne:
	CGO_ENABLED=0 GOOS=linux go build $(LDFLAGS) -o bin/octelium-nocturne github.com/octelium/octelium/cluster/nocturne
build-apiserver:
	CGO_ENABLED=0 GOOS=linux go build $(LDFLAGS) -o bin/octelium-apiserver github.com/octelium/octelium/cluster/apiserver
build-genesis:
	CGO_ENABLED=0 GOOS=linux go build $(LDFLAGS) -o bin/octelium-genesis github.com/octelium/octelium/cluster/genesis
build-nodeinit:
	CGO_ENABLED=0 GOOS=linux go build $(LDFLAGS) -o bin/octelium-nodeinit github.com/octelium/octelium/cluster/nodeinit
build-gwagent:
	CGO_ENABLED=0 GOOS=linux go build $(LDFLAGS) -o bin/octelium-gwagent github.com/octelium/octelium/cluster/gwagent
build-dnsserver:
	CGO_ENABLED=0 GOOS=linux go build $(LDFLAGS) -o bin/octelium-dnsserver github.com/octelium/octelium/cluster/dnsserver
build-authserver:
	CGO_ENABLED=0 GOOS=linux go build $(LDFLAGS) -o bin/octelium-authserver github.com/octelium/octelium/cluster/authserver
build-ingress:
	CGO_ENABLED=0 GOOS=linux go build $(LDFLAGS) -o bin/octelium-ingress github.com/octelium/octelium/cluster/ingress
build-rscserver:
	CGO_ENABLED=0 GOOS=linux go build $(LDFLAGS) -o bin/octelium-rscserver github.com/octelium/octelium/cluster/rscserver
build-cloudman:
	CGO_ENABLED=0 GOOS=linux go build $(LDFLAGS) -o bin/octelium-cloudman github.com/octelium/octelium/cluster/cloudman
build-vigil:
	CGO_ENABLED=0 GOOS=linux go build $(LDFLAGS) -o bin/octelium-vigil github.com/octelium/octelium/cluster/vigil
build-octovigil:
	CGO_ENABLED=0 GOOS=linux go build $(LDFLAGS) -o bin/octelium-octovigil github.com/octelium/octelium/cluster/octovigil
build-portal:
	CGO_ENABLED=0 GOOS=linux go build $(LDFLAGS) -o bin/octelium-portal github.com/octelium/octelium/cluster/portal
build-e2e:
	CGO_ENABLED=0 GOOS=linux go build $(LDFLAGS) -o bin/octelium-e2e github.com/octelium/octelium/cluster/e2e

build-cli-octelium:
	CGO_ENABLED=0 go build $(LDFLAGS) -o bin/ github.com/octelium/octelium/client/octelium

build-cli-octeliumctl:
	CGO_ENABLED=0 go build $(LDFLAGS) -o bin/ github.com/octelium/octelium/client/octeliumctl

build-cli-octops:
	CGO_ENABLED=0 go build $(LDFLAGS) -o bin/ github.com/octelium/octelium/client/octops

build-cli: build-cli-octelium build-cli-octeliumctl build-cli-octops

install-cli: build-cli
	mkdir -p ~/go/bin
	cp bin/octelium ~/go/bin/octelium
	cp bin/octeliumctl ~/go/bin/octeliumctl
	cp bin/octops ~/go/bin/octops

gen-go-main:
	mkdir -p apis/main/metav1 apis/main/corev1 apis/main/clusterv1 apis/main/authv1 apis/main/userv1 apis/main/quicv0
	protoc -I . -I $(PROTO_IN_MAIN)/metav1 metav1.proto \
		--go_out=apis/main/metav1 --go-grpc_out=apis/main/metav1 $(PROTO_GO_OPT)
	protoc -I . -I $(PROTO_IN_MAIN)/corev1 corev1.proto \
		--go_out=apis/main/corev1 --go-grpc_out=apis/main/corev1 $(PROTO_GO_OPT_GRPC)
	protoc -I . -I $(PROTO_IN_MAIN)/userv1 userv1.proto \
		--go_out=apis/main/userv1 --go-grpc_out=apis/main/userv1 $(PROTO_GO_OPT_GRPC)
	protoc -I . -I $(PROTO_IN_MAIN)/authv1 authv1.proto \
		--go_out=apis/main/authv1 --go-grpc_out=apis/main/authv1 $(PROTO_GO_OPT_GRPC)
	protoc -I . -I $(PROTO_IN_MAIN)/quicv0 quicv0.proto \
		--go_out=apis/main/quicv0 --go-grpc_out=apis/main/quicv0 $(PROTO_GO_OPT)

gen-go-cluster:
	mkdir -p apis/cluster/cclusterv1 apis/cluster/coctovigilv1 apis/cluster/cvigilv1
	mkdir -p apis/cluster/cbootstrapv1
	mkdir -p apis/cluster/csecretmanv1
	protoc -I . -I $(PROTO_IN_CLUSTER)/clusterv1 cclusterv1.proto \
		--go_out=apis/cluster/cclusterv1 --go-grpc_out=apis/cluster/cclusterv1 $(PROTO_GO_OPT)
	protoc -I . -I $(PROTO_IN_CLUSTER)/octovigilv1 coctovigilv1.proto \
		--go_out=apis/cluster/coctovigilv1 --go-grpc_out=apis/cluster/coctovigilv1 $(PROTO_GO_OPT_GRPC)
	protoc -I . -I $(PROTO_IN_CLUSTER)/bootstrapv1 cbootstrapv1.proto \
		--go_out=apis/cluster/cbootstrapv1 --go-grpc_out=apis/cluster/cbootstrapv1 $(PROTO_GO_OPT)
	protoc -I . -I $(PROTO_IN_CLUSTER)/secretmanv1 csecretmanv1.proto \
		--go_out=apis/cluster/csecretmanv1 --go-grpc_out=apis/cluster/csecretmanv1 $(PROTO_GO_OPT_GRPC)
	protoc -I . -I $(PROTO_IN_CLUSTER)/vigilv1 cvigilv1.proto \
		--go_out=apis/cluster/cvigilv1 --go-grpc_out=apis/cluster/cvigilv1 $(PROTO_GO_OPT_GRPC)

gen-go-rsc:
	mkdir -p apis/rsc/rmetav1 apis/rsc/rcorev1 apis/rsc/rcachev1 apis/rsc/rratelimitv1
	protoc -I . -I $(PROTO_IN_RSC)/metav1 rmetav1.proto \
		--go_out=apis/rsc/rmetav1 --go-grpc_out=apis/rsc/rmetav1 $(PROTO_GO_OPT)
	protoc -I . -I $(PROTO_IN_RSC)/corev1 rcorev1.proto \
		--go_out=apis/rsc/rcorev1 --go-grpc_out=apis/rsc/rcorev1 $(PROTO_GO_OPT_GRPC)
	protoc -I . -I $(PROTO_IN_RSC)/cachev1 rcachev1.proto \
		--go_out=apis/rsc/rcachev1 --go-grpc_out=apis/rsc/rcachev1 $(PROTO_GO_OPT_GRPC)
	protoc -I . -I $(PROTO_IN_RSC)/ratelimitv1 rratelimitv1.proto \
		--go_out=apis/rsc/rratelimitv1 --go-grpc_out=apis/rsc/rratelimitv1 $(PROTO_GO_OPT_GRPC)


gen-go-client:
	mkdir -p apis/client/cliconfigv1
	protoc -I . -I $(PROTO_IN_CLIENT)/configv1 configv1.proto \
		--go_out=apis/client/cliconfigv1 --go-grpc_out=apis/client/cliconfigv1 $(PROTO_GO_OPT)

gen-api: gen-go-main gen-go-cluster gen-go-client gen-go-rsc
	rm -rf ./apis/protobuf
	go run unsorted/licenser/main.go

gen-api-doc-main:
	protoc -I . -I $(PROTO_IN_MAIN)/metav1 metav1.proto \
		$(PROTOC_DOC_ARG),./tmp/docs/metav1.json
	protoc -I . -I $(PROTO_IN_MAIN)/corev1 corev1.proto \
		$(PROTOC_DOC_ARG),./tmp/docs/corev1.json
	protoc -I . -I $(PROTO_IN_MAIN)/userv1 userv1.proto \
		$(PROTOC_DOC_ARG),./tmp/docs/userv1.json
	protoc -I . -I $(PROTO_IN_MAIN)/authv1 authv1.proto \
		$(PROTOC_DOC_ARG),./tmp/docs/authv1.json
	rm -rf ./apis/protobuf

tidy:
	cd apis; $(CMD_TIDY)
	cd pkg; $(CMD_TIDY)
	cd octelium-go; $(CMD_TIDY)
	cd client/common; $(CMD_TIDY)
	cd client/octelium; $(CMD_TIDY)
	cd client/octeliumctl; $(CMD_TIDY)
	cd client/octops; $(CMD_TIDY)
	cd cluster/common; $(CMD_TIDY)
	cd cluster/rscserver; $(CMD_TIDY)
	cd cluster/apiserver; $(CMD_TIDY)
	cd cluster/dnsserver; $(CMD_TIDY)
	cd cluster/genesis; $(CMD_TIDY)
	cd cluster/nocturne; $(CMD_TIDY)
	cd cluster/ingress; $(CMD_TIDY)
	cd cluster/authserver; $(CMD_TIDY)
	cd cluster/portal; $(CMD_TIDY)
	cd cluster/octovigil; $(CMD_TIDY)
	cd cluster/vigil; $(CMD_TIDY)
	cd cluster/nodeinit; $(CMD_TIDY)
	cd cluster/gwagent; $(CMD_TIDY)
	cd cluster/e2e; $(CMD_TIDY)
set-license:
	go run unsorted/licenser/main.go