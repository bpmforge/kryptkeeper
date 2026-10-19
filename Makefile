.PHONY: all build build-agent build-agent-all test lint clean release-snapshot fips-image fips-smoke

BINARY      := kryptkeeper
AGENT       := kryptkeeper-agent
VERSION     ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMIT      ?= $(shell git rev-parse --short=12 HEAD 2>/dev/null || echo unknown)
BUILD_DATE  ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
BUILD_FLAGS := -ldflags="-X main.version=$(VERSION) -X main.commit=$(COMMIT) -X main.date=$(BUILD_DATE)"
OUT_DIR     := dist

all: build build-agent

## Hub server binary (host platform)
build:
	go build $(BUILD_FLAGS) -o $(OUT_DIR)/$(BINARY) ./cmd/kryptkeeper/

## Agent binary (host platform)
build-agent:
	go build $(BUILD_FLAGS) -o $(OUT_DIR)/$(AGENT) ./cmd/kryptkeeper-agent/

## Cross-compile agent for all supported platforms
build-agent-all: \
	agent-linux-amd64 \
	agent-linux-arm64 \
	agent-darwin-amd64 \
	agent-darwin-arm64 \
	agent-windows-amd64

agent-linux-amd64:
	GOOS=linux GOARCH=amd64 go build $(BUILD_FLAGS) \
		-o $(OUT_DIR)/$(AGENT)-linux-amd64 ./cmd/kryptkeeper-agent/

agent-linux-arm64:
	GOOS=linux GOARCH=arm64 go build $(BUILD_FLAGS) \
		-o $(OUT_DIR)/$(AGENT)-linux-arm64 ./cmd/kryptkeeper-agent/

agent-darwin-amd64:
	GOOS=darwin GOARCH=amd64 go build $(BUILD_FLAGS) \
		-o $(OUT_DIR)/$(AGENT)-darwin-amd64 ./cmd/kryptkeeper-agent/

agent-darwin-arm64:
	GOOS=darwin GOARCH=arm64 go build $(BUILD_FLAGS) \
		-o $(OUT_DIR)/$(AGENT)-darwin-arm64 ./cmd/kryptkeeper-agent/

## Windows agent (no CGO; pure Go)
agent-windows-amd64:
	GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build $(BUILD_FLAGS) \
		-o $(OUT_DIR)/$(AGENT)-windows-amd64.exe ./cmd/kryptkeeper-agent/

## Windows agent MSI (W18-07). Builds on Linux/macOS with wixl (msitools).
## The service does NOT start until %ProgramData%\Kryptkeeper\agent.env exists
## (see docs/ops/WINDOWS_AGENT.md), so install, configure, then Start-Service.
MSI_VERSION ?= $(shell echo $(VERSION) | sed 's/^v//; s/-.*//' | grep -E '^[0-9]+\.[0-9]+\.[0-9]+$$' || echo 0.0.0)
agent-windows-msi: agent-windows-amd64
	wixl -a x64 -D Version=$(MSI_VERSION) -D AgentExe=$(OUT_DIR)/$(AGENT)-windows-amd64.exe \
		-D EnvExample=packaging/windows/agent.env.example \
		-o $(OUT_DIR)/$(AGENT)-windows-amd64.msi packaging/windows/kryptkeeper-agent.wxs

## Asserts the MSI registers an auto-start service and does not start it
## before the operator has written agent.env (W18-07).
agent-windows-msi-check: agent-windows-msi
	@msiinfo export $(OUT_DIR)/$(AGENT)-windows-amd64.msi ServiceInstall | grep -qP '^AgentSvc\tKryptkeeperAgent\t.*\t16\t2\t1\t' \
		&& echo "msi: KryptkeeperAgent is own-process, auto-start" \
		|| { echo "msi: ServiceInstall row wrong"; exit 1; }
	@! msiinfo export $(OUT_DIR)/$(AGENT)-windows-amd64.msi ServiceControl | grep -qP '\tKryptkeeperAgent\t(1|3|17|19)\t' \
		&& echo "msi: no start-on-install event" || { echo "msi: unexpected start event"; exit 1; }
	@msiinfo export $(OUT_DIR)/$(AGENT)-windows-amd64.msi Registry | grep -q 'EventLog\\Application\\KryptkeeperAgent.*EventMessageFile' \
		&& echo "msi: registers the KryptkeeperAgent event source" || { echo "msi: event source not registered"; exit 1; }

## Local goreleaser proof (no signing, publishing or docker). Needs goreleaser
## v2, syft, and wixl (msitools). GORELEASER_CURRENT_TAG defaults to the latest
## v* tag so the version is not picked up from an unrelated tag. Afterwards
## `bash packaging/homebrew/render-formula.sh dist/checksums.txt <tag>` renders
## the Homebrew formula the release workflow attaches.
release-snapshot:
	GORELEASER_CURRENT_TAG=$${GORELEASER_CURRENT_TAG:-$$(git describe --tags --abbrev=0 --match 'v*')} \
		goreleaser release --snapshot --clean --skip=sign,publish,docker

## Run tests
test:
	go test ./...

## Run tests with race detector
test-race:
	go test -race -timeout 30m ./...

## Lint (requires golangci-lint: go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@latest)
#
# Resolved through GOPATH/bin rather than invoked bare. `go install` puts tools
# there, and that directory is on PATH for interactive shells but routinely not
# for make, CI, or a conductor session — so a bare `golangci-lint` fails with
# "No such file or directory" on a machine where the linter IS installed. That
# is a gate failing on environment rather than on code, which is the fastest way
# to teach people to ignore a gate. If it is genuinely missing, say so and how
# to get it, rather than emitting a shell error.
lint:
	@GOLANGCI="$$(command -v golangci-lint || echo "$$(go env GOPATH)/bin/golangci-lint")"; \
	if [ ! -x "$$GOLANGCI" ]; then \
		echo "make lint: golangci-lint not found (looked on PATH and in $$(go env GOPATH)/bin)"; \
		echo "  install: go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@latest"; \
		exit 1; \
	fi; \
	"$$GOLANGCI" run ./...
	$(MAKE) plugins-check

## Build every delivery plugin into dist/plugins/<name>/ with its manifest
## pinned to the module's sha256, ready to install (W20-22).
.PHONY: plugins
plugins:
	bash scripts/build-plugins.sh

## Delivery plugin SDK and plugins (W20-19). They are separate Go modules,
## so ./... above never reaches them. Their wasip1 files cross the ABI with
## uintptr-to-pointer conversions vet's unsafeptr check cannot judge (the
## offsets belong to the WebAssembly host), hence -unsafeptr=false there only.
.PHONY: plugins-check
plugins-check:
	cd sdk/delivery-go && go vet ./... && go test ./... && GOOS=wasip1 GOARCH=wasm go vet -unsafeptr=false ./...
	cd plugins/example && GOOS=wasip1 GOARCH=wasm go vet -unsafeptr=false ./...
	cd plugins/f5 && GOOS=wasip1 GOARCH=wasm go vet -unsafeptr=false ./...
	cd plugins/citrix && GOOS=wasip1 GOARCH=wasm go vet -unsafeptr=false ./...
	cd plugins/vault && GOOS=wasip1 GOARCH=wasm go vet -unsafeptr=false ./...
	cd plugins/azure-keyvault && GOOS=wasip1 GOARCH=wasm go vet -unsafeptr=false ./...
	cd plugins/gcp-secretmanager && GOOS=wasip1 GOARCH=wasm go vet -unsafeptr=false ./...
	cd plugins/cloudflare && GOOS=wasip1 GOARCH=wasm go vet -unsafeptr=false ./...
	cd plugins/aws && GOOS=wasip1 GOARCH=wasm go vet -unsafeptr=false ./...
	cd plugins/aws-secretsmanager && GOOS=wasip1 GOARCH=wasm go vet -unsafeptr=false ./...
	cd plugins/azure && GOOS=wasip1 GOARCH=wasm go vet -unsafeptr=false ./...
	cd tests/plugins/conformance/testdata/hostile && GOOS=wasip1 GOARCH=wasm go vet -unsafeptr=false ./...

## FIPS 140-3 image variant (W23-32). Not part of default CI; release.yml
## builds and signs it. CONTAINER_ENGINE=podman when docker is absent.
CONTAINER_ENGINE ?= docker
FIPS_IMAGE       ?= kryptkeeper-fips:local
GOFIPS140        ?= v1.0.0

fips-image:
	$(CONTAINER_ENGINE) build -f Dockerfile.fips --build-arg GOFIPS140=$(GOFIPS140) -t $(FIPS_IMAGE) .

## Positive leg: /api/v1/meta reports fips. Negative leg: software root key refused (NFR-011).
fips-smoke: fips-image
	CONTAINER_ENGINE=$(CONTAINER_ENGINE) bash scripts/fips-smoke.sh $(FIPS_IMAGE)

## Remove build outputs
clean:
	rm -rf $(OUT_DIR)/

$(OUT_DIR):
	mkdir -p $(OUT_DIR)

build build-agent build-agent-all: | $(OUT_DIR)

## Gate — the definition of green for a local run
.PHONY: gate hooks
gate:
	go build ./...
	go test ./...
	$(MAKE) lint
	bash scripts/validate-openapi.sh
	bash tests/protocol/run.sh
	cd ui && npm run lint && npm test -- --run

## Install the versioned git hooks (pre-push runs `make gate` for pushes to main)
hooks:
	git config core.hooksPath scripts/git-hooks
	@echo "hooks installed: core.hooksPath=scripts/git-hooks"
