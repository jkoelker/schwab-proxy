# This Makefile lets you run the devkit image and all related commands in the
# exact same way they are executed in CI. The only requirement is that you have
# Docker installed and running on your machine.

SHELL := /bin/bash
INTERACTIVE := $(shell [ -t 0 ] && echo 1)

root_mkfile_path := $(abspath $(lastword $(MAKEFILE_LIST)))
REPO_ROOT := $(realpath $(dir $(root_mkfile_path)))

DEVKIT_IMG ?= ghcr.io/jkoelker/schwab-proxy:latest-devkit
DEVKIT_PHONY_FILE ?= $(REPO_ROOT)/.devkit-$(subst :,.,$(subst /,-,$(DEVKIT_IMG)))

CONTAINER_TOOL ?= podman
ifeq ($(shell command -v $(CONTAINER_TOOL)),)
	CONTAINER_TOOL := docker
endif


# The cache directories are mounted into the devkit image as volumes. The
# They are by default located in the repository root, but can be overridden
# by setting the environment variables.
CACHE_ROOT ?= $(REPO_ROOT)/.cache
GOCACHE ?= $(CACHE_ROOT)/go/go-build
GOMODCACHE ?= $(CACHE_ROOT)/go/pkg/mod
GOLANGCI_LINT_CACHE ?= $(CACHE_ROOT)/golangci-lint

# Additional arguments to pass to the devkit image. This can be used to set
# environment variables, mount additional volumes, etc.
DEVKIT_ADDITIONAL_ARGS ?=

DEVKIT_ARGS ?= \
	--rm \
	$(if $(INTERACTIVE),--tty) \
	--interactive \
	--env=DEVKIT=true \
	--env CI \
	--env GOCACHE=/code/.cache/go/go-build \
	--env GOMODCACHE=/code/.cache/go/pkg/mod \
	--env GOLANGCI_LINT_CACHE=/code/.cache/golangci-lint \
	--volume $(REPO_ROOT):/code:Z \
	--volume $(GOCACHE):/code/.cache/go/go-build:Z \
	--volume $(GOMODCACHE):/code/.cache/go/pkg/mod:Z \
	--volume $(GOLANGCI_LINT_CACHE):/code/.cache/golangci-lint:Z \
	$(DEVKIT_ADDITIONAL_ARGS) \
	--workdir /code \

ALL_GO_FILES := $(shell \
	find $(REPO_ROOT) \
	-path $(CACHE_ROOT) -prune \
	-o -path $(REPO_ROOT)/.schwab_data -prune \
	-o -type f -name '*'.go\
)

# Proxy the state of the devkit image to the phony file. If the image does not
# exist, then the phony file will not exist. This allows setting the phony file
# as a dependency for other targets that require the devkit image to be built.
# The assignment of the `junk` variable is to decouple the proxy from the
# targets, since variables are evaluated before targets.
ifneq ($(shell command -v $(CONTAINER_TOOL)),)
	ifeq ($(shell $(CONTAINER_TOOL) image ls --quiet "$(DEVKIT_IMG)"),)
		junk := $(shell rm -f "$(DEVKIT_PHONY_FILE)")
	endif
endif

# Rebuild the devkit image on any changes to Containerfile.devkit.
$(DEVKIT_PHONY_FILE): Containerfile.devkit
	@echo "Building $(DEVKIT_IMG)..."
	$(CONTAINER_TOOL) build --tag "$(DEVKIT_IMG)" --file "$<" .
	@touch "$@"

# The devkit target is a phony target that will run the devkit image. The
# devkit image is built if it does not exist. the variable WHAT is passed to
# the image as the command to run. Git will be preconfigured to use the
# repository root (mounted in the container as /code) as a safe directory.
WHAT ?= /bin/bash
.PHONY: devkit
devkit: $(DEVKIT_PHONY_FILE)
devkit: cache
	@$(CONTAINER_TOOL) run $(DEVKIT_ARGS) "$(DEVKIT_IMG)" $(WHAT)

# dev and shell are just aliases for devkit.
.PHONY: dev
dev: devkit

.PHONY: shell
shell: devkit

# The cache targets are used to create the cache directories used by the devkit
# image. These targets are not phony, so they will only be run if the cache
# directories do not exist.
$(GOCACHE):
	mkdir -p "$@"

$(GOMODCACHE):
	mkdir -p "$@"

$(GOLANGCI_LINT_CACHE):
	mkdir -p "$@"

.PHONY: cache
cache: $(GOCACHE)
cache: $(GOMODCACHE)
cache: $(GOLANGCI_LINT_CACHE)

.PHONY: clean
clean: WHAT=make clean-cache coverage
clean: devkit

.PHONY: clean-cache
clean-cache:
	@echo "Clean Cache"
	rm -rf .cache

.PHONY: clean-coverage
clean-coverage:
	@echo "Clean Coverage"
	rm -f coverate.out coverage.xml coverage.html

# NOTE(jkoelker) `-race` detection requires CGO on all platforms except
# arm64/mac
coverage.out: $(ALL_GO_FILES)
	@echo "Generate Coverage"
	CGO_ENABLED=1 go tool gotestsum \
		--format=testname \
		-- \
		-covermode=atomic \
		-coverprofile=$@ \
		-race \
		-short \
		-v \
		./...

coverage.html: coverage.out
	@echo "Generate Coverage HTML"
	go tool cover -html=$< -o $@

.PHONY: mod-download
mod-download: cache
	go mod download -x

.PHONY: deps
deps: WHAT=make mod-download
deps: devkit

.PHONY: test
test: WHAT=make coverage.html
test: devkit

go.sum: go.mod
	@echo "Update Go Modules"
	go mod tidy -v

.PHONY: tidy
tidy: WHAT=make go.mod
tidy:devkit

# Check that the go.mod and go.sum files are up to date. if they are not, then
# echo instructions on how to update them.
.PHONY: check-tidy
check-tidy: go.sum
	@echo "Check Go Modules"
	@if ! git diff --quiet go.mod go.sum; then \
		echo -e "\n\n*****************************************"; \
		echo "'go.mod' and/or 'go.sum' are out of date."; \
		echo "Please run 'make tidy' to update them."; \
		echo -e "*****************************************\n\n"; \
		exit 1; \
	fi

# tidy-ci differs from tidy in that it will fail if the go.mod or go.sum files
# are out of date.
.PHONY: tidy-ci
tidy-ci: WHAT=make go.sum check-tidy
tidy-ci: devkit

.PHONY: golangci-lint
golangci-lint:
	golangci-lint --version
	golangci-lint run --verbose --fix

dockerfile-lint:
	hadolint --version
	hadolint Containerfile*

.PHONY: lint
lint: WHAT=make golangci-lint dockerfile-lint
lint: devkit

# Docker targets
.PHONY: docker-build
docker-build:
	@echo "Building Docker image..."
	$(CONTAINER_TOOL) build -t schwab-proxy:latest .


schwab_data:
	mkdir --parents --mode 777 .schwab_data

.PHONY: docker-run
docker-run: schwab_data
docker-run: docker-build
	@echo "Running Docker container..."
	$(CONTAINER_TOOL) run --rm -p 8080:8080 \
		--name schwab-proxy \
		--read-only \
		--tmpfs /tmp \
		--security-opt no-new-privileges:true \
		-v ./.schwab_data:/data:Z \
		-e STORAGE_SEED="dev-storage-seed-replace-in-production" \
		-e JWT_SEED="dev-jwt-seed-replace-in-production" \
		-e SCHWAB_CLIENT_ID \
		-e SCHWAB_CLIENT_SECRET \
		-e SCHWAB_REDIRECT_URI \
		-e DATA_PATH="/data" \
		-e DEBUG_LOGGING=true \
		schwab-proxy:latest

.PHONY: docker-clean
docker-clean:
	@echo "Cleaning Docker artifacts..."
	$(CONTAINER_TOOL) system prune -f
	$(CONTAINER_TOOL) image rm -f schwab-proxy:latest 2>/dev/null || true
