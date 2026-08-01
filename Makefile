APP := passfs
GO ?= go
GO_ENV := env -u GOROOT GOWORK=off
SYSTEM := $(shell uname -s)
BIN_DIR := bin
BINARY := $(BIN_DIR)/$(APP)
PACKAGE := ./cmd/passfs
GO_BIN_DIR := $(shell $(GO_ENV) $(GO) env GOBIN)
ifeq ($(GO_BIN_DIR),)
GO_BIN_DIR := $(shell $(GO_ENV) $(GO) env GOPATH)/bin
endif
MACOS_APP := $(BIN_DIR)/PassFS.app
MACOS_INSTALL_APP ?= $(HOME)/Applications/PassFS.app
MACOS_PROVISIONING_PROFILE ?= $(HOME)/Downloads/passfs_mounter_Developer_ID.provisionprofile
MACOS_FSKIT_PROVISIONING_PROFILE ?= $(HOME)/Downloads/passfs_filesystem_Developer_ID.provisionprofile
MACOS_APPLICATION_SIGN_IDENTITY ?= auto
MACOS_INSTALLER_SIGN_IDENTITY ?= auto
MACOS_NOTARY_KEY ?= $(firstword $(wildcard $(HOME)/Downloads/AuthKey_*.p8))
MACOS_NOTARY_KEY_ID ?= $(patsubst AuthKey_%.p8,%,$(notdir $(MACOS_NOTARY_KEY)))
MACOS_NOTARY_ISSUER_ID ?= $(shell security find-generic-password -a "$(USER)" -s "com.menxit.passfs.notary.issuer-id" -w 2>/dev/null)
MACOS_ARCHES ?= $(shell uname -m)
RELEASE_VERSION ?= 0.1.0
RELEASE_BUILD_NUMBER ?= 1
RELEASE_ROOT ?= release
RELEASE_DIR := $(RELEASE_ROOT)/v$(RELEASE_VERSION)
MACOS_PACKAGE := $(RELEASE_DIR)/PassFS-macos-universal.pkg
DOCKER ?= docker
SERVER_TEST_IMAGE ?= passfs-server-test

.PHONY: all build install install-unsigned macos-app macos-package macos-release linux-release release-checksums release-signature pages docker-server docker-server-shell test test-scripts test-race vet cross-build-linux fskit-check check clean

all: build

build:
	mkdir -p $(BIN_DIR)
	$(GO_ENV) $(GO) build -o $(BINARY) $(PACKAGE)

ifeq ($(SYSTEM),Darwin)
install: macos-app
	./scripts/install-macos-app.sh \
		$(MACOS_APP) \
		"$(MACOS_INSTALL_APP)" \
		"$(GO_BIN_DIR)/$(APP)"
else
install:
	$(GO_ENV) $(GO) install $(PACKAGE)
endif

install-unsigned:
	$(GO_ENV) $(GO) install $(PACKAGE)

macos-app:
	PASSFS_VERSION="$(RELEASE_VERSION)" \
	PASSFS_BUILD_NUMBER="$(RELEASE_BUILD_NUMBER)" \
	PASSFS_MACOS_ARCHES="$(MACOS_ARCHES)" \
	./scripts/build-macos-app.sh \
		"$(MACOS_PROVISIONING_PROFILE)" \
		"$(MACOS_APPLICATION_SIGN_IDENTITY)" \
		$(MACOS_APP) \
		"$(MACOS_FSKIT_PROVISIONING_PROFILE)"

macos-package macos-release: MACOS_ARCHES = amd64 arm64

macos-package: macos-release

macos-release: macos-app
	./scripts/notarize-macos.sh \
		$(MACOS_APP) \
		"$(MACOS_NOTARY_KEY)" \
		"$(MACOS_NOTARY_KEY_ID)" \
		"$(MACOS_NOTARY_ISSUER_ID)"
	./scripts/build-macos-package.sh \
		$(MACOS_APP) \
		"$(MACOS_INSTALLER_SIGN_IDENTITY)" \
		"$(RELEASE_VERSION)" \
		$(MACOS_PACKAGE)
	./scripts/notarize-macos.sh \
		$(MACOS_PACKAGE) \
		"$(MACOS_NOTARY_KEY)" \
		"$(MACOS_NOTARY_KEY_ID)" \
		"$(MACOS_NOTARY_ISSUER_ID)"

linux-release:
	./scripts/build-linux-release.sh "$(RELEASE_VERSION)" "$(RELEASE_DIR)"

release-checksums:
	./scripts/checksums.sh "$(RELEASE_DIR)"

release-signature: release-checksums
	./scripts/sign-release.sh "$(RELEASE_DIR)"

pages:
	PASSFS_VERSION="$(RELEASE_VERSION)" ./scripts/prepare-pages.sh

docker-server:
	$(DOCKER) build \
		-f test/docker/server/Dockerfile \
		-t $(SERVER_TEST_IMAGE) \
		.

docker-server-shell: docker-server
	DOCKER="$(DOCKER)" ./scripts/docker-server-shell.sh "$(SERVER_TEST_IMAGE)"

test:
	$(GO_ENV) $(GO) test ./...

test-scripts:
	./scripts/test-next-version.sh
	./scripts/test-macos-installer.sh
	./scripts/test-macos-uninstaller.sh
	./scripts/test-macos-sandbox.sh

test-race:
	$(GO_ENV) $(GO) test -race ./...

vet:
	$(GO_ENV) $(GO) vet ./...

cross-build-linux:
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 $(GO_ENV) $(GO) build ./...

ifeq ($(SYSTEM),Darwin)
fskit-check:
	./scripts/check-fskit.sh

check: fskit-check
else
fskit-check:
	@echo "FSKit check skipped on $(SYSTEM)"
endif

check: test test-scripts vet build cross-build-linux

clean:
	rm -rf $(BINARY) $(MACOS_APP) $(RELEASE_ROOT) .pages
