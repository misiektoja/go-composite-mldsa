# Setting SHELL to bash allows bash commands to be executed by recipes.
# Options are set to exit when a recipe line exits non-zero or a piped command fails.
SHELL = /usr/bin/env bash -o pipefail
.SHELLFLAGS = -ec

# GO_VERSION is the go directive in go.mod. Every recipe runs with exactly that toolchain, which is the
# one CI installs through go-version-file, so a newer local Go cannot change what the checks see.
# golangci-lint analyses the standard library of the toolchain in use. A toolchain newer than the
# linter understands makes it crash rather than report a finding.
GO_VERSION := $(shell awk '$$1 == "go" && $$2 ~ /^[0-9]/ { print $$2; exit }' go.mod)
export GOTOOLCHAIN := go$(GO_VERSION)

.PHONY: all
all: test

##@ General

.PHONY: help
help: ## Display this help.
	@awk 'BEGIN {FS = ":.*##"; printf "\nUsage:\n  make \033[36m<target>\033[0m\n"} /^[a-zA-Z_0-9-]+:.*?##/ { printf "  \033[36m%-15s\033[0m %s\n", $$1, $$2 } /^##@/ { printf "\n\033[1m%s\033[0m\n", substr($$0, 5) } ' $(MAKEFILE_LIST)

##@ Development

.PHONY: fmt
fmt: ## Format the Go sources.
	go fmt ./...
	cd interop && go fmt ./...

.PHONY: fmt-check
fmt-check: ## Fail when a tracked Go file is not gofmt formatted.
	@files=$$(git ls-files '*.go'); \
	if [ -z "$$files" ]; then echo "no Go files are tracked"; exit 1; fi; \
	unformatted=$$(gofmt -l $$files); \
	if [ -n "$$unformatted" ]; then echo "not gofmt formatted:"; echo "$$unformatted"; exit 1; fi

.PHONY: vet
vet: ## Run go vet.
	go vet ./...

.PHONY: tidy-check
tidy-check: ## Fail when go.mod or go.sum is not tidy.
	go mod tidy -diff
	cd interop && go mod tidy -diff

# TEST_SCRATCH holds coverage profiles, downloaded test tools and the release check export.
TEST_SCRATCH ?= $(CURDIR)/.cache/tests
export TEST_SCRATCH

.PHONY: test-scratch
test-scratch:
	mkdir -p "$(TEST_SCRATCH)"

.PHONY: test
test: vet test-scratch ## Run the tests under the race detector.
	go test -race -count=1 -coverprofile "$(TEST_SCRATCH)/cover.out" ./...

# Bouncy Castle is the independent implementation the interoperability tests compare against. The jars
# come from Maven Central and are checked against these SHA-256 digests before use.
BC_VERSION ?= 1.86
BC_DIR = $(TEST_SCRATCH)/bouncycastle-$(BC_VERSION)
BC_JARS = bcprov bcpkix bcutil
BC_SHA256_bcprov = 2af190b300cbb0b35e248ccf5f4a06b6072030aeb3da7a98ec73abe5b4cb371f
BC_SHA256_bcpkix = 8d8b41a4b149bdae8d331f059a578870954d1e3ff29f8269a9eb3ee19a7e4ef7
BC_SHA256_bcutil = 1c268e15f785aafb1e4670d8d6e5f856f69475e96c162dadcd1ff9b350e9139f
empty :=
space := $(empty) $(empty)
BC_CLASSPATH = $(subst $(space),:,$(foreach jar,$(BC_JARS),$(BC_DIR)/$(jar)-jdk18on-$(BC_VERSION).jar))

.PHONY: bouncycastle
bouncycastle: test-scratch ## Download and verify the Bouncy Castle jars the interoperability tests use.
	@mkdir -p "$(BC_DIR)"
	@$(foreach jar,$(BC_JARS), \
		file="$(BC_DIR)/$(jar)-jdk18on-$(BC_VERSION).jar"; \
		if [ ! -f "$$file" ]; then \
			echo "Downloading $(jar)-jdk18on-$(BC_VERSION).jar"; \
			curl -fsSL -o "$$file.part" "https://repo1.maven.org/maven2/org/bouncycastle/$(jar)-jdk18on/$(BC_VERSION)/$(jar)-jdk18on-$(BC_VERSION).jar"; \
			mv "$$file.part" "$$file"; \
		fi; \
		echo "$(BC_SHA256_$(jar))  $$file" | shasum -a 256 -c --quiet || { echo "error: $$file does not match the pinned digest"; exit 1; };)

.PHONY: test-interop
test-interop: bouncycastle ## Exchange certificates, revocation lists, requests, keys and signatures with Bouncy Castle. Needs a JDK on PATH.
	@command -v java >/dev/null || { echo "error: java is required for the interoperability tests"; exit 1; }
	cd interop && go vet ./...
	cd interop && BC_CLASSPATH="$(BC_CLASSPATH)" go test -count=1 -v ./...

# FUZZ_TIME bounds each target. go test fuzzes one target per invocation, so the targets run in turn.
FUZZ_TIME ?= 20s
# Minimization of newly interesting inputs stalls the workers for seconds at a time. A worker still
# busy when FUZZ_TIME expires makes Go report the run as failed with "context deadline exceeded"
# (golang/go#75804), so the bounded runs disable it. Set a duration to minimize crashers locally.
FUZZ_MINIMIZE_TIME ?= 0
FUZZ_TARGETS := .:FuzzParsePKIXPublicKey .:FuzzParsePKCS8PrivateKey .:FuzzVerify \
	./compositex509:FuzzParsePKIXPublicKey ./compositex509:FuzzCertificate

.PHONY: fuzz
fuzz: ## Fuzz every parsing target for FUZZ_TIME each. Failing inputs are saved under testdata.
	@for target in $(FUZZ_TARGETS); do \
		pkg="$${target%%:*}"; name="$${target##*:}"; \
		go test -list "^$$name$$" "$$pkg" | grep -x "$$name" >/dev/null || { echo "fuzz target $$name is missing from $$pkg"; exit 1; }; \
		echo "fuzzing $$name in $$pkg for $(FUZZ_TIME)"; \
		go test -run "^$$" -fuzz "^$$name$$" -fuzztime "$(FUZZ_TIME)" -fuzzminimizetime "$(FUZZ_MINIMIZE_TIME)" "$$pkg"; \
	done

##@ Documentation

# PYTHON selects the interpreter that provides the MkDocs toolchain.
PYTHON ?= python3

.PHONY: docs-deps
docs-deps: ## Install the pinned documentation build dependencies.
	$(PYTHON) -m pip install -r docs/requirements.txt

.PHONY: docs-build
docs-build: ## Build the documentation site into site/ and fail on any warning.
	$(PYTHON) -m mkdocs build --strict

.PHONY: docs-serve
docs-serve: ## Serve the documentation site locally with live reload.
	$(PYTHON) -m mkdocs serve

##@ Release

# VERSION names the release tag, for example v0.1.0. Every artifact is named after it.
VERSION ?=
# Artifacts without a release, such as the routine SBOM run, are named after the commit instead.
SBOM_VERSION := $(if $(VERSION),$(VERSION),$(shell git rev-parse --short HEAD))
SOURCE_ZIP = dist/go-composite-mldsa-$(VERSION)-source.zip
SOURCE_TAR_GZ = dist/go-composite-mldsa-$(VERSION)-source.tar.gz
SBOM_FILE = dist/go-composite-mldsa-$(SBOM_VERSION)-sbom.cdx.json
RELEASE_CHECKSUMS = dist/go-composite-mldsa-$(VERSION)_SHA256SUMS.txt

.PHONY: require-version
require-version:
	@test -n "$(VERSION)" || { echo "Set VERSION, for example VERSION=v0.1.0" >&2; exit 1; }

.PHONY: release-check
release-check: test-scratch ## Build, vet and test an export of HEAD and import it from a separate module. Set VERSION to check the release notes heading.
	@if grep -q '^replace ' go.mod; then echo "error: go.mod has a replace directive"; exit 1; fi
	@if [ -n "$(VERSION)" ]; then \
		version="$(VERSION)"; version="$${version#v}"; \
		grep -q "^## \[$$version\] - [0-9]" RELEASE_NOTES.md || { echo "error: RELEASE_NOTES.md has no dated heading for $$version"; exit 1; }; \
		if grep -qi '^## \[Unreleased' RELEASE_NOTES.md; then echo "error: RELEASE_NOTES.md still has an Unreleased section"; exit 1; fi; \
	fi
	@export="$(TEST_SCRATCH)/release-check"; \
	if [ -e "$$export" ]; then echo "error: $$export exists, move it aside first"; exit 1; fi; \
	mkdir -p "$$export/export" "$$export/consumer"; \
	git archive --format=tar HEAD | tar -x -C "$$export/export"; \
	cd "$$export/export" && go mod verify && go build ./... && go vet ./... && go test -count=1 ./...; \
	cd "$$export/consumer" && printf 'module example.com/consumer\n\ngo %s\n\nrequire github.com/misiektoja/go-composite-mldsa v0.0.0\n\nreplace github.com/misiektoja/go-composite-mldsa => ../export\n' "$(GO_VERSION)" > go.mod; \
	printf 'package main\n\nimport (\n\t"crypto/x509"\n\t"log"\n\n\tcompositemldsa "github.com/misiektoja/go-composite-mldsa"\n\t"github.com/misiektoja/go-composite-mldsa/compositex509"\n)\n\nfunc main() {\n\tkey, err := compositemldsa.GenerateKey(compositemldsa.MLDSA65ECDSAP256SHA512)\n\tif err != nil {\n\t\tlog.Fatal(err)\n\t}\n\tder, err := compositex509.CreateCertificateRequest(nil, &x509.CertificateRequest{}, key)\n\tif err != nil {\n\t\tlog.Fatal(err)\n\t}\n\tlog.Println(key.Algorithm(), len(der))\n}\n' > main.go; \
	go mod tidy && go build ./... && go run .; \
	echo "release check passed for $$(git -C "$(CURDIR)" rev-parse --short HEAD)"

.PHONY: release-body
release-body: require-version ## Extract the RELEASE_NOTES.md section of VERSION into dist/release-body.md.
	@mkdir -p dist
	@version="$(VERSION)"; awk -v want="## [$${version#v}]" 'index($$0, want) == 1 { found = 1; next } found && /^## \[/ { exit } found { print }' RELEASE_NOTES.md | sed '/./,$$!d' > dist/release-body.md
	@grep -q '[^[:space:]]' dist/release-body.md || { echo "error: RELEASE_NOTES.md has no section for $(VERSION)" >&2; exit 1; }
	@echo "Wrote dist/release-body.md"

.PHONY: sbom
sbom: cyclonedx-gomod ## Generate a CycloneDX software bill of materials for the module. Set VERSION for a release.
	mkdir -p dist
	"$(CYCLONEDX_GOMOD)" mod -licenses -json -output "$(SBOM_FILE)" .
	@echo "Wrote $(SBOM_FILE)"

.PHONY: release-source-archives
release-source-archives: require-version ## Archive the complete tagged source tree as ZIP and tar. Set VERSION.
	mkdir -p dist
	git archive --format=zip --output "$(SOURCE_ZIP)" "$(VERSION)"
	git archive --format=tar.gz --output "$(SOURCE_TAR_GZ)" "$(VERSION)"

.PHONY: release-checksums
release-checksums: release-source-archives ## Write SHA-256 checksums for the source archives and the SBOM. Set VERSION.
	@test -f "$(SBOM_FILE)" || { echo "Run sbom with the same VERSION first, $(SBOM_FILE) is missing" >&2; exit 1; }
	cd dist && shasum -a 256 "$(notdir $(SBOM_FILE))" "$(notdir $(SOURCE_ZIP))" "$(notdir $(SOURCE_TAR_GZ))" | tee "$(notdir $(RELEASE_CHECKSUMS))"

##@ Checks

.PHONY: lint
lint: golangci-lint ## Run golangci-lint.
	"$(GOLANGCI_LINT)" run
	cd interop && "$(GOLANGCI_LINT)" run

.PHONY: lint-fix
lint-fix: golangci-lint ## Run golangci-lint and apply the fixes it offers.
	"$(GOLANGCI_LINT)" run --fix

.PHONY: lint-config
lint-config: golangci-lint ## Verify the golangci-lint configuration.
	"$(GOLANGCI_LINT)" config verify

.PHONY: actionlint
actionlint: actionlint-tool ## Lint the GitHub Actions workflows.
	"$(ACTIONLINT)"

.PHONY: govulncheck
govulncheck: govulncheck-tool ## Report known vulnerabilities that reach the module or its dependencies.
	"$(GOVULNCHECK)" ./...
	cd interop && "$(GOVULNCHECK)" -test ./...

# GITLEAKS_LOG_OPTS selects the history the commit scan walks.
GITLEAKS_LOG_OPTS ?= --full-history --all

.PHONY: gitleaks
gitleaks: gitleaks-tool ## Scan the working tree and the commit history for leaked credentials.
# Excluded artifact paths must not contain tracked files.
	@test -z "$$(git ls-files local .cache bin)" || { echo "error: tracked files are excluded from the gitleaks scan by .gitleaks.toml"; exit 1; }
	"$(GITLEAKS)" dir . --config .gitleaks.toml --redact --no-banner
	"$(GITLEAKS)" git . --config .gitleaks.toml --redact --no-banner --log-opts="$(GITLEAKS_LOG_OPTS)"

##@ Dependencies

## Location to install dependencies to
LOCALBIN ?= $(shell pwd)/bin
$(LOCALBIN):
	mkdir -p "$(LOCALBIN)"

## Tool Binaries
GOLANGCI_LINT ?= $(LOCALBIN)/golangci-lint
GOVULNCHECK ?= $(LOCALBIN)/govulncheck
GITLEAKS ?= $(LOCALBIN)/gitleaks
ACTIONLINT ?= $(LOCALBIN)/actionlint
CYCLONEDX_GOMOD ?= $(LOCALBIN)/cyclonedx-gomod

## Tool Versions
GOLANGCI_LINT_VERSION ?= v2.14.0
GOVULNCHECK_VERSION ?= v1.8.0
GITLEAKS_VERSION ?= v8.30.1
ACTIONLINT_VERSION ?= v1.7.12
CYCLONEDX_GOMOD_VERSION ?= v1.12.0

.PHONY: golangci-lint
golangci-lint: | $(LOCALBIN) ## Download golangci-lint locally if necessary.
	$(call go-install-tool,$(GOLANGCI_LINT),github.com/golangci/golangci-lint/v2/cmd/golangci-lint,$(GOLANGCI_LINT_VERSION))

.PHONY: govulncheck-tool
govulncheck-tool: | $(LOCALBIN) ## Download govulncheck locally if necessary.
	$(call go-install-tool,$(GOVULNCHECK),golang.org/x/vuln/cmd/govulncheck,$(GOVULNCHECK_VERSION))

.PHONY: gitleaks-tool
gitleaks-tool: | $(LOCALBIN) ## Download gitleaks locally if necessary.
	$(call go-install-tool,$(GITLEAKS),github.com/zricethezav/gitleaks/v8,$(GITLEAKS_VERSION))

.PHONY: actionlint-tool
actionlint-tool: | $(LOCALBIN) ## Download actionlint locally if necessary.
	$(call go-install-tool,$(ACTIONLINT),github.com/rhysd/actionlint/cmd/actionlint,$(ACTIONLINT_VERSION))

.PHONY: cyclonedx-gomod
cyclonedx-gomod: | $(LOCALBIN) ## Download cyclonedx-gomod locally if necessary.
	$(call go-install-tool,$(CYCLONEDX_GOMOD),github.com/CycloneDX/cyclonedx-gomod/cmd/cyclonedx-gomod,$(CYCLONEDX_GOMOD_VERSION))

# go-install-tool installs a package at a pinned version under a versioned directory and points the
# unversioned tool path at it, so a version bump installs the new tool instead of keeping the old one.
# $1 - tool path, $2 - package path, $3 - version
define go-install-tool
@dir="$(LOCALBIN)/.tools/$(notdir $(1))@$(3)"; \
if [ ! -x "$$dir/$(notdir $(1))" ]; then \
	echo "Downloading $(2)@$(3)"; \
	mkdir -p "$$dir"; \
	GOBIN="$$dir" go install "$(2)@$(3)"; \
fi; \
ln -sfn "$$dir/$(notdir $(1))" "$(1)"
endef
