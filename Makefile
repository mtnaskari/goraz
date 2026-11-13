.PHONY: check fmt vet lint vuln test fuzz build bench

FUZZTIME ?= 20s

GOLANGCI_LINT ?= golangci-lint

check: fmt vet lint vuln test

fmt:
	@test -z "$$(gofmt -l .)" || (gofmt -l . && exit 1)

vet:
	go vet ./...

# Lint once per platform and build tag, so files that build only there are checked.
lint:
	$(GOLANGCI_LINT) run ./...
	GOOS=linux $(GOLANGCI_LINT) run ./...
	GOOS=darwin $(GOLANGCI_LINT) run ./...
	GOEXPERIMENT=runtimesecret $(GOLANGCI_LINT) run ./...

vuln:
	govulncheck ./...

test:
	go test -race ./...

bench:
	go test -run '^$$' -bench . -count 8 ./... | tee bench.txt

build:
	CGO_ENABLED=0 go build -trimpath -o goraz ./cmd/goraz

fuzz:
	go test ./internal/format -run '^$$' -fuzz FuzzParse -fuzztime $(FUZZTIME)
	go test ./internal/envelope -run '^$$' -fuzz FuzzOpen -fuzztime $(FUZZTIME)
	go test ./internal/names -run '^$$' -fuzz FuzzValidate -fuzztime $(FUZZTIME)
	go test ./internal/tokfmt -run '^$$' -fuzz 'FuzzParse$$' -fuzztime $(FUZZTIME)
	go test ./internal/tokfmt -run '^$$' -fuzz FuzzParseRecovery -fuzztime $(FUZZTIME)
	go test ./audit -run '^$$' -fuzz FuzzVerifyBytes -fuzztime $(FUZZTIME)
	go test ./token -run '^$$' -fuzz FuzzVerify -fuzztime $(FUZZTIME)
	go test ./password -run '^$$' -fuzz FuzzParseOTPAuth -fuzztime $(FUZZTIME)
	go test ./vault -run '^$$' -fuzz FuzzDecodeManifest -fuzztime $(FUZZTIME)
	go test ./vault -run '^$$' -fuzz FuzzOpenReadOnly -fuzztime $(FUZZTIME)
	go test ./vault -run '^$$' -fuzz FuzzUnpad -fuzztime $(FUZZTIME)
	go test ./internal/state -run '^$$' -fuzz FuzzParseRecord -fuzztime $(FUZZTIME)
	go test ./internal/state -run '^$$' -fuzz FuzzDecide -fuzztime $(FUZZTIME)
	go test ./cmd/goraz -run '^$$' -fuzz FuzzParseDotEnv -fuzztime $(FUZZTIME)
	go test ./cmd/goraz -run '^$$' -fuzz FuzzParseRef -fuzztime $(FUZZTIME)
