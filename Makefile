.PHONY: check fmt vet staticcheck gosec vuln test fuzz build

FUZZTIME ?= 20s

check: fmt vet staticcheck gosec vuln test

fmt:
	@test -z "$$(gofmt -l .)" || (gofmt -l . && exit 1)

vet:
	go vet ./...

staticcheck:
	staticcheck ./...

gosec:
	gosec -quiet -exclude-generated -tests=false ./...

vuln:
	govulncheck ./...

test:
	go test -race ./...

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
	go test ./cmd/goraz -run '^$$' -fuzz FuzzParseDotEnv -fuzztime $(FUZZTIME)
	go test ./cmd/goraz -run '^$$' -fuzz FuzzParseRef -fuzztime $(FUZZTIME)
