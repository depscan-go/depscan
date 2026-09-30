.PHONY: build test lint run-cli


build:
	go build -o bin/depscan ./cmd/depscan


build-server:
	go build -o bin/server ./cmd/server

test:
	go test -race ./...


cover:
	go test -coverprofile=coverage.out ./...
	go tool cover -html=coverage.out


lint:
	golangci-lint run ./...


run-cli:
	go run ./cmd/depscan scan --path=.