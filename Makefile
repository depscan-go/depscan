.PHONY: build build-server test cover lint run-cli run-server


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
	go run ./cmd/depscan --path=./testdata --policy=./policy.yaml

run-server:
	go run ./cmd/server --policy=./policy.yaml