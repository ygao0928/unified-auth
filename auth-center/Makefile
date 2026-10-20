ROOT := $(dir $(abspath $(lastword $(MAKEFILE_LIST))))

.PHONY: test vet build tidy keygen up down

test:
	cd $(ROOT) && go test -race -count=1 ./...

vet:
	cd $(ROOT) && go vet ./...

build:
	cd $(ROOT) && go build -o bin/auth-center ./cmd/auth-center

tidy:
	cd $(ROOT) && go mod tidy

keygen:
	cd $(ROOT) && test -f .dev-keys/active.pem || go run ./cmd/auth-center keygen -dir .dev-keys

up: keygen
	cd $(ROOT) && docker compose up --build

down:
	cd $(ROOT) && docker compose down
