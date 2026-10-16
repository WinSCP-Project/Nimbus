GO        ?= go
BIN       ?= nimbus
DATA      ?= $(HOME)/.nimbus
LISTEN    ?= 127.0.0.1:8787

.PHONY: all test build run tidy

all: test build

tidy:
	$(GO) mod tidy

test:
	$(GO) test ./...

build:
	$(GO) build -trimpath -ldflags "-s -w" -o $(BIN) .

run: build
	./$(BIN) -data $(DATA) -listen $(LISTEN)

windows:
	GOOS=windows GOARCH=amd64 $(GO) build -trimpath -ldflags "-s -w" -o nimbus.exe .
