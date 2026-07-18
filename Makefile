BIN := wgcoord
PKG := ./cmd/wgcoord
INSTALL_DIR ?= /usr/local/bin

LDFLAGS := -s -w

.PHONY: build install uninstall run-coordinator run-client test vet fmt tidy clean

build:
	go build -trimpath -ldflags "$(LDFLAGS)" -o $(BIN) $(PKG)

# Build and copy the binary to INSTALL_DIR (default /usr/local/bin).
install: build
	install -m 0755 $(BIN) $(INSTALL_DIR)/$(BIN)

uninstall:
	rm -f $(INSTALL_DIR)/$(BIN)

vet:
	go vet ./...

fmt:
	gofmt -w .

tidy:
	go mod tidy

test:
	go test ./...

clean:
	rm -f $(BIN)
