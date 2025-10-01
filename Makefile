.PHONY: all build proto clean test run

all: proto build

proto:
	@echo "Generating Go code from proto file..."
	@mkdir -p proto
	@protoc --go_out=proto --go_opt=paths=source_relative \
		--go-grpc_out=proto --go-grpc_opt=paths=source_relative \
		plugin.proto
	@echo "Proto generation complete!"

build: proto
	@echo "Building plugin..."
	@go build -o anthropic-error-plugin .

clean:
	@echo "Cleaning..."
	@rm -rf proto/
	@rm -f anthropic-error-plugin

test:
	@echo "Running tests..."
	@go test -v ./...

run: build
	@echo "Running plugin..."
	./anthropic-error-plugin

install-deps:
	@echo "Installing dependencies..."
	@go install google.golang.org/protobuf/cmd/protoc-gen-go@latest
	@go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@latest
	@go mod download

help:
	@echo "Available targets:"
	@echo "  make proto        - Generate Go code from proto files"
	@echo "  make build        - Build the plugin binary"
	@echo "  make clean        - Clean generated files and binary"
	@echo "  make test         - Run tests"
	@echo "  make run          - Build and run the plugin"
	@echo "  make install-deps - Install required Go tools"
	@echo "  make help         - Show this help message"