.PHONY: all build proto clean test run

all: proto build

proto:
	@echo "Generating protobuf code..."
	@./generate.sh

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

docker-build:
	@echo "Building Docker image..."
	@docker build -t anthropic-error-plugin:latest .

help:
	@echo "Available targets:"
	@echo "  make proto        - Generate Go code from proto files"
	@echo "  make build        - Build the plugin binary"
	@echo "  make clean        - Clean generated files and binary"
	@echo "  make test         - Run tests"
	@echo "  make run          - Build and run the plugin"
	@echo "  make install-deps - Install required Go tools"
	@echo "  make docker-build - Build Docker image"
	@echo "  make help         - Show this help message"