#!/bin/bash

# Generate Go code from proto file
echo "Generating Go code from proto file..."

# Create proto directory
mkdir -p proto

# Generate the Go code
protoc --go_out=proto --go_opt=paths=source_relative \
       --go-grpc_out=proto --go-grpc_opt=paths=source_relative \
       plugin.proto

echo "Proto generation complete!"