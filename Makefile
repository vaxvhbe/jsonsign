.PHONY: build test clean keys help install lint fmt vet coverage

# Build binaries
build:
	@mkdir -p bin
	go build -o bin/sign cmd/sign/main.go
	go build -o bin/validate cmd/validate/main.go

# Run tests
test:
	go test ./...

# Run tests with coverage
coverage:
	go test -coverprofile=coverage.out ./...
	go tool cover -html=coverage.out -o coverage.html

# Clean build artifacts
clean:
	rm -rf bin/
	rm -f coverage.out coverage.html
	rm -f *.key *.pem
	find . -name "*.json" -not -path "./testdata/*" -delete

# Generate RSA keys for testing
keys:
	openssl genpkey -algorithm RSA -out private.key -pkeyopt rsa_keygen_bits:2048
	openssl rsa -pubout -in private.key -out public.key

# Format code
fmt:
	go fmt ./...

# Vet code
vet:
	go vet ./...

# Run linter (requires golangci-lint)
lint:
	@which golangci-lint > /dev/null || (echo "golangci-lint not found. Install with: go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest"; exit 1)
	golangci-lint run

# Install dependencies and tidy
install:
	go mod download
	go mod tidy

# Development workflow - format, vet, test
dev: fmt vet test

# Help
help:
	@echo "Available commands:"
	@echo "  build     - Build the binaries"
	@echo "  test      - Run all tests"
	@echo "  coverage  - Run tests with coverage report"
	@echo "  clean     - Clean build artifacts and temporary files"
	@echo "  keys      - Generate RSA keys for testing"
	@echo "  fmt       - Format Go code"
	@echo "  vet       - Run go vet"
	@echo "  lint      - Run golangci-lint"
	@echo "  install   - Install and tidy dependencies"
	@echo "  dev       - Run fmt, vet, and test (development workflow)"
	@echo "  help      - Show this help message"
