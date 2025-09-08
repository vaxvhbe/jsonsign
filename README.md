# JSON Signature

The `jsonsign` library provides functionality to digitally sign JSON data using RSA cryptography. It allows users to:

- **Sign JSON Files**: Creates a secure signature for a given JSON document, ensuring the integrity and authenticity of the data. The signature is appended to the original JSON object without altering the data structure or content.
- **Validate JSON Signatures**: Verifies the authenticity of the signed JSON document by checking the validity of the signature against the public key. This process ensures that the JSON data has not been tampered with and originates from a trusted source.
- **Deterministic Serialization**: Ensures that the JSON data is serialized in a consistent manner before signing, preventing issues related to key ordering or formatting that could invalidate the signature.

The library is suitable for applications that require secure communication of JSON data, ensuring both integrity and authenticity through cryptographic signatures.

## Features

- **Multiple Algorithms**: Supports RS256, RS384, and RS512 signature algorithms
- **Clean Architecture**: Well-organized codebase with separation of concerns
- **Comprehensive Testing**: Full test coverage including cryptographic utilities
- **Standards Compliant**: Follows JSON Signature Format (JSF) and RFC 7518

## Quick Start

### 1. Build the project
```sh
make build
```

### 2. Generate RSA keys
```sh
make keys
```

### 3. Sign a JSON file
```sh
./bin/sign -priv private.key -json myfile.json
```

### 4. Validate the signature
```sh
./bin/validate -pub public.key -json myfile.json
```

## Development

### Development Workflow
```sh
make dev        # Format, vet, and test (recommended)
make help       # Show all available commands
```

### Testing
```sh
make test       # Run all tests
make coverage   # Generate coverage report
```

### Code Quality
```sh
make fmt        # Format code
make vet        # Run go vet
make lint       # Run linter (requires golangci-lint)
```

## Algorithm Support

The library supports the following RSA signature algorithms:

- **RS256** (default): RSASSA-PKCS1-v1_5 using SHA-256
- **RS384**: RSASSA-PKCS1-v1_5 using SHA-384  
- **RS512**: RSASSA-PKCS1-v1_5 using SHA-512

### Usage with specific algorithms
```sh
# Sign with RS384
./bin/sign -priv private.key -json myfile.json -RS384

# Validate RS384 signature
./bin/validate -pub public.key -json myfile.json -RS384
```

## Library Usage

```go
import "github.com/vaxvhbe/jsonsign"

// Create signer with private key file
signer := jsonsign.New(
    jsonsign.WithPrivateKeyFilePath("private.key"),
)

// Sign a JSON file
err := signer.Sign("document.json")

// Create validator with public key file  
validator := jsonsign.New(
    jsonsign.WithPublicKeyFilePath("public.key"),
)

// Validate signature
err = validator.Validate("document.json")
```

## Project Structure

```
├── cmd/                    # Command-line tools
│   ├── sign/              # JSON signing CLI
│   └── validate/          # JSON validation CLI
├── internal/crypto/       # Cryptographic utilities
├── testdata/             # Test JSON files
├── jsonsign.go           # Main library
└── jsonsign_test.go      # Library tests
```

## Standards

- [JSON Signature Format (JSF)](https://cyberphone.github.io/doc/security/jsf.html)
- [RFC 7518 - JSON Web Algorithms (JWA)](https://datatracker.ietf.org/doc/html/rfc7518)
