# JSON Signature

The `jsonsign` library provides functionality to digitally sign JSON data using modern cryptographic algorithms including RSA and ECDSA. It allows users to:

- **Sign JSON Files**: Creates a secure signature for a given JSON document using RSA (PKCS#1 v1.5 or PSS) or ECDSA algorithms, ensuring the integrity and authenticity of the data. The signature is appended to the original JSON object without altering the data structure or content.
- **Validate JSON Signatures**: Verifies the authenticity of the signed JSON document by checking the validity of the signature against the corresponding public key. This process ensures that the JSON data has not been tampered with and originates from a trusted source.
- **Deterministic Serialization**: Ensures that the JSON data is serialized in a consistent manner before signing, preventing issues related to key ordering or formatting that could invalidate the signature.
- **Multiple Cryptographic Algorithms**: Supports both RSA (RS*/PS* families) and ECDSA (ES* family) signature algorithms for maximum flexibility and security.

The library is suitable for applications that require secure communication of JSON data, ensuring both integrity and authenticity through state-of-the-art cryptographic signatures.

## Features

- **Multiple Algorithms**: Supports RSA (RS*/PS*) and ECDSA (ES*) signature algorithms
- **RSA Algorithms**: RS256, RS384, RS512, PS256, PS384, PS512
- **ECDSA Algorithms**: ES256, ES384, ES512 (with P-256, P-384, P-521 curves)
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

The library supports multiple signature algorithm families:

### RSA Algorithms
- **RS256** (default): RSASSA-PKCS1-v1_5 using SHA-256
- **RS384**: RSASSA-PKCS1-v1_5 using SHA-384  
- **RS512**: RSASSA-PKCS1-v1_5 using SHA-512
- **PS256**: RSASSA-PSS using SHA-256 (more secure than RS256)
- **PS384**: RSASSA-PSS using SHA-384
- **PS512**: RSASSA-PSS using SHA-512

### ECDSA Algorithms
- **ES256**: ECDSA using P-256 curve and SHA-256
- **ES384**: ECDSA using P-384 curve and SHA-384
- **ES512**: ECDSA using P-521 curve and SHA-512

### Usage with specific algorithms
```sh
# RSA algorithms (use RSA keys)
./bin/sign -priv private.key -json myfile.json -RS384
./bin/sign -priv private.key -json myfile.json -PS256

# ECDSA algorithms (use ECDSA keys)
./bin/sign -priv ecdsa_private.key -json myfile.json -ES256
./bin/validate -pub ecdsa_public.key -json myfile.json -ES256
```

## Library Usage

### RSA Keys
```go
import "github.com/vaxvhbe/jsonsign"

// Create signer with RSA private key file
signer := jsonsign.New(
    jsonsign.WithPrivateKeyFilePath("private.key"),
)
signer.Algorithm = jsonsign.PS256 // Use PSS instead of PKCS1v15

// Sign a JSON file
err := signer.Sign("document.json")

// Create validator with RSA public key file  
validator := jsonsign.New(
    jsonsign.WithPublicKeyFilePath("public.key"),
)
validator.Algorithm = jsonsign.PS256

// Validate signature
err = validator.Validate("document.json")
```

### ECDSA Keys
```go
// Create signer with ECDSA private key file
signer := jsonsign.New(
    jsonsign.WithECDSAPrivateKeyFilePath("ecdsa_private.key"),
)
signer.Algorithm = jsonsign.ES256

// Create validator with ECDSA public key file
validator := jsonsign.New(
    jsonsign.WithECDSAPublicKeyFilePath("ecdsa_public.key"),
)
validator.Algorithm = jsonsign.ES256

// Sign and validate
err := signer.Sign("document.json")
err = validator.Validate("document.json")
```

## Project Structure

```
├── cmd/                    # Command-line tools
│   ├── sign/               # JSON signing CLI
│   └── validate/           # JSON validation CLI
├── internal/crypto/        # Cryptographic implementation
│   ├── types.go            # Type definitions and interfaces
│   ├── keys.go             # Key generation and loading
│   └── algorithms.go       # Signature algorithm implementations
├── testdata/               # Test JSON files
├── jsonsign.go             # Public API
└── jsonsign_test.go        # Comprehensive tests (RSA + ECDSA)
```

## Architecture

The library uses a clean architecture with clear separation of concerns:

- **Public API** (`jsonsign.go`): Simple, user-friendly interface for signing and validation
- **Internal Implementation** (`internal/crypto/`): All cryptographic operations are isolated
- **Type System**: Strong typing with interface-based design for extensibility
- **Algorithm Support**: Pluggable architecture supporting multiple signature algorithms

## Standards

- [JSON Signature Format (JSF)](https://cyberphone.github.io/doc/security/jsf.html)
- [RFC 7518 - JSON Web Algorithms (JWA)](https://datatracker.ietf.org/doc/html/rfc7518)
