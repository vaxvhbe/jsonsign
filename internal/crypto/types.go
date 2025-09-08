package crypto

import (
	"crypto/ecdsa"
	"crypto/rsa"
)

// KeyType represents the type of cryptographic key
type KeyType int

const (
	RSAKey KeyType = iota
	ECDSAKey
	Ed25519Key
)

// DSA represents signature algorithm types
type DSA uint

const (
	RS256 DSA = 1 + iota
	RS384
	RS512
	PS256
	PS384
	PS512
	ES256
	ES384
	ES512
	Ed25519
)

func (dsa DSA) String() string {
	return DsaStrings[dsa]
}

var DsaStrings = map[DSA]string{
	RS256:   "RS256",
	RS384:   "RS384",
	RS512:   "RS512",
	PS256:   "PS256",
	PS384:   "PS384",
	PS512:   "PS512",
	ES256:   "ES256",
	ES384:   "ES384",
	ES512:   "ES512",
	Ed25519: "Ed25519",
}

// Signer interface for different key types
type Signer interface {
	Sign(digest []byte, algorithm DSA) ([]byte, error)
	KeyType() KeyType
}

// Verifier interface for different key types  
type Verifier interface {
	Verify(digest []byte, signature []byte, algorithm DSA) error
	KeyType() KeyType
}

// RSASigner implements Signer for RSA keys
type RSASigner struct {
	privateKey *rsa.PrivateKey
}

func NewRSASigner(key *rsa.PrivateKey) *RSASigner {
	return &RSASigner{privateKey: key}
}

func (r *RSASigner) Sign(digest []byte, algorithm DSA) ([]byte, error) {
	return GenerateRSASignature(r.privateKey, digest, algorithm)
}

func (r *RSASigner) KeyType() KeyType {
	return RSAKey
}

// RSAVerifier implements Verifier for RSA keys
type RSAVerifier struct {
	publicKey *rsa.PublicKey
}

func NewRSAVerifier(key *rsa.PublicKey) *RSAVerifier {
	return &RSAVerifier{publicKey: key}
}

func (r *RSAVerifier) Verify(digest []byte, signature []byte, algorithm DSA) error {
	return VerifyRSASignature(r.publicKey, digest, signature, algorithm)
}

func (r *RSAVerifier) KeyType() KeyType {
	return RSAKey
}

// ECDSASigner implements Signer for ECDSA keys
type ECDSASigner struct {
	privateKey *ecdsa.PrivateKey
}

func NewECDSASigner(key *ecdsa.PrivateKey) *ECDSASigner {
	return &ECDSASigner{privateKey: key}
}

func (e *ECDSASigner) Sign(digest []byte, algorithm DSA) ([]byte, error) {
	return GenerateECDSASignature(e.privateKey, digest, algorithm)
}

func (e *ECDSASigner) KeyType() KeyType {
	return ECDSAKey
}

// ECDSAVerifier implements Verifier for ECDSA keys
type ECDSAVerifier struct {
	publicKey *ecdsa.PublicKey
}

func NewECDSAVerifier(key *ecdsa.PublicKey) *ECDSAVerifier {
	return &ECDSAVerifier{publicKey: key}
}

func (e *ECDSAVerifier) Verify(digest []byte, signature []byte, algorithm DSA) error {
	return VerifyECDSASignature(e.publicKey, digest, signature, algorithm)
}

func (e *ECDSAVerifier) KeyType() KeyType {
	return ECDSAKey
}

// Helper function to determine algorithm compatibility with key type
func IsAlgorithmCompatible(algorithm DSA, keyType KeyType) bool {
	switch keyType {
	case RSAKey:
		return algorithm >= RS256 && algorithm <= PS512
	case ECDSAKey:
		return algorithm >= ES256 && algorithm <= ES512
	case Ed25519Key:
		return algorithm == Ed25519
	default:
		return false
	}
}