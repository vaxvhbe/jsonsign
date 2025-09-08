package crypto

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"encoding/asn1"
	"fmt"
	"math/big"
)

// GenerateRSASignature generates RSA signature with specified algorithm
func GenerateRSASignature(privateKey *rsa.PrivateKey, digest []byte, algorithm DSA) ([]byte, error) {
	switch algorithm {
	case RS256, RS384, RS512:
		return generateRSAPKCS1Signature(privateKey, digest, algorithm)
	case PS256, PS384, PS512:
		return generateRSAPSSSignature(privateKey, digest, algorithm)
	default:
		return nil, fmt.Errorf("unsupported RSA algorithm: %s", algorithm.String())
	}
}

// VerifyRSASignature verifies RSA signature with specified algorithm
func VerifyRSASignature(publicKey *rsa.PublicKey, digest, signature []byte, algorithm DSA) error {
	switch algorithm {
	case RS256, RS384, RS512:
		return verifyRSAPKCS1Signature(publicKey, digest, signature, algorithm)
	case PS256, PS384, PS512:
		return verifyRSAPSSSignature(publicKey, digest, signature, algorithm)
	default:
		return fmt.Errorf("unsupported RSA algorithm: %s", algorithm.String())
	}
}

// GenerateECDSASignature generates ECDSA signature with specified algorithm
func GenerateECDSASignature(privateKey *ecdsa.PrivateKey, digest []byte, algorithm DSA) ([]byte, error) {
	if !IsAlgorithmCompatible(algorithm, ECDSAKey) {
		return nil, fmt.Errorf("algorithm %s not compatible with ECDSA", algorithm.String())
	}

	r, s, err := ecdsa.Sign(rand.Reader, privateKey, digest)
	if err != nil {
		return nil, fmt.Errorf("failed to sign with ECDSA: %w", err)
	}

	sig := ecdsaSignature{R: r, S: s}
	return asn1.Marshal(sig)
}

// VerifyECDSASignature verifies ECDSA signature with specified algorithm
func VerifyECDSASignature(publicKey *ecdsa.PublicKey, digest, signature []byte, algorithm DSA) error {
	if !IsAlgorithmCompatible(algorithm, ECDSAKey) {
		return fmt.Errorf("algorithm %s not compatible with ECDSA", algorithm.String())
	}

	var sig ecdsaSignature
	_, err := asn1.Unmarshal(signature, &sig)
	if err != nil {
		return fmt.Errorf("failed to unmarshal ECDSA signature: %w", err)
	}

	if !ecdsa.Verify(publicKey, digest, sig.R, sig.S) {
		return fmt.Errorf("ECDSA signature verification failed")
	}

	return nil
}

// ECDSA signature structure for ASN.1 encoding
type ecdsaSignature struct {
	R, S *big.Int
}

// generateRSAPKCS1Signature generates RSA PKCS#1 v1.5 signature
func generateRSAPKCS1Signature(privateKey *rsa.PrivateKey, digest []byte, algorithm DSA) ([]byte, error) {
	hashFunc, err := GetHashForAlgorithm(algorithm)
	if err != nil {
		return nil, err
	}

	signature, err := rsa.SignPKCS1v15(rand.Reader, privateKey, hashFunc, digest)
	if err != nil {
		return nil, fmt.Errorf("failed to sign with RSA PKCS1v15: %w", err)
	}

	return signature, nil
}

// verifyRSAPKCS1Signature verifies RSA PKCS#1 v1.5 signature
func verifyRSAPKCS1Signature(publicKey *rsa.PublicKey, digest, signature []byte, algorithm DSA) error {
	hashFunc, err := GetHashForAlgorithm(algorithm)
	if err != nil {
		return err
	}

	err = rsa.VerifyPKCS1v15(publicKey, hashFunc, digest, signature)
	if err != nil {
		return fmt.Errorf("RSA PKCS1v15 signature verification failed: %w", err)
	}

	return nil
}

// generateRSAPSSSignature generates RSA-PSS signature
func generateRSAPSSSignature(privateKey *rsa.PrivateKey, digest []byte, algorithm DSA) ([]byte, error) {
	var cryptoHash crypto.Hash

	switch algorithm {
	case PS256:
		cryptoHash = crypto.SHA256
	case PS384:
		cryptoHash = crypto.SHA384
	case PS512:
		cryptoHash = crypto.SHA512
	default:
		return nil, fmt.Errorf("unsupported PSS algorithm: %s", algorithm.String())
	}

	opts := &rsa.PSSOptions{
		SaltLength: rsa.PSSSaltLengthAuto,
		Hash:       cryptoHash,
	}

	signature, err := rsa.SignPSS(rand.Reader, privateKey, cryptoHash, digest, opts)
	if err != nil {
		return nil, fmt.Errorf("failed to sign with RSA-PSS: %w", err)
	}

	return signature, nil
}

// verifyRSAPSSSignature verifies RSA-PSS signature
func verifyRSAPSSSignature(publicKey *rsa.PublicKey, digest, signature []byte, algorithm DSA) error {
	var cryptoHash crypto.Hash

	switch algorithm {
	case PS256:
		cryptoHash = crypto.SHA256
	case PS384:
		cryptoHash = crypto.SHA384
	case PS512:
		cryptoHash = crypto.SHA512
	default:
		return fmt.Errorf("unsupported PSS algorithm: %s", algorithm.String())
	}

	opts := &rsa.PSSOptions{
		SaltLength: rsa.PSSSaltLengthAuto,
		Hash:       cryptoHash,
	}

	err := rsa.VerifyPSS(publicKey, cryptoHash, digest, signature, opts)
	if err != nil {
		return fmt.Errorf("RSA-PSS signature verification failed: %w", err)
	}

	return nil
}

// GetHashForAlgorithm returns the crypto.Hash for the given algorithm
func GetHashForAlgorithm(algorithm DSA) (crypto.Hash, error) {
	switch algorithm {
	case RS256, PS256, ES256:
		return crypto.SHA256, nil
	case RS384, PS384, ES384:
		return crypto.SHA384, nil
	case RS512, PS512, ES512:
		return crypto.SHA512, nil
	default:
		return 0, fmt.Errorf("unsupported algorithm: %s", algorithm.String())
	}
}