package crypto

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha512"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"time"
)

type RsaBitSize int

const (
	Rsa1024 RsaBitSize = 1024
	Rsa2048 RsaBitSize = 2048
	Rsa4096 RsaBitSize = 4096
)

func GenerateRsaKey(bitSize RsaBitSize) *rsa.PrivateKey {
	// Generate RSA key.
	key, err := rsa.GenerateKey(rand.Reader, int(bitSize))
	if err != nil {
		panic(err)
	}
	return key
}

func RsaKeyToPem(Key *rsa.PrivateKey) (
	PublicKey,
	PrivateKey *[]byte,
) {
	// Extract public component.
	pub := Key.Public()

	// Encode private key to PKCS#8 ASN.1 PEM.
	prvBytes, err := x509.MarshalPKCS8PrivateKey(Key)
	if err != nil {
		panic(err)
	}
	keyPEM := pem.EncodeToMemory(
		&pem.Block{
			Type:  "PRIVATE KEY",
			Bytes: prvBytes,
		},
	)

	// Encode public key to PKCS#8 ASN.1 PEM.
	pubBytes, err := x509.MarshalPKIXPublicKey(pub.(*rsa.PublicKey))
	if err != nil {
		panic(err)
	}
	pubPEM := pem.EncodeToMemory(
		&pem.Block{
			Type:  "PUBLIC KEY",
			Bytes: pubBytes,
		},
	)

	return &pubPEM, &keyPEM
}

// LoadPrivateKey load private key from file
func LoadPrivateKey(filename string) (*rsa.PrivateKey, error) {
	privateKeyFile, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(privateKeyFile)
	if block == nil || block.Type != "PRIVATE KEY" {
		return nil, fmt.Errorf("invalid private key")
	}

	privateKey, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	return privateKey.(*rsa.PrivateKey), nil
}

// LoadPublicKey load public key from file
func LoadPublicKey(filename string) (*rsa.PublicKey, error) {
	publicKeyFile, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(publicKeyFile)
	if block == nil || block.Type != "PUBLIC KEY" {
		return nil, fmt.Errorf("invalid public key")
	}

	publicKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	return publicKey.(*rsa.PublicKey), nil
}

func NewX509CertificateTemplate(
	Organization,
	CommonName string,
	Duration time.Duration,
) *x509.Certificate {
	return &x509.Certificate{
		SerialNumber: big.NewInt(1), // Unique serial number
		Subject: pkix.Name{
			Organization: []string{Organization},
			CommonName:   CommonName,
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(Duration),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
}

func GenerateRsaCertificate(
	Key *rsa.PrivateKey,
	CertTemplate *x509.Certificate,
) (
	Certificate *[]byte,
) {
	certBytes, err := x509.CreateCertificate(rand.Reader, CertTemplate, CertTemplate, Key.Public(), Key)
	if err != nil {
		panic(err)
	}
	return &certBytes
}

func CertificateToPem(
	CertBytes *[]byte,
) *[]byte {
	certPEM := new(bytes.Buffer)
	pem.Encode(certPEM, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: *CertBytes,
	})
	CertificatePem := certPEM.Bytes()
	return &CertificatePem
}

// https://gist.github.com/miguelmota/3ea9286bd1d3c2a985b67cac4ba2130a
// EncryptWithPublicKey encrypts data with public key
func EncryptWithPublicKey(
	msg []byte,
	pub *rsa.PublicKey,
) []byte {
	hash := sha512.New()
	ciphertext, err := rsa.EncryptOAEP(hash, rand.Reader, pub, msg, nil)
	if err != nil {
		panic(err)
	}
	return ciphertext
}

// DecryptWithPrivateKey decrypts data with private key
func DecryptWithPrivateKey(
	ciphertext []byte,
	priv *rsa.PrivateKey,
) []byte {
	hash := sha512.New()
	plaintext, err := rsa.DecryptOAEP(hash, rand.Reader, priv, ciphertext, nil)
	if err != nil {
		panic(err)
	}
	return plaintext
}

// ECDSA Curve type
type ECDSACurve int

const (
	P256 ECDSACurve = iota
	P384
	P521
)

// GenerateECDSAKey generates an ECDSA key with the specified curve
func GenerateECDSAKey(curve ECDSACurve) *ecdsa.PrivateKey {
	var ellipticCurve elliptic.Curve

	switch curve {
	case P256:
		ellipticCurve = elliptic.P256()
	case P384:
		ellipticCurve = elliptic.P384()
	case P521:
		ellipticCurve = elliptic.P521()
	default:
		panic("unsupported ECDSA curve")
	}

	key, err := ecdsa.GenerateKey(ellipticCurve, rand.Reader)
	if err != nil {
		panic(err)
	}
	return key
}

// ECDSAKeyToPem converts ECDSA key to PEM format
func ECDSAKeyToPem(key *ecdsa.PrivateKey) (
	PublicKey,
	PrivateKey *[]byte,
) {
	// Encode private key to PKCS#8 ASN.1 PEM
	prvBytes, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		panic(err)
	}
	keyPEM := pem.EncodeToMemory(
		&pem.Block{
			Type:  "PRIVATE KEY",
			Bytes: prvBytes,
		},
	)

	// Encode public key to PKIX ASN.1 PEM
	pubBytes, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		panic(err)
	}
	pubPEM := pem.EncodeToMemory(
		&pem.Block{
			Type:  "PUBLIC KEY",
			Bytes: pubBytes,
		},
	)

	return &pubPEM, &keyPEM
}

// LoadECDSAPrivateKey loads ECDSA private key from file
func LoadECDSAPrivateKey(filename string) (*ecdsa.PrivateKey, error) {
	privateKeyFile, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(privateKeyFile)
	if block == nil || block.Type != "PRIVATE KEY" {
		return nil, fmt.Errorf("invalid private key")
	}

	privateKey, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	ecdsaKey, ok := privateKey.(*ecdsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("not an ECDSA private key")
	}

	return ecdsaKey, nil
}

// LoadECDSAPublicKey loads ECDSA public key from file
func LoadECDSAPublicKey(filename string) (*ecdsa.PublicKey, error) {
	publicKeyFile, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(publicKeyFile)
	if block == nil || block.Type != "PUBLIC KEY" {
		return nil, fmt.Errorf("invalid public key")
	}

	publicKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	ecdsaKey, ok := publicKey.(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("not an ECDSA public key")
	}

	return ecdsaKey, nil
}
