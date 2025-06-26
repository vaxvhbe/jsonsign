package jsonsign

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha512"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
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
			// Bytes: x509.MarshalPKCS1PrivateKey(Key),
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
			// Bytes: x509.MarshalPKCS1PublicKey(pub.(*rsa.PublicKey)),
		},
	)

	return &pubPEM, &keyPEM
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
