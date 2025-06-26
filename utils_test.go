package jsonsign

import (
	"bytes"
	"testing"
	"time"
)

func TestRsaKey(t *testing.T) {
	key := GenerateRsaKey(Rsa2048)

	msg := []byte("test message")
	ciphertext := EncryptWithPublicKey(msg, &key.PublicKey)
	plaintext := DecryptWithPrivateKey(ciphertext, key)
	if !bytes.Equal(plaintext, msg) {
		t.Fail()
	} else {
		t.Logf("message: %s", msg)
		t.Logf("decrypt: %s", plaintext)
	}
}

func TestRsaCert(t *testing.T) {
	key := GenerateRsaKey(Rsa2048)
	pubPem, privPem := RsaKeyToPem(key)
	if len(*pubPem) == 0 || len(*privPem) == 0 {
		t.Fail()
	} else {
		t.Logf("pub: %s", pubPem)
		t.Logf("key: %s", privPem)
	}

	certTemplate := NewX509CertificateTemplate("testorg", "muhname", 24*time.Hour)
	cert := GenerateRsaCertificate(key, certTemplate)
	certPem := CertificateToPem(cert)
	if len(*certPem) == 0 {
		t.Fail()
	} else {
		t.Logf("cert: %s", certPem)
	}
}
