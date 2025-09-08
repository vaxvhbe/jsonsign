package crypto

import (
	"os"
	"testing"
)

func TestGenerateRsaKey(t *testing.T) {
	key := GenerateRsaKey(Rsa2048)
	if key == nil {
		t.Error("expected key to be generated")
	}
	if key.Size() != 256 { // 2048 bits = 256 bytes
		t.Errorf("expected key size to be 256, got %d", key.Size())
	}
}

func TestRsaKeyToPem(t *testing.T) {
	key := GenerateRsaKey(Rsa2048)
	pubPem, privPem := RsaKeyToPem(key)

	if pubPem == nil || privPem == nil {
		t.Error("expected PEM data to be generated")
	}

	if len(*pubPem) == 0 || len(*privPem) == 0 {
		t.Error("expected PEM data to be non-empty")
	}
}

func TestLoadKeys(t *testing.T) {
	// Generate a key and write to temp files
	key := GenerateRsaKey(Rsa2048)
	pubPem, privPem := RsaKeyToPem(key)

	// Create temporary files
	pubF, err := os.CreateTemp("", "pub.key")
	if err != nil {
		t.Fatalf("cannot create tmp public key: %s", err)
	}
	defer os.Remove(pubF.Name())
	pubF.Write(*pubPem)
	pubF.Close()

	privF, err := os.CreateTemp("", "priv.key")
	if err != nil {
		t.Fatalf("cannot create tmp private key: %s", err)
	}
	defer os.Remove(privF.Name())
	privF.Write(*privPem)
	privF.Close()

	// Test loading
	loadedPrivKey, err := LoadPrivateKey(privF.Name())
	if err != nil {
		t.Errorf("cannot load private key: %s", err)
	}

	loadedPubKey, err := LoadPublicKey(pubF.Name())
	if err != nil {
		t.Errorf("cannot load public key: %s", err)
	}

	// Verify keys match
	if !key.PublicKey.Equal(loadedPubKey) {
		t.Error("loaded public key does not match original")
	}

	if !key.Equal(loadedPrivKey) {
		t.Error("loaded private key does not match original")
	}
}

func TestEncryptDecrypt(t *testing.T) {
	key := GenerateRsaKey(Rsa2048)
	message := []byte("Hello, World!")

	// Encrypt
	encrypted := EncryptWithPublicKey(message, &key.PublicKey)
	if len(encrypted) == 0 {
		t.Error("expected encrypted data to be non-empty")
	}

	// Decrypt
	decrypted := DecryptWithPrivateKey(encrypted, key)
	if string(decrypted) != string(message) {
		t.Errorf("expected %s, got %s", message, decrypted)
	}
}

func TestGenerateECDSAKey(t *testing.T) {
	curves := []ECDSACurve{P256, P384, P521}

	for _, curve := range curves {
		key := GenerateECDSAKey(curve)
		if key == nil {
			t.Errorf("expected ECDSA key to be generated for curve %d", curve)
		}

		// Verify curve is correct
		var expectedBitSize int
		switch curve {
		case P256:
			expectedBitSize = 256
		case P384:
			expectedBitSize = 384
		case P521:
			expectedBitSize = 521
		}

		if key.Curve.Params().BitSize != expectedBitSize {
			t.Errorf("expected bit size %d, got %d", expectedBitSize, key.Curve.Params().BitSize)
		}
	}
}

func TestECDSAKeyToPem(t *testing.T) {
	key := GenerateECDSAKey(P256)
	pubPem, privPem := ECDSAKeyToPem(key)

	if pubPem == nil || privPem == nil {
		t.Error("expected PEM data to be generated")
	}

	if len(*pubPem) == 0 || len(*privPem) == 0 {
		t.Error("expected PEM data to be non-empty")
	}
}

func TestLoadECDSAKeys(t *testing.T) {
	// Generate a key and write to temp files
	key := GenerateECDSAKey(P256)
	pubPem, privPem := ECDSAKeyToPem(key)

	// Create temporary files
	pubF, err := os.CreateTemp("", "ecdsa_pub.key")
	if err != nil {
		t.Fatalf("cannot create tmp public key: %s", err)
	}
	defer os.Remove(pubF.Name())
	pubF.Write(*pubPem)
	pubF.Close()

	privF, err := os.CreateTemp("", "ecdsa_priv.key")
	if err != nil {
		t.Fatalf("cannot create tmp private key: %s", err)
	}
	defer os.Remove(privF.Name())
	privF.Write(*privPem)
	privF.Close()

	// Test loading
	loadedPrivKey, err := LoadECDSAPrivateKey(privF.Name())
	if err != nil {
		t.Errorf("cannot load ECDSA private key: %s", err)
	}

	loadedPubKey, err := LoadECDSAPublicKey(pubF.Name())
	if err != nil {
		t.Errorf("cannot load ECDSA public key: %s", err)
	}

	// Verify keys match
	if !key.PublicKey.Equal(loadedPubKey) {
		t.Error("loaded ECDSA public key does not match original")
	}

	if !key.Equal(loadedPrivKey) {
		t.Error("loaded ECDSA private key does not match original")
	}
}
