package jsonsign

import (
	"os"
	"testing"

	cryptoutil "github.com/vaxvhbe/jsonsign/internal/crypto"
)

const TestJsonFilePath = "./testdata/sample.json"

// ECDSA test functions moved from ecdsa_test.go
func TestECDSASignAndVerify(t *testing.T) {
	testCases := []struct {
		curve cryptoutil.ECDSACurve
		alg   DSA
	}{
		{cryptoutil.P256, ES256},
		{cryptoutil.P384, ES384},
		{cryptoutil.P521, ES512},
	}

	for _, tc := range testCases {
		t.Run(tc.alg.String(), func(t *testing.T) {
			key := cryptoutil.GenerateECDSAKey(tc.curve)
			message := []byte("ECDSA test message")
			hashed, err := JsonToHash(message, tc.alg)
			if err != nil {
				t.Fatalf("failed to hash message: %v", err)
			}

			signature, err := GenerateECDSASignature(key, hashed, tc.alg)
			if err != nil {
				t.Fatalf("failed to sign: %v", err)
			}

			if len(signature) == 0 {
				t.Error("expected signature to be non-empty")
			}

			err = VerifyECDSASignature(&key.PublicKey, hashed, signature, tc.alg)
			if err != nil {
				t.Fatalf("failed to verify signature: %v", err)
			}
		})
	}
}

func TestECDSASignerVerifier(t *testing.T) {
	key := cryptoutil.GenerateECDSAKey(cryptoutil.P256)

	signer := cryptoutil.NewECDSASigner(key)
	verifier := cryptoutil.NewECDSAVerifier(&key.PublicKey)

	message := []byte("test message for ECDSA signer/verifier")
	hashed, err := JsonToHash(message, ES256)
	if err != nil {
		t.Fatalf("failed to hash message: %v", err)
	}

	signature, err := signer.Sign(hashed, ES256)
	if err != nil {
		t.Fatalf("failed to sign: %v", err)
	}

	if signer.KeyType() != ECDSAKey {
		t.Error("expected ECDSAKey type for signer")
	}

	if verifier.KeyType() != ECDSAKey {
		t.Error("expected ECDSAKey type for verifier")
	}

	err = verifier.Verify(hashed, signature, ES256)
	if err != nil {
		t.Fatalf("failed to verify signature: %v", err)
	}
}

func TestIsAlgorithmCompatible(t *testing.T) {
	testCases := []struct {
		alg      DSA
		keyType  KeyType
		expected bool
	}{
		{RS256, RSAKey, true},
		{PS256, RSAKey, true},
		{RS256, ECDSAKey, false},
		{ES256, ECDSAKey, true},
		{ES384, ECDSAKey, true},
		{ES256, RSAKey, false},
		{Ed25519, Ed25519Key, true},
		{Ed25519, RSAKey, false},
		{Ed25519, ECDSAKey, false},
	}

	for _, tc := range testCases {
		result := cryptoutil.IsAlgorithmCompatible(tc.alg, tc.keyType)
		if result != tc.expected {
			t.Errorf("IsAlgorithmCompatible(%s, %d) = %v, expected %v",
				tc.alg.String(), tc.keyType, result, tc.expected)
		}
	}
}

func TestECDSAJsonSignAndValidate(t *testing.T) {
	key := cryptoutil.GenerateECDSAKey(cryptoutil.P256)

	signer := New(
		WithECDSAPrivateKey(key),
	)
	signer.Algorithm = ES256

	validator := New(
		WithECDSAPublicKey(&key.PublicKey),
	)
	validator.Algorithm = ES256

	testFile, err := os.CreateTemp("", "test_ecdsa_*.json")
	if err != nil {
		t.Fatalf("failed to create temp file: %v", err)
	}
	defer os.Remove(testFile.Name())

	testContent := `{"message": "ECDSA test", "curve": "P256"}`
	_, err = testFile.WriteString(testContent)
	if err != nil {
		t.Fatalf("failed to write test content: %v", err)
	}
	testFile.Close()

	err = signer.Sign(testFile.Name())
	if err != nil {
		t.Fatalf("failed to sign with ECDSA: %v", err)
	}

	err = validator.Validate(testFile.Name())
	if err != nil {
		t.Fatalf("failed to validate ECDSA signature: %v", err)
	}

	if signer.KeyType() != ECDSAKey {
		t.Error("expected ECDSAKey type for signer")
	}

	if validator.KeyType() != ECDSAKey {
		t.Error("expected ECDSAKey type for validator")
	}
}

func TestECDSAFromFile(t *testing.T) {
	if _, err := os.Stat("ecdsa_private_p256.key"); os.IsNotExist(err) {
		t.Skip("ECDSA key files not found, skipping file-based test")
	}

	signer := New(
		WithECDSAPrivateKeyFilePath("ecdsa_private_p256.key"),
	)
	signer.Algorithm = ES256

	validator := New(
		WithECDSAPublicKeyFilePath("ecdsa_public_p256.key"),
	)
	validator.Algorithm = ES256

	testFile := "./test_ecdsa_p256.json"

	err := signer.Sign(testFile)
	if err != nil {
		t.Fatalf("failed to sign with ECDSA from file: %v", err)
	}

	err = validator.Validate(testFile)
	if err != nil {
		t.Fatalf("failed to validate ECDSA signature from file: %v", err)
	}

	t.Log("ECDSA file-based signing and validation successful")
}

// Test ECDSA with SignAndVerifyAll
func TestECDSASignAndVerifyAll(t *testing.T) {
	key := cryptoutil.GenerateECDSAKey(cryptoutil.P256)

	signer := New(
		WithECDSAPrivateKey(key),
	)

	validator := New(
		WithECDSAPublicKey(&key.PublicKey),
	)

	SignAndVerifyAll(signer, validator, t)
}

func SignAndVerifyAll(
	Signer,
	Validator *JsonSign,
	t *testing.T,
) {
	// Test appropriate algorithms based on key type
	var algorithms []DSA
	if Signer.KeyType() == RSAKey {
		algorithms = []DSA{RS256, RS384, RS512, PS256, PS384, PS512}
	} else if Signer.KeyType() == ECDSAKey {
		algorithms = []DSA{ES256, ES384, ES512}
	}

	for _, alg := range algorithms {
		algName := DsaStrings[alg]
		Signer.Algorithm = alg
		if err := Signer.Sign(TestJsonFilePath); err != nil {
			t.Errorf("error signing %s: %v", algName, err)
		}
		Validator.Algorithm = alg
		if err := Validator.Validate(TestJsonFilePath); err != nil {
			t.Errorf("error validating %s: %v", algName, err)
		}
	}
}

func TestSVFromBytes(t *testing.T) {

	key := cryptoutil.GenerateRsaKey(cryptoutil.Rsa2048)
	Signer := New(
		WithPrivateKey(key),
	)

	Validator := New(
		WithPublicKey(&key.PublicKey),
	)

	SignAndVerifyAll(Signer, Validator, t)
}

func TestSVFromPath(t *testing.T) {

	key := cryptoutil.GenerateRsaKey(cryptoutil.Rsa2048)
	pubPem, prvPem := cryptoutil.RsaKeyToPem(key)

	pubF, err := os.CreateTemp("", "pub.key")
	if err != nil {
		t.Fatalf("cannot create tmp public key: %s", err)
	}
	defer os.Remove(pubF.Name())
	pubF.Write(*pubPem)

	prvF, err := os.CreateTemp("", "prv.key")
	if err != nil {
		t.Fatalf("cannot create tmp private key: %s", err)
	}
	defer os.Remove(prvF.Name())
	prvF.Write(*prvPem)
	t.Log(prvF.Name())

	Signer := New(
		WithPrivateKeyFilePath(prvF.Name()),
	)

	Validator := New(
		WithPublicKeyFilePath(pubF.Name()),
	)

	SignAndVerifyAll(Signer, Validator, t)
}
