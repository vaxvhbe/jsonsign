package jsonsign

import (
	"os"
	"testing"
	// "github.com/vaxvhbe/jsonsign"
)

const TestJsonFilePath = "./g.json"

func SignAndVerifyAll(
	Signer,
	Validator *JsonSign,
	t *testing.T,
) {
	for k, v := range DsaStrings {
		Signer.Algorithm = k
		if err := Signer.Sign(TestJsonFilePath); err != nil {
			t.Errorf("error signing %s", v)
		}
		Validator.Algorithm = k
		if err := Validator.Validate(TestJsonFilePath); err != nil {
			t.Errorf("error validating %s", v)
		}
	}
}

func TestSVFromBytes(t *testing.T) {

	key := GenerateRsaKey(Rsa2048)
	Signer := New(
		WithPrivateKey(key),
	)

	Validator := New(
		WithPublicKey(&key.PublicKey),
	)

	SignAndVerifyAll(Signer, Validator, t)
}

func TestSVFromPath(t *testing.T) {

	key := GenerateRsaKey(Rsa2048)
	pubPem, prvPem := RsaKeyToPem(key)

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
