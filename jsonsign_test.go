package jsonsign

import (
	"testing"
	// "github.com/vaxvhbe/jsonsign"
)

func TestRsa(t *testing.T) {
	jsonFilePath := "./g.json"

	privateKeyFilePath := "./private.key"
	jsSign := New(
		WithPrivateKeyFilePath(privateKeyFilePath),
	)

	publicKeyFilePath := "./public.key"
	jsValidate := New(
		WithPublicKeyFilePath(publicKeyFilePath),
	)

	options := JsonSignOptions{
		JsfCompliant: true,
	}
	for k, v := range DsaStrings {
		options.Algorithm = k
		if err := jsSign.Sign(jsonFilePath, &options); err != nil {
			t.Errorf("error signing %s", v)
		}
		if err := jsValidate.Validate(jsonFilePath, &options); err != nil {
			t.Errorf("error validating %s", v)
		}
	}
}
