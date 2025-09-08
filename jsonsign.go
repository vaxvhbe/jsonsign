package jsonsign

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"sort"

	cryptoutil "github.com/vaxvhbe/jsonsign/internal/crypto"
)

// JsonSign contains keys and algorithm information
// For now, supports both RSA and ECDSA keys (but not simultaneously)
type JsonSign struct {
	// RSA keys (for RS*, PS* algorithms)
	PrivateKey *rsa.PrivateKey
	PublicKey  *rsa.PublicKey

	// ECDSA keys (for ES* algorithms)
	ECDSAPrivateKey *ecdsa.PrivateKey
	ECDSAPublicKey  *ecdsa.PublicKey

	Algorithm DSA
}

// KeyType returns the type of key currently configured
func (js *JsonSign) KeyType() KeyType {
	if js.ECDSAPrivateKey != nil || js.ECDSAPublicKey != nil {
		return ECDSAKey
	}
	return RSAKey
}

// New create new instance of JsonSign
func New(options ...func(*JsonSign)) *JsonSign {
	js := &JsonSign{
		Algorithm: RS256,
	}

	for _, option := range options {
		option(js)
	}

	return js
}

func WithPublicKey(publicKey *rsa.PublicKey) func(*JsonSign) {
	return func(js *JsonSign) {
		js.PublicKey = publicKey
	}
}

// WithPublicKeyFilePath give the public key file path
func WithPublicKeyFilePath(publicKeyFilePath string) func(*JsonSign) {

	publicKey, err := cryptoutil.LoadPublicKey(publicKeyFilePath)
	if err != nil {
		panic(fmt.Sprintf("cannot load public key: %s", err))
	}

	return func(js *JsonSign) {
		js.PublicKey = publicKey
	}
}

func WithPrivateKey(privateKey *rsa.PrivateKey) func(*JsonSign) {
	return func(js *JsonSign) {
		js.PrivateKey = privateKey
	}
}

// WithPrivateKeyFilePath give the private key file path
func WithPrivateKeyFilePath(privateKeyFilePath string) func(*JsonSign) {

	// Load the private key
	privateKey, err := cryptoutil.LoadPrivateKey(privateKeyFilePath)
	if err != nil {
		panic(fmt.Sprintf("cannot load private key: %s", err))
	}

	return func(js *JsonSign) {
		js.PrivateKey = privateKey
	}
}

func WithECDSAPrivateKey(privateKey *ecdsa.PrivateKey) func(*JsonSign) {
	return func(js *JsonSign) {
		js.ECDSAPrivateKey = privateKey
	}
}

func WithECDSAPublicKey(publicKey *ecdsa.PublicKey) func(*JsonSign) {
	return func(js *JsonSign) {
		js.ECDSAPublicKey = publicKey
	}
}

// WithECDSAPrivateKeyFilePath loads ECDSA private key from file
func WithECDSAPrivateKeyFilePath(privateKeyFilePath string) func(*JsonSign) {
	privateKey, err := cryptoutil.LoadECDSAPrivateKey(privateKeyFilePath)
	if err != nil {
		panic(fmt.Sprintf("cannot load ECDSA private key: %s", err))
	}

	return func(js *JsonSign) {
		js.ECDSAPrivateKey = privateKey
	}
}

// WithECDSAPublicKeyFilePath loads ECDSA public key from file
func WithECDSAPublicKeyFilePath(publicKeyFilePath string) func(*JsonSign) {
	publicKey, err := cryptoutil.LoadECDSAPublicKey(publicKeyFilePath)
	if err != nil {
		panic(fmt.Sprintf("cannot load ECDSA public key: %s", err))
	}

	return func(js *JsonSign) {
		js.ECDSAPublicKey = publicKey
	}
}

// Re-export types from internal/crypto for public API
type DSA = cryptoutil.DSA
type KeyType = cryptoutil.KeyType

// Re-export constants
const (
	RS256   = cryptoutil.RS256
	RS384   = cryptoutil.RS384
	RS512   = cryptoutil.RS512
	PS256   = cryptoutil.PS256
	PS384   = cryptoutil.PS384
	PS512   = cryptoutil.PS512
	ES256   = cryptoutil.ES256
	ES384   = cryptoutil.ES384
	ES512   = cryptoutil.ES512
	Ed25519 = cryptoutil.Ed25519

	RSAKey     = cryptoutil.RSAKey
	ECDSAKey   = cryptoutil.ECDSAKey
	Ed25519Key = cryptoutil.Ed25519Key
)

var DsaStrings = cryptoutil.DsaStrings

func JsonToHash(stableJson []byte, alg DSA) ([]byte, error) {
	var res []byte
	var err error
	switch alg {
	case RS256, PS256, ES256:
		tmp := sha256.Sum256(stableJson)
		res = tmp[:]
	case RS384, PS384, ES384:
		tmp := sha512.Sum384(stableJson)
		res = tmp[:]
	case RS512, PS512, ES512:
		tmp := sha512.Sum512(stableJson)
		res = tmp[:]
	case Ed25519:
		// Ed25519 doesn't pre-hash, it signs the raw message
		res = stableJson
	default:
		err = fmt.Errorf("unsupported alg: %s", alg.String())
	}
	return res, err
}

func GenerateSignature(privateKey *rsa.PrivateKey, hashed []byte, alg DSA) ([]byte, error) {
	return cryptoutil.GenerateRSASignature(privateKey, hashed, alg)
}

func VerifySignature(publicKey *rsa.PublicKey, hashed, signature []byte, alg DSA) error {
	return cryptoutil.VerifyRSASignature(publicKey, hashed, signature, alg)
}

func GenerateECDSASignature(privateKey *ecdsa.PrivateKey, hashed []byte, alg DSA) ([]byte, error) {
	return cryptoutil.GenerateECDSASignature(privateKey, hashed, alg)
}

func VerifyECDSASignature(publicKey *ecdsa.PublicKey, hashed, signature []byte, alg DSA) error {
	return cryptoutil.VerifyECDSASignature(publicKey, hashed, signature, alg)
}

func SetupAlgFlags() map[DSA]*bool {
	algFlags := map[DSA]*bool{}
	for k, v := range DsaStrings {
		algFlags[k] = flag.Bool(v, false, v)
	}
	return algFlags
}

func ParseAlgFlag(algFlags map[DSA]*bool) (*DSA, error) {
	count := 0
	var alg DSA
	for k, v := range algFlags {
		if *v {
			alg = k
			count += 1
		}
	}
	// default rsa256
	if count == 0 {
		alg = RS256
	} else if count > 1 {
		return nil, fmt.Errorf("must specify 0 or 1 algorithms")
	}
	return &alg, nil
}

// Sign the JSON file and add a signature
func (js *JsonSign) Sign(jsonFilePath string) error {

	if err := validateFilePath(jsonFilePath); err != nil {
		return fmt.Errorf("cannot validate json file path: %s", err)
	}

	// Read and unmarshal the JSON data
	jsonData, err := os.ReadFile(jsonFilePath)
	if err != nil {
		return fmt.Errorf("cannot read json file: %s", err)
	}

	var jsonMap map[string]interface{}
	if err := json.Unmarshal(jsonData, &jsonMap); err != nil {
		return fmt.Errorf("cannot unmarshal json: %s", err)
	}

	// Remove any existing signature before signing
	delete(jsonMap, "signature")

	// set signature scaffold
	sig := map[string]interface{}{
		"algorithm": js.Algorithm.String(),
	}
	jsonMap["signature"] = sig

	// Serialize the JSON in a stable, deterministic way
	stableJson, err := toStableJson(jsonMap)
	if err != nil {
		return fmt.Errorf("cannot serialize json deterministically: %s", err)
	}

	// Create a hash of the stable JSON
	hashed, err := JsonToHash(stableJson, js.Algorithm)
	if err != nil {
		return fmt.Errorf("cannot hash payload: %s", err)
	}

	// Sign the hash using appropriate algorithm
	var signature []byte
	switch js.KeyType() {
	case RSAKey:
		signature, err = GenerateSignature(js.PrivateKey, hashed, js.Algorithm)
	case ECDSAKey:
		signature, err = GenerateECDSASignature(js.ECDSAPrivateKey, hashed, js.Algorithm)
	default:
		return fmt.Errorf("unsupported key type for algorithm %s", js.Algorithm.String())
	}
	if err != nil {
		return fmt.Errorf("cannot sign json: %s", err)
	}

	// Encode the signature in base64
	signatureBase64 := base64.StdEncoding.EncodeToString(signature)

	// Add the signature to the original JSON map
	sig["value"] = signatureBase64
	jsonMap["signature"] = sig

	// Marshal the modified JSON back to a file
	signedJsonData, err := json.MarshalIndent(jsonMap, "", "  ")
	if err != nil {
		return fmt.Errorf("cannot marshal signed json: %s", err)
	}

	// Write the signed JSON to the file
	if err := os.WriteFile(jsonFilePath, signedJsonData, 0644); err != nil {
		return fmt.Errorf("cannot write signed json to file: %s", err)
	}

	return nil
}

// Validate the JSON file signature
func (js *JsonSign) Validate(jsonFilePath string) error {

	if err := validateFilePath(jsonFilePath); err != nil {
		return fmt.Errorf("cannot validate json file path: %s", err)
	}

	// Read and unmarshal the JSON data
	jsonData, err := os.ReadFile(jsonFilePath)
	if err != nil {
		return fmt.Errorf("cannot read json file: %s", err)
	}

	var jsonMap map[string]interface{}
	if err := json.Unmarshal(jsonData, &jsonMap); err != nil {
		return fmt.Errorf("cannot unmarshal json: %s", err)
	}

	// Extract the signature from the JSON & reset scaffold
	sig, ok := jsonMap["signature"].(map[string]interface{})
	if !ok {
		return fmt.Errorf("no signature found in json")
	}
	signatureBase64 := sig["value"].(string)
	delete(sig, "value")
	jsonMap["signature"] = sig

	// Serialize the JSON in a stable, deterministic way
	stableJson, err := toStableJson(jsonMap)
	if err != nil {
		return fmt.Errorf("cannot serialize json deterministically: %s", err)
	}

	// Create a hash of the stable JSON
	hashed, err := JsonToHash(stableJson, js.Algorithm)
	if err != nil {
		return fmt.Errorf("cannot hash payload: %s", err)
	}

	// Decode the base64 signature
	signature, err := base64.StdEncoding.DecodeString(signatureBase64)
	if err != nil {
		return fmt.Errorf("cannot decode signature: %s", err)
	}

	// Verify the signature using appropriate algorithm
	switch js.KeyType() {
	case RSAKey:
		err = VerifySignature(js.PublicKey, hashed, signature, js.Algorithm)
	case ECDSAKey:
		err = VerifyECDSASignature(js.ECDSAPublicKey, hashed, signature, js.Algorithm)
	default:
		return fmt.Errorf("unsupported key type for algorithm %s", js.Algorithm.String())
	}
	if err != nil {
		return fmt.Errorf("invalid signature: %s", err)
	}

	return nil
}

// Helper to serialize JSON in a stable way (sorted by keys)
func toStableJson(jsonMap map[string]interface{}) ([]byte, error) {
	// Sort the keys of the JSON
	keys := make([]string, 0, len(jsonMap))
	for key := range jsonMap {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	// Create a buffer to serialize the JSON
	buffer := new(bytes.Buffer)
	buffer.WriteString("{")

	for i, key := range keys {
		// Marshal each key-value pair deterministically
		keyValue, err := json.Marshal(map[string]interface{}{key: jsonMap[key]})
		if err != nil {
			return nil, err
		}
		buffer.Write(keyValue[1 : len(keyValue)-1]) // Remove { and } from key-value

		if i < len(keys)-1 {
			buffer.WriteString(",")
		}
	}

	buffer.WriteString("}")

	return buffer.Bytes(), nil
}

// validateFilePath validate file path
func validateFilePath(path string) error {
	info, err := os.Stat(path)
	if os.IsNotExist(err) {
		return fmt.Errorf("file '%s' is not exist", path)
	}
	if err != nil {
		return fmt.Errorf("invalid file path '%s': %v", path, err)
	}

	if info.IsDir() {
		return fmt.Errorf("file path is a directory")
	}

	return nil
}
