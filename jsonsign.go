package jsonsign

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
	"sort"
)

// JsonSign containt keys path
type JsonSign struct {
	privateKeyFilePath string
	publicKeyFilePath  string
}

// New create new instance of JsonSign
func New(options ...func(*JsonSign)) *JsonSign {
	js := &JsonSign{}

	for _, option := range options {
		option(js)
	}

	return js
}

// WithPublicKeyFilePath give the public key file path
func WithPublicKeyFilePath(publicKeyFilePath string) func(*JsonSign) {
	return func(js *JsonSign) {
		js.publicKeyFilePath = publicKeyFilePath
	}
}

// WithPrivateKeyFilePath give the private key file path
func WithPrivateKeyFilePath(privateKeyFilePath string) func(*JsonSign) {
	return func(js *JsonSign) {
		js.privateKeyFilePath = privateKeyFilePath
	}
}

// Sign the JSON file and add a signature
func (js *JsonSign) Sign(jsonFilePath string) error {
	if err := validateFilePath(jsonFilePath); err != nil {
		return fmt.Errorf("cannot validate json file path: %s", err)
	}

	// Load the private key
	privateKey, err := loadPrivateKey(js.privateKeyFilePath)
	if err != nil {
		return fmt.Errorf("cannot load private key: %s", err)
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

	// Serialize the JSON in a stable, deterministic way
	stableJson, err := toStableJson(jsonMap)
	if err != nil {
		return fmt.Errorf("cannot serialize json deterministically: %s", err)
	}

	// Create a hash of the stable JSON
	hashed := sha256.Sum256(stableJson)

	// Sign the hash using RSA
	signature, err := rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA256, hashed[:])
	if err != nil {
		return fmt.Errorf("cannot sign json: %s", err)
	}

	// Encode the signature in base64
	signatureBase64 := base64.StdEncoding.EncodeToString(signature)

	// Add the signature to the original JSON map
	jsonMap["signature"] = signatureBase64

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

	// Load the public key
	publicKey, err := loadPublicKey(js.publicKeyFilePath)
	if err != nil {
		return fmt.Errorf("cannot load public key: %s", err)
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

	// Extract the signature from the JSON
	signatureBase64, ok := jsonMap["signature"].(string)
	if !ok {
		return fmt.Errorf("no signature found in json")
	}

	// Remove the signature field for validation
	delete(jsonMap, "signature")

	// Serialize the JSON in a stable, deterministic way
	stableJson, err := toStableJson(jsonMap)
	if err != nil {
		return fmt.Errorf("cannot serialize json deterministically: %s", err)
	}

	// Create a hash of the stable JSON
	hashed := sha256.Sum256(stableJson)

	// Decode the base64 signature
	signature, err := base64.StdEncoding.DecodeString(signatureBase64)
	if err != nil {
		return fmt.Errorf("cannot decode signature: %s", err)
	}

	// Verify the signature
	err = rsa.VerifyPKCS1v15(publicKey, crypto.SHA256, hashed[:], signature)
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

// loadPrivateKey load private key from file
func loadPrivateKey(filename string) (*rsa.PrivateKey, error) {
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

// loadPublicKey load public key from file
func loadPublicKey(filename string) (*rsa.PublicKey, error) {
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
