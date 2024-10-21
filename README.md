# JSON Signature

The `jsonsign` library provides functionality to digitally sign JSON data using RSA cryptography. It allows users to:

- **Sign JSON Files**: It creates a secure signature for a given JSON document, ensuring the integrity and authenticity of the data. The signature is appended to the original JSON object without altering the data structure or content.
- **Validate JSON Signatures**: It verifies the authenticity of the signed JSON document by checking the validity of the signature against the public key. This process ensures that the JSON data has not been tampered with and originates from a trusted source.
- **Deterministic Serialization**: The library ensures that the JSON data is serialized in a consistent manner before signing, preventing issues related to key ordering or formatting that could invalidate the signature.

The library is suitable for applications that require secure communication of JSON data, ensuring both integrity and authenticity through cryptographic signatures.


## Build
```sh
make
```

## Create keys

```sh
make keys
```

## Usage

### Sign

```sh
./bin/sign -priv private.key -json myfile.json
```

### Validate

```sh
./bin/validate -pub public.key -json myfile.json
```