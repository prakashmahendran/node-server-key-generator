# Node Server Key Generator

A Node.js utility to generate mutual TLS certificates and elliptic curve (EC) JWK key sets (JWKS) for secure server-to-server communication and JWT-based authentication.

## Features

- 🔐 Generate mutual TLS (mTLS) certificates with custom SANs
- 🔑 Generate ES256 JWK key pairs for JWT signing
- 📦 Automated CA and certificate generation
- ⚙️ Configurable via environment variables
- 🛡️ Secure key storage with encrypted private keys

## Prerequisites

- Node.js >= 18.0.0
- OpenSSL (for TLS certificate generation)

## Installation

```bash
npm install
```

## Usage

### Generate Both TLS Certificates and JWK Keys

```bash
npm run generate
```

### Generate TLS Certificates Only

```bash
npm run generate:tls
```

### Generate JWK Keys Only

```bash
npm run generate:jwk
```

## Configuration

Create a `.env` file in the root directory to customize generation:

```env
# TLS Certificate Configuration
KEY_DIR=keys                 # Directory to store generated keys
CN=internal-service          # Common Name for certificate
SAN_DNS=localhost            # DNS Subject Alternative Name
SAN_IP=127.0.0.1            # IP Subject Alternative Name
```

## Generated Files

### TLS Certificates (in `keys/` directory)

- `tls-ca-key.pem` - Root CA private key
- `tls-ca-cert.pem` - Root CA certificate
- `tls-shared-key.pem` - Service private key (encrypted)
- `tls-shared-cert.pem` - Service certificate
- `tls-shared-key-passphrase.txt` - Passphrase for encrypted private key
- `openssl.cnf` - OpenSSL configuration used

### JWK Keys (in `keys/` directory)

- `jwks.json` - Public JWK Set (for distribution)
- `jwks-private-key.pem` - Private key in PEM format

## Security Considerations

⚠️ **Important**: 
- Never commit the `keys/` directory to version control
- Store private keys securely
- Rotate keys regularly
- Use strong passphrases for encrypted keys

## Algorithm Details

### TLS Certificates
- CA: RSA 4096-bit
- Service Key: RSA 2048-bit with AES-256 encryption
- Signature: SHA-256
- Validity: 825 days (service cert), 10 years (CA cert)

### JWK
- Algorithm: ES256 (ECDSA with P-256 curve and SHA-256)
- Key Usage: Digital signature
- Key ID: Generated from public key components using SHA-256

## Example Output

```bash
$ npm run generate

[*] Generating Root CA...
[*] Generating shared passphrase and saving to file...
[*] Generating shared private key...
[*] Creating OpenSSL config with SANs...
[*] Creating CSR with SANs...
[*] Signing certificate with CA and SANs...
[✔] Shared certificate and key generated.
✅ JWK and PEM private key files generated:
- jwks.json
- jwks-private-key.pem
```

## License

ISC
