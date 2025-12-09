/**
 * TLS Certificate Generator
 * 
 * Generates mutual TLS (mTLS) certificates for secure server-to-server communication:
 * - Root CA certificate and key
 * - Service certificate and encrypted private key
 * - Subject Alternative Names (SANs) for DNS and IP addresses
 * 
 * Configuration via environment variables:
 * - KEY_DIR: Output directory (default: 'keys')
 * - CN: Common Name for service certificate (default: 'internal-service')
 * - SAN_DNS: DNS Subject Alternative Name (default: 'localhost')
 * - SAN_IP: IP Subject Alternative Name (default: '127.0.0.1')
 * 
 * @module generate-tls-certs
 */

import { mkdirSync, writeFileSync, existsSync } from 'fs';
import { chdir, cwd } from 'process';
import { execSync } from 'child_process';
import dotenv from 'dotenv';
import { fileURLToPath } from 'url';
import { dirname, join, resolve } from 'path';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

// Load environment variables
dotenv.config();

// Configuration constants
const KEY_DIR = process.env.KEY_DIR || 'keys';
const CN = process.env.CN || 'internal-service';
const SAN_DNS = process.env.SAN_DNS || 'localhost';
const SAN_IP = process.env.SAN_IP || '127.0.0.1';

// Certificate parameters
const CA_KEY_SIZE = 4096;
const SERVICE_KEY_SIZE = 2048;
const CA_VALIDITY_DAYS = 3650; // 10 years
const SERVICE_VALIDITY_DAYS = 825; // ~2.25 years (Apple requirement)
const PASSPHRASE_LENGTH = 16;

/**
 * Execute a shell command with error handling
 * @param {string} command - Command to execute
 * @param {string} description - Human-readable description of the command
 * @throws {Error} If command execution fails
 */
function executeCommand(command, description) {
  try {
    execSync(command, { stdio: 'pipe' });
  } catch (error) {
    console.error(`❌ Failed to ${description}:`, error.message);
    throw error;
  }
}

/**
 * Generate OpenSSL configuration with Subject Alternative Names
 * @returns {string} OpenSSL configuration content
 */
function generateOpenSSLConfig() {
  return `[req]
distinguished_name = req_distinguished_name
x509_extensions = v3_req
prompt = no

[req_distinguished_name]
CN = ${CN}

[v3_req]
basicConstraints = CA:FALSE
keyUsage = digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth, clientAuth
subjectAltName = @alt_names

[alt_names]
DNS.1 = ${CN}
DNS.2 = ${SAN_DNS}
IP.1 = ${SAN_IP}
`;
}

/**
 * Main function to generate TLS certificates
 */
function generateTLSCertificates() {
  try {
    const originalDir = cwd();
    const keyDirPath = resolve(__dirname, KEY_DIR);

    // Create keys directory
    mkdirSync(keyDirPath, { recursive: true });
    chdir(keyDirPath);

    // Generate Root CA
    console.log('[*] Generating Root CA...');
    executeCommand(
      `openssl genrsa -out tls-ca-key.pem ${CA_KEY_SIZE}`,
      'generate CA private key'
    );
    executeCommand(
      `openssl req -x509 -new -key tls-ca-key.pem -sha256 -days ${CA_VALIDITY_DAYS} -out tls-ca-cert.pem -subj "/CN=internal-ca"`,
      'generate CA certificate'
    );

    // Generate and save passphrase
    console.log('[*] Generating shared passphrase and saving to file...');
    const passphrase = execSync(`openssl rand -base64 ${PASSPHRASE_LENGTH}`)
      .toString()
      .trim();
    writeFileSync('tls-shared-key-passphrase.txt', passphrase);

    // Generate service private key (encrypted)
    console.log('[*] Generating shared private key...');
    executeCommand(
      `openssl genrsa -aes256 -passout pass:${passphrase} -out tls-shared-key.pem ${SERVICE_KEY_SIZE}`,
      'generate encrypted service private key'
    );

    // Create OpenSSL config
    console.log('[*] Creating OpenSSL config with SANs...');
    const opensslConfig = generateOpenSSLConfig();
    writeFileSync('openssl.cnf', opensslConfig);

    // Create CSR
    console.log('[*] Creating CSR with SANs...');
    executeCommand(
      `openssl req -new -key tls-shared-key.pem -out tls-shared.csr -subj "/CN=${CN}" -passin pass:${passphrase} -config openssl.cnf`,
      'create certificate signing request'
    );

    // Sign certificate
    console.log('[*] Signing certificate with CA and SANs...');
    executeCommand(
      `openssl x509 -req -in tls-shared.csr -CA tls-ca-cert.pem -CAkey tls-ca-key.pem -CAcreateserial -out tls-shared-cert.pem -days ${SERVICE_VALIDITY_DAYS} -sha256 -extfile openssl.cnf -extensions v3_req`,
      'sign service certificate'
    );

    console.log('[✔] TLS certificates generated successfully.');
    console.log(`\nGenerated files in ${keyDirPath}:`);
    console.log('- tls-ca-cert.pem (Root CA certificate)');
    console.log('- tls-ca-key.pem (Root CA private key)');
    console.log('- tls-shared-cert.pem (Service certificate)');
    console.log('- tls-shared-key.pem (Encrypted service private key)');
    console.log('- tls-shared-key-passphrase.txt (Key passphrase)');

    // Return to original directory
    chdir(originalDir);
  } catch (error) {
    console.error('❌ Error generating TLS certificates:', error.message);
    process.exit(1);
  }
}

// Check for OpenSSL
if (!existsSync('/usr/bin/openssl') && !existsSync('/usr/local/bin/openssl')) {
  try {
    execSync('which openssl', { stdio: 'pipe' });
  } catch {
    console.error('❌ OpenSSL not found. Please install OpenSSL and try again.');
    process.exit(1);
  }
}

// Execute
generateTLSCertificates();
