/**
 * JWK Key Generator
 * 
 * Generates ES256 (ECDSA with P-256 curve) JSON Web Key (JWK) pairs for JWT signing.
 * 
 * Output:
 * - jwks.json: Public JWK Set for distribution
 * - jwks-private-key.pem: Private key in PEM format for signing
 * 
 * @module generate-jwk
 */

import { generateKeyPair, exportJWK, exportPKCS8 } from 'jose';
import { writeFile, mkdir } from 'fs/promises';
import { createHash } from 'crypto';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

// Constants
const ALGORITHM = 'ES256';
const KEY_USE = 'sig';
const KEYS_DIR = join(__dirname, 'keys');
const JWKS_PATH = join(KEYS_DIR, 'jwks.json');
const PRIVATE_KEY_PATH = join(KEYS_DIR, 'jwks-private-key.pem');

/**
 * Generate a JWK-compliant key ID (kid) from the public key components.
 * The kid is a base64url-encoded SHA-256 hash of the key material.
 * 
 * @param {Object} jwk - The JWK object containing public key components
 * @param {string} jwk.kty - Key type (e.g., 'EC')
 * @param {string} jwk.crv - Curve name (e.g., 'P-256')
 * @param {string} jwk.x - X coordinate of the public key point
 * @param {string} jwk.y - Y coordinate of the public key point
 * @returns {string} Base64url-encoded SHA-256 hash as the key ID
 */
function generateKid(jwk) {
  const input = `${jwk.kty}-${jwk.crv}-${jwk.x}-${jwk.y}`;
  return createHash('sha256').update(input).digest('base64url');
}

/**
 * Main function to generate and save JWK key pair
 */
async function generateJWKKeyPair() {
  try {
    // Ensure keys directory exists
    await mkdir(KEYS_DIR, { recursive: true });

    // Generate ES256 key pair
    const { publicKey, privateKey } = await generateKeyPair(ALGORITHM, {
      extractable: true,
    });

    // Export keys to JWK format
    const publicJwk = await exportJWK(publicKey);
    const privateJwk = await exportJWK(privateKey);
    const privatePem = await exportPKCS8(privateKey);

    // Generate kid and set metadata
    const kid = generateKid(publicJwk);
    publicJwk.kid = kid;
    publicJwk.alg = ALGORITHM;
    publicJwk.use = KEY_USE;
    
    privateJwk.kid = kid;
    privateJwk.alg = ALGORITHM;
    privateJwk.use = KEY_USE;

    // Write public JWKS (only public key should be in JWKS)
    await writeFile(
      JWKS_PATH,
      JSON.stringify({ keys: [publicJwk] }, null, 2),
      'utf8'
    );

    // Write private key in PEM format
    await writeFile(PRIVATE_KEY_PATH, privatePem, 'utf8');

    console.log('✅ JWK and PEM private key files generated:');
    console.log('- jwks.json');
    console.log('- jwks-private-key.pem');
    console.log(`\nKey ID (kid): ${kid}`);
    console.log(`Algorithm: ${ALGORITHM}`);
  } catch (error) {
    console.error('❌ Error generating JWK key pair:', error.message);
    process.exit(1);
  }
}

// Execute
generateJWKKeyPair();
