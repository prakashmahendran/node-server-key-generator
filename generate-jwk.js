import { generateKeyPair, exportJWK, exportPKCS8 } from "jose";
import { writeFile } from "fs/promises";
import { createHash } from "crypto";

/**
 * Generate a JWK-compliant key ID (kid) from the public key components.
 */
function generateKid(jwk) {
  const input = `${jwk.kty}-${jwk.crv}-${jwk.x}-${jwk.y}`;
  return createHash("sha256").update(input).digest("base64url");
}

const alg = "ES256";

const { publicKey, privateKey } = await generateKeyPair(alg, {
  extractable: true,
});

const publicJwk = await exportJWK(publicKey);
const privateJwk = await exportJWK(privateKey);
const privatePem = await exportPKCS8(privateKey);

// Set metadata and generate kid
const kid = generateKid(publicJwk);
publicJwk.kid = privateJwk.kid = kid;
publicJwk.alg = privateJwk.alg = alg;
publicJwk.use = privateJwk.use = "sig";

// Write JWKS
await writeFile(
  "./keys/jwks.json",
  JSON.stringify({ keys: [publicJwk] }, null, 2),
  "utf8"
);

// Write Private PEM
await writeFile("./keys/jwks-private-key.pem", privatePem, "utf8");

console.log("✅ JWK and PEM private key files generated:");
console.log("- jwks.json");
console.log("- jwks-private-key.pem");
