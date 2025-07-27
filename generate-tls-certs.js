import { mkdirSync, writeFileSync } from "fs";
import { chdir } from "process";
import path from "path";
import { execSync } from "child_process";
import dotenv from "dotenv";

dotenv.config();

const KEY_DIR = process.env.KEY_DIR || "keys";
const CN = process.env.CN || "internal-service";
const SAN_DNS = process.env.SAN_DNS || "localhost";
const SAN_IP = process.env.SAN_IP || "127.0.0.1";

mkdirSync(KEY_DIR, { recursive: true });
chdir(KEY_DIR);

console.log("[*] Generating Root CA...");
execSync(`openssl genrsa -out tls-ca-key.pem 4096`);
execSync(
  `openssl req -x509 -new -key tls-ca-key.pem -sha256 -days 3650 -out tls-ca-cert.pem -subj "/CN=internal-ca"`
);

console.log("[*] Generating shared passphrase and saving to file...");
const passphrase = execSync(`openssl rand -base64 16`).toString().trim();
writeFileSync("tls-shared-key-passphrase.txt", passphrase);

console.log("[*] Generating shared private key...");
execSync(
  `openssl genrsa -aes256 -passout pass:${passphrase} -out tls-shared-key.pem 2048`
);

console.log("[*] Creating OpenSSL config with SANs...");
const opensslCnf = `
[req]
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

writeFileSync("openssl.cnf", opensslCnf);

console.log("[*] Creating CSR with SANs...");
execSync(
  `openssl req -new -key tls-shared-key.pem -out tls-shared.csr -subj "/CN=${CN}" -passin pass:${passphrase} -config openssl.cnf`
);

console.log("[*] Signing certificate with CA and SANs...");
execSync(
  `openssl x509 -req -in tls-shared.csr -CA tls-ca-cert.pem -CAkey tls-ca-key.pem -CAcreateserial -out tls-shared-cert.pem -days 825 -sha256 -extfile openssl.cnf -extensions v3_req`
);

console.log("[✔] Shared certificate and key generated.");
