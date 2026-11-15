/**
 * Generates Self-Signed X.509 TLS Certificates for Zero-Trust Localhost Lab
 */
const fs = require('fs');
const path = require('path');
const selfsigned = require('../node-express/node_modules/selfsigned');

async function generateCerts() {
  const certDir = path.join(__dirname, '..', 'certs');
  if (!fs.existsSync(certDir)) {
    fs.mkdirSync(certDir, { recursive: true });
  }

  console.log('[TLS SETUP] Generating 2048-bit RSA Self-Signed Certificate for Zero-Trust Enterprise Lab...');

  const attrs = [
    { name: 'commonName', value: 'localhost' },
    { name: 'countryName', value: 'US' },
    { shortName: 'ST', value: 'California' },
    { name: 'localityName', value: 'Enterprise Lab' },
    { name: 'organizationName', value: 'Zero Trust Security Lab' },
    { shortName: 'OU', value: 'Cybersecurity Engineering' },
  ];

  const pems = await selfsigned.generate(attrs, {
    algorithm: 'sha256',
    days: 365,
    keySize: 2048,
    extensions: [
      {
        name: 'basicConstraints',
        cA: true,
      },
      {
        name: 'keyUsage',
        keyCertSign: true,
        digitalSignature: true,
        nonRepudiation: true,
        keyEncipherment: true,
        dataEncipherment: true,
      },
      {
        name: 'subjectAltName',
        altNames: [
          { type: 2, value: 'localhost' },
          { type: 2, value: 'auth-service' },
          { type: 2, value: 'app-api' },
          { type: 7, ip: '127.0.0.1' },
        ],
      },
    ],
  });

  fs.writeFileSync(path.join(certDir, 'server.key'), pems.private, { encoding: 'utf8' });
  fs.writeFileSync(path.join(certDir, 'server.crt'), pems.cert, { encoding: 'utf8' });

  console.log('[TLS SETUP] Success! Certificates created:');
  console.log(` - Private Key:  ${path.join(certDir, 'server.key')}`);
  console.log(` - Certificate:  ${path.join(certDir, 'server.crt')}`);
  console.log('[TLS SETUP] Lab TLS Encryption In-Transit ready.');
}

generateCerts().catch((err) => {
  console.error('[TLS SETUP FAILED]', err);
  process.exit(1);
});
