/**
 * Demo helper: simulates a user forwarding an email to the local SMTP intake
 * address (analyze@<SMTP_DOMAIN>, default port 2525), exactly as a mail
 * client configured with a custom SMTP account pointed at localhost would.
 *
 * A real external mail server (Gmail, Outlook, etc.) cannot forward to this
 * address on its own — phishing-forensics.local only resolves on this
 * machine. This script (or a locally-configured mail client) is the way to
 * demonstrate the "Forward Email" ingestion path without public DNS/MX setup.
 *
 * Usage:
 *   node server/scripts/sendTestForward.js [path/to/email.eml]
 * Defaults to the bundled paypal-phishing.eml sample.
 */
import net from 'net';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import 'dotenv/config';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const PORT   = parseInt(process.env.SMTP_PORT || '2525');
const DOMAIN = process.env.SMTP_DOMAIN || 'phishing-forensics.local';

const emlPath = process.argv[2]
  ? path.resolve(process.argv[2])
  : path.join(__dirname, '../test/samples/paypal-phishing.eml');

const rawEmail = fs.readFileSync(emlPath, 'utf8');

function talk(socket, line) {
  return new Promise(resolve => {
    socket.once('data', data => resolve(data.toString().trim()));
    socket.write(line + '\r\n');
  });
}

console.log(`Forwarding "${path.basename(emlPath)}" to analyze@${DOMAIN} via localhost:${PORT} ...\n`);

const socket = net.createConnection(PORT, 'localhost', async () => {
  const banner = await new Promise(r => socket.once('data', d => r(d.toString().trim())));
  console.log('<', banner);
  console.log('<', await talk(socket, 'HELO demo-client'));
  console.log('<', await talk(socket, 'MAIL FROM:<demo-user@gmail.com>'));
  console.log('<', await talk(socket, `RCPT TO:<analyze@${DOMAIN}>`));
  console.log('<', await talk(socket, 'DATA'));
  console.log('<', await talk(socket, rawEmail.replace(/\n/g, '\r\n') + '\r\n.'));
  console.log('<', await talk(socket, 'QUIT'));
  socket.end();
  console.log('\nSent. Check the dashboard\'s "Forward Email" tab, or GET /api/smtp/status, for the result.');
});

socket.on('error', err => {
  console.error(`Could not connect to localhost:${PORT} — is the backend (npm run dev:server) running?`);
  console.error(err.message);
  process.exit(1);
});
