/**
 * Sonde quelles valeurs de `client_id` et `deviceType` Vaultwarden accepte.
 *
 * Objectif : déterminer jusqu'où Zwarden peut s'identifier sous son propre nom
 * plutôt que de se faire passer pour un client Bitwarden.
 *
 * Usage :
 *   ZWARDEN_TEST_SERVER=... ZWARDEN_TEST_EMAIL=... ZWARDEN_TEST_PASSWORD=... \
 *   node scripts/sonde-client-id.mjs
 */

import { webcrypto as crypto } from 'node:crypto';

const SERVER = process.env.ZWARDEN_TEST_SERVER;
const EMAIL = process.env.ZWARDEN_TEST_EMAIL?.trim().toLowerCase();
const PASSWORD = process.env.ZWARDEN_TEST_PASSWORD;

if (!SERVER || !EMAIL || !PASSWORD) {
  console.error('Variables ZWARDEN_TEST_* requises.');
  process.exit(1);
}

const enc = new TextEncoder();

async function pbkdf2(password, salt, iterations) {
  const key = await crypto.subtle.importKey('raw', password, 'PBKDF2', false, ['deriveBits']);
  return new Uint8Array(
    await crypto.subtle.deriveBits(
      { name: 'PBKDF2', salt, iterations, hash: 'SHA-256' },
      key,
      256,
    ),
  );
}

const b64 = (bytes) => Buffer.from(bytes).toString('base64');

// Dérivation, une seule fois : c'est l'opération coûteuse.
const prelogin = await (
  await fetch(`${SERVER}/identity/accounts/prelogin`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email: EMAIL }),
  })
).json();

const masterKey = await pbkdf2(
  enc.encode(PASSWORD.normalize('NFKD')),
  enc.encode(EMAIL),
  prelogin.kdfIterations,
);
const passwordHash = b64(await pbkdf2(masterKey, enc.encode(PASSWORD.normalize('NFKD')), 1));

const authEmail = Buffer.from(EMAIL, 'utf8')
  .toString('base64')
  .replace(/\+/g, '-')
  .replace(/\//g, '_')
  .replace(/=+$/, '');

async function essai(label, overrides) {
  const form = new URLSearchParams({
    grant_type: 'password',
    username: EMAIL,
    password: passwordHash,
    scope: 'api offline_access',
    client_id: 'browser',
    deviceType: '2',
    deviceIdentifier: '00000000-0000-4000-8000-0000000000aa',
    deviceName: 'zwarden',
    ...overrides,
  });

  const response = await fetch(`${SERVER}/identity/connect/token`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded',
      'Auth-Email': authEmail,
    },
    body: form.toString(),
  });

  const body = await response.text();
  let détail = '';
  if (!response.ok) {
    try {
      const json = JSON.parse(body);
      détail = ` — ${json.error_description ?? json.error ?? body.slice(0, 90)}`;
    } catch {
      détail = ` — ${body.slice(0, 90)}`;
    }
  }

  const verdict = response.ok ? 'ACCEPTÉ' : 'REFUSÉ ';
  console.log(`  ${verdict}  ${label}${détail}`);
  return response.ok;
}

console.log(`Serveur : ${SERVER}`);
console.log(`KDF     : type ${prelogin.kdf}, ${prelogin.kdfIterations} itérations\n`);

console.log('client_id :');
for (const id of ['browser', 'zwarden', 'desktop', 'cli', 'web', 'mobile', 'inventé-xyz', '']) {
  await essai(`client_id="${id}"`, { client_id: id });
}

console.log('\ndeviceType :');
for (const type of ['2', '3', '14', '21', '99', '']) {
  await essai(`deviceType="${type}"`, { deviceType: type });
}

console.log('\nscope :');
for (const scope of ['api offline_access', 'api', '']) {
  await essai(`scope="${scope}"`, { scope });
}

console.log('\nen-tête Auth-Email :');
{
  const form = new URLSearchParams({
    grant_type: 'password',
    username: EMAIL,
    password: passwordHash,
    scope: 'api offline_access',
    client_id: 'zwarden',
    deviceType: '2',
    deviceIdentifier: '00000000-0000-4000-8000-0000000000aa',
    deviceName: 'zwarden',
  });
  const response = await fetch(`${SERVER}/identity/connect/token`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: form.toString(),
  });
  console.log(`  ${response.ok ? 'ACCEPTÉ' : 'REFUSÉ '}  sans en-tête Auth-Email`);
}
