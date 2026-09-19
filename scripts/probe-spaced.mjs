/**
 * Re-probes the doubtful parameters, spacing the requests out.
 *
 * The first probe saturated Vaultwarden's rate limiter
 * (LOGIN_RATELIMIT_MAX_BURST, 10 by default), making its conclusions unusable
 * past the tenth request. So we space them out, and re-test a control value
 * known to be good on every round, to tell a genuine refusal from throttling.
 */

import { webcrypto as crypto } from 'node:crypto';

const SERVER = process.env.ZWARDEN_TEST_SERVER;
const EMAIL = process.env.ZWARDEN_TEST_EMAIL?.trim().toLowerCase();
const PASSWORD = process.env.ZWARDEN_TEST_PASSWORD;

const enc = new TextEncoder();
const pause = (ms) => new Promise((r) => setTimeout(r, ms));

async function pbkdf2(password, salt, iterations) {
  const key = await crypto.subtle.importKey('raw', password, 'PBKDF2', false, ['deriveBits']);
  return new Uint8Array(
    await crypto.subtle.deriveBits({ name: 'PBKDF2', salt, iterations, hash: 'SHA-256' }, key, 256),
  );
}

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
const passwordHash = Buffer.from(
  await pbkdf2(masterKey, enc.encode(PASSWORD.normalize('NFKD')), 1),
).toString('base64');

const authEmail = Buffer.from(EMAIL, 'utf8')
  .toString('base64')
  .replace(/\+/g, '-')
  .replace(/\//g, '_')
  .replace(/=+$/, '');

async function attempt(overrides) {
  const form = new URLSearchParams({
    grant_type: 'password',
    username: EMAIL,
    password: passwordHash,
    scope: 'api offline_access',
    client_id: 'zwarden',
    deviceType: '2',
    deviceIdentifier: '00000000-0000-4000-8000-0000000000bb',
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
  return { ok: response.ok, status: response.status, body: body.slice(0, 200) };
}

// Every case is preceded by a known-good control. If the control fails, the
// tested case's result cannot be interpreted.
const cas = [
  ['client_id="zwarden", deviceType=2', {}],
  ['deviceType="99"', { deviceType: '99' }],
  ['scope="api"', { scope: 'api' }],
];

console.log(`Serveur : ${SERVER}\n`);

for (const [label, overrides] of cas) {
  await pause(12_000);
  const control = await attempt({});
  await pause(12_000);
  const result = await attempt(overrides);

  if (!control.ok) {
    console.log(`  INCONCLUSIVE  ${label} — control failed (${control.status}), throttling`);
    continue;
  }

  console.log(
    `  ${result.ok ? 'ACCEPTED' : 'REFUSED '}  ${label}` +
      (result.ok ? '' : ` — HTTP ${result.status} ${result.body}`),
  );
}
