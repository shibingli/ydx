import assert from 'node:assert/strict';
import { createHmac } from 'node:crypto';
import { test } from 'node:test';

import { CaptchaError, createClient, verifyToken } from '../index.js';

function tokenFor(secret, claims, kid = 'k1') {
  const payload = Buffer.from(JSON.stringify(claims)).toString('base64url');
  const body = `v1.${kid}.${payload}`;
  const signature = createHmac('sha256', Buffer.from(secret)).update(body).digest('base64url');
  return `${body}.${signature}`;
}

const claims = () => ({
  cid: 'c1',
  act: 'login',
  iat: 1,
  exp: Math.floor(Date.now() / 1000) + 60,
  risk: 0,
  jti: 'j1'
});

test('requires an absolute endpoint', () => {
  assert.throws(
    () => createClient({ endpoint: '/captcha', fetch: async () => ({}) }),
    (err) => err instanceof CaptchaError && err.code === 'invalid_options'
  );
});

test('maps transport failures to CaptchaError', async () => {
  const client = createClient({
    endpoint: 'https://app.example.test/captcha',
    fetch: async () => {
      throw new TypeError('fetch failed');
    }
  });
  await assert.rejects(
    () => client.challenge({ action: 'login' }),
    (err) => err instanceof CaptchaError && err.code === 'network_error'
  );
});

test('timeout also covers a stalled response body', async () => {
  const client = createClient({
    endpoint: 'https://app.example.test/captcha',
    timeout: 40,
    fetch: async (_url, init) => ({
      ok: true,
      status: 200,
      json: () => new Promise((_resolve, reject) => {
        init.signal.addEventListener('abort', () => {
          const err = new Error('aborted');
          err.name = 'AbortError';
          reject(err);
        });
      })
    })
  });
  const started = Date.now();
  await assert.rejects(
    () => client.challenge({ action: 'login' }),
    (err) => err instanceof CaptchaError && err.code === 'timeout'
  );
  assert.ok(Date.now() - started < 1000);
});

test('unknown kid never falls back to secret or prototype properties', () => {
  const secret = '0123456789abcdef0123456789abcdef';
  const unknown = tokenFor(secret, claims(), 'missing');
  assert.throws(
    () => verifyToken(unknown, 'login', { keys: { k1: secret }, secret }),
    (err) => err instanceof CaptchaError && err.code === 'invalid_token'
  );
  const prototype = tokenFor(secret, claims(), 'toString');
  assert.throws(
    () => verifyToken(prototype, 'login', { keys: {}, secret }),
    (err) => err instanceof CaptchaError && err.code === 'invalid_token'
  );
});

test('configured key IDs verify tokens', () => {
  const secret = '0123456789abcdef0123456789abcdef';
  const token = tokenFor(secret, claims(), 'k2');
  assert.equal(verifyToken(token, 'login', { keys: { k2: secret } }).cid, 'c1');
});

test('client locale is applied unless the call overrides it', async () => {
  const bodies = [];
  const client = createClient({
    endpoint: 'https://app.example.test/captcha',
    locale: 'ja-JP',
    fetch: async (_url, init) => {
      bodies.push(JSON.parse(init.body));
      return { ok: true, status: 200, json: async () => ({ ok: true, challenge: { id: 'c1' } }) };
    }
  });
  await client.challenge({ action: 'login' });
  await client.challenge({ action: 'login', locale: 'de' });
  assert.equal(bodies[0].locale, 'ja-JP');
  assert.equal(bodies[1].locale, 'de');
});
