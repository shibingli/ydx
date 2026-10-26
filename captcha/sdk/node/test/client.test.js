import assert from 'node:assert/strict';
import { createHmac } from 'node:crypto';
import { test } from 'node:test';

import { CaptchaError, createClient, solvePoW, verifyToken } from '../index.js';

function tokenFor(secret, claims, kid = 'k1') {
  const payload = Buffer.from(JSON.stringify(claims)).toString('base64url');
  const body = `v1.${kid}.${payload}`;
  const signature = createHmac('sha256', Buffer.from(secret)).update(body).digest('base64url');
  return `${body}.${signature}`;
}

test('challenge posts to the endpoint and returns the challenge', async () => {
  let captured;
  const client = createClient({
    endpoint: 'https://app.example.test/captcha',
    fetch: async (url, init) => {
      captured = { url, init };
      return {
        ok: true,
        status: 200,
        json: async () => ({ ok: true, challenge: { id: 'c1', type: 'text' } })
      };
    }
  });
  const challenge = await client.challenge({ action: 'login', type: 'text' });
  assert.equal(challenge.id, 'c1');
  assert.equal(captured.url, 'https://app.example.test/captcha/challenge');
  assert.equal(captured.init.method, 'POST');
  assert.equal(JSON.parse(captured.init.body).action, 'login');
});

test('maps API errors to CaptchaError', async () => {
  const client = createClient({
    endpoint: 'https://app.example.test/captcha',
    fetch: async () => ({
      ok: false,
      status: 429,
      json: async () => ({ ok: false, error: { code: 'rate_limited', message: 'slow down', retry_after: 2 } })
    })
  });
  await assert.rejects(
    () => client.challenge({ action: 'login' }),
    (err) => err instanceof CaptchaError && err.code === 'rate_limited' && err.retryAfter === 2
  );
});

test('verifyToken validates signature, action and expiry', () => {
  const secret = '0123456789abcdef0123456789abcdef';
  const claims = { cid: 'c1', act: 'login', iat: 1, exp: Math.floor(Date.now() / 1000) + 60, risk: 0, jti: 'j1' };
  const token = tokenFor(secret, claims);
  assert.equal(verifyToken(token, 'login', { secret }).cid, 'c1');
  assert.throws(() => verifyToken(token, 'register', { secret }), /invalid token action/);
  const expired = tokenFor(secret, { ...claims, exp: 1 });
  assert.throws(() => verifyToken(expired, 'login', { secret }), /token expired/);
  assert.throws(() => verifyToken(token.replace(/.$/, 'A'), 'login', { secret }), /invalid token/);
});

test('solvePoW produces a valid nonce', async () => {
  const pow = { algorithm: 'sha256', seed: '00112233445566778899aabbccddeeff', difficulty: 8 };
  const proof = await solvePoW(pow);
  assert.ok(Number.isInteger(proof.nonce));
});
