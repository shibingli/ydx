import assert from 'node:assert/strict';
import { createRequire } from 'node:module';
import { test } from 'node:test';

const require = createRequire(import.meta.url);
const YdCaptcha = require('../dist/yd-captcha.js');

test('exports a version and mount function', () => {
  assert.equal(typeof YdCaptcha.version, 'string');
  assert.equal(typeof YdCaptcha.mount, 'function');
});

test('mount without a DOM explains the failure', () => {
  assert.throws(() => YdCaptcha.mount('#captcha'), /browser DOM/);
});

test('SHA-256 matches the FIPS test vector', () => {
  const digest = YdCaptcha._sha256(Buffer.from('abc'));
  assert.equal(Buffer.from(digest).toString('hex'), 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad');
});

test('proof of work solves and verifies', async () => {
  const pow = { algorithm: 'sha256', seed: '00112233445566778899aabbccddeeff', difficulty: 8 };
  const proof = await YdCaptcha.solvePoW(pow);
  assert.ok(Number.isInteger(proof.nonce));
  const digest = YdCaptcha._sha256(Buffer.from(`${pow.seed}:${proof.nonce}`));
  assert.ok(YdCaptcha._leadingZeroBits(digest) >= pow.difficulty);
});

test('detects common screenshot shortcuts', () => {
  assert.equal(YdCaptcha._screenshotShortcut({ key: 'PrintScreen' }), 'screenshot_key');
  assert.equal(YdCaptcha._screenshotShortcut({ key: '4', metaKey: true, shiftKey: true }), 'screenshot_key');
  assert.equal(YdCaptcha._screenshotShortcut({ key: 's', ctrlKey: true, shiftKey: true }), 'screenshot_key');
  assert.equal(YdCaptcha._screenshotShortcut({ key: 'a' }), '');
});

test('ships locale catalogs and resolves regional tags', () => {
  assert.ok(YdCaptcha.locales.includes('ja'));
  assert.ok(YdCaptcha.locales.includes('zh-TW'));
  assert.equal(YdCaptcha.labels('ja').submit, '認証');
  assert.equal(YdCaptcha.labels('ja-JP').submit, '認証');
  assert.equal(YdCaptcha.labels('zh-HK').submit, '驗證');
  assert.equal(YdCaptcha.labels('fr-CA').submit, 'Vérifier');
  assert.equal(YdCaptcha._normalizeLocale('zh_Hant_TW'), 'zh-TW');
});

test('normalizes theme values', () => {
  assert.equal(YdCaptcha._normalizeTheme('system'), 'auto');
  assert.equal(YdCaptcha._normalizeTheme('DARK'), 'dark');
  assert.equal(YdCaptcha._normalizeTheme('light'), 'light');
  assert.equal(YdCaptcha._normalizeTheme('sepia'), 'auto');
});
