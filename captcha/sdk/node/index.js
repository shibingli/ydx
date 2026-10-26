import { createHash, createHmac, timingSafeEqual } from 'node:crypto';

export class CaptchaError extends Error {
  constructor(message, code, status, retryAfter) {
    super(message);
    this.name = 'CaptchaError';
    this.code = code || 'request_failed';
    this.status = status || 0;
    this.retryAfter = retryAfter || 0;
  }
}

function joinURL(endpoint, path) {
  if (/^https?:\/\//i.test(path)) return path;
  return `${String(endpoint || '/captcha').replace(/\/+$/, '')}/${String(path || '').replace(/^\/+/, '')}`;
}

function errorFrom(data, status) {
  return new CaptchaError(
    data?.error?.message || 'captcha request failed',
    data?.error?.code || 'request_failed',
    status,
    data?.error?.retry_after || 0
  );
}

async function requestJSON(fetchImpl, url, body, headers, timeout) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeout);
  let response;
  let data;
  try {
    response = await fetchImpl(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', ...headers },
      body: JSON.stringify(body || {}),
      signal: controller.signal
    });
    // Keep the timer active while the body is read: a stalled response body
    // must not outlive the configured timeout. | 读取响应体期间保持定时器有效，
    // 慢速或停滞的响应体不能突破超时。
    data = await response.json();
  } catch (err) {
    if (err?.name === 'AbortError') {
      throw new CaptchaError('captcha request timed out', 'timeout', 0, 0);
    }
    if (err instanceof CaptchaError) throw err;
    throw new CaptchaError('captcha request failed', 'network_error', response?.status || 0, 0);
  } finally {
    clearTimeout(timer);
  }
  if (!response.ok || !data?.ok) throw errorFrom(data, response.status);
  return data;
}

function leadingZeroBits(digest) {
  let count = 0;
  for (const byte of digest) {
    if (byte === 0) {
      count += 8;
      continue;
    }
    let mask = 128;
    while ((byte & mask) === 0) {
      count++;
      mask >>= 1;
    }
    return count;
  }
  return count;
}

export async function solvePoW(pow) {
  if (!pow || pow.algorithm !== 'sha256' || !pow.seed) {
    throw new CaptchaError('unsupported proof of work', 'pow_unsupported', 0, 0);
  }
  const difficulty = Number(pow.difficulty || 0);
  let nonce = 0;
  while (nonce < 0xffffffff) {
    const digest = createHash('sha256').update(`${pow.seed}:${nonce}`).digest();
    if (leadingZeroBits(digest) >= difficulty) return { nonce };
    nonce++;
    if ((nonce & 4095) === 0) await new Promise((resolve) => setImmediate(resolve));
  }
  throw new CaptchaError('proof of work exhausted', 'pow_exhausted', 0, 0);
}

function tokenKey(options, kid) {
  const keys = options.keys;
  if (keys && typeof keys === 'object') {
    if (!Object.prototype.hasOwnProperty.call(keys, kid)) return null;
    const value = keys[kid];
    if (typeof value !== 'string' && !Buffer.isBuffer(value) && !(value instanceof Uint8Array)) {
      throw new CaptchaError('invalid token key', 'invalid_token', 0, 0);
    }
    return Buffer.from(value);
  }
  if (options.secret) return Buffer.from(options.secret);
  return null;
}

export function verifyToken(token, action, options = {}) {
  if (typeof token !== 'string') throw new CaptchaError('invalid token', 'invalid_token', 0, 0);
  const parts = token.split('.');
  if (parts.length !== 4 || parts[0] !== 'v1') {
    throw new CaptchaError('invalid token', 'invalid_token', 0, 0);
  }
  const key = tokenKey(options, parts[1]);
  if (!key) throw new CaptchaError('token key is not configured', 'invalid_token', 0, 0);
  const expected = createHmac('sha256', key)
    .update(`${parts[0]}.${parts[1]}.${parts[2]}`)
    .digest();
  let supplied;
  try {
    supplied = Buffer.from(parts[3], 'base64url');
  } catch {
    throw new CaptchaError('invalid token', 'invalid_token', 0, 0);
  }
  if (supplied.length !== expected.length || !timingSafeEqual(supplied, expected)) {
    throw new CaptchaError('invalid token', 'invalid_token', 0, 0);
  }
  let claims;
  try {
    claims = JSON.parse(Buffer.from(parts[2], 'base64url').toString('utf8'));
  } catch {
    throw new CaptchaError('invalid token', 'invalid_token', 0, 0);
  }
  if (claims.act !== action) throw new CaptchaError('invalid token action', 'invalid_token', 0, 0);
  if (options.issuer && claims.iss !== options.issuer) {
    throw new CaptchaError('invalid token issuer', 'invalid_token', 0, 0);
  }
  const now = Math.floor(Date.now() / 1000);
  if (!Number.isFinite(claims.exp) || now >= claims.exp) {
    throw new CaptchaError('token expired', 'token_expired', 0, 0);
  }
  return claims;
}

export function createClient(options = {}) {
  const endpoint = options.endpoint || '/captcha';
  if (!/^https?:\/\//i.test(String(endpoint))) {
    throw new CaptchaError('endpoint must be an absolute http(s) URL', 'invalid_options', 0, 0);
  }
  const fetchImpl = options.fetch || globalThis.fetch;
  if (typeof fetchImpl !== 'function') throw new TypeError('fetch is required');
  const headers = options.headers || {};
  const defaultLocale = options.locale ? String(options.locale) : '';
  const timeout = Number(options.timeout || 15000);
  if (!Number.isFinite(timeout) || timeout <= 0) {
    throw new CaptchaError('timeout must be a positive number', 'invalid_options', 0, 0);
  }

  async function call(path, body) {
    const payload = defaultLocale && body?.locale === undefined ? { ...(body || {}), locale: defaultLocale } : body;
    const data = await requestJSON(fetchImpl, joinURL(endpoint, path), payload, headers, timeout);
    return data;
  }

  return {
    endpoint,
    async challenge(body = {}) {
      const data = await call('challenge', body);
      return data.challenge;
    },
    async verify(body = {}) {
      const data = await call('verify', body);
      return data.result;
    },
    async send(body = {}) {
      const data = await call('send', body);
      return data.challenge;
    },
    async consume(body = {}) {
      const data = await call('token/consume', body);
      return data.claims;
    },
    verifyToken(token, action) {
      return verifyToken(token, action, {
        secret: options.secret,
        keys: options.keys,
        issuer: options.issuer
      });
    },
    solvePoW
  };
}
