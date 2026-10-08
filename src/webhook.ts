/**
 * Verify a Cbox ID webhook / inline-action signature. The header is
 * `X-Cbox-Signature: t={unix},v1={hex hmac}` — an HMAC-SHA256 over
 * `"{timestamp}.{raw body}"`, valid within a freshness window. Built on Web Crypto
 * so it runs on Node, edge and the browser.
 */

/** Constant-time compare of two hex strings. */
function timingSafeEqual(a: string, b: string): boolean {
  if (a.length !== b.length) {
    return false;
  }
  let mismatch = 0;
  for (let i = 0; i < a.length; i++) {
    mismatch |= a.charCodeAt(i) ^ b.charCodeAt(i);
  }
  return mismatch === 0;
}

function toHex(bytes: ArrayBuffer): string {
  return Array.from(new Uint8Array(bytes))
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

export interface VerifyWebhookOptions {
  /** The RAW request body — the exact bytes received, not a re-encoded copy. */
  payload: string;
  /** The value of the `X-Cbox-Signature` header. */
  signatureHeader: string | null | undefined;
  /** The signing secret issued when the webhook/action endpoint was registered. */
  secret: string;
  /** Freshness window in seconds. Defaults to 300 (5 minutes). */
  toleranceSeconds?: number;
  /** Injectable clock (unix seconds), for tests. Defaults to `Date.now()`. */
  now?: number;
}

/** Returns `true` only when the signature is present, fresh and valid. Never throws. */
export async function verifyWebhook(options: VerifyWebhookOptions): Promise<boolean> {
  const { payload, signatureHeader, secret } = options;
  const toleranceSeconds = options.toleranceSeconds ?? 300;
  const now = options.now ?? Math.floor(Date.now() / 1000);

  if (!signatureHeader) {
    return false;
  }

  const parts: Record<string, string> = {};
  for (const segment of signatureHeader.split(',')) {
    const [key, value] = segment.trim().split('=', 2);
    if (key) {
      parts[key] = value ?? '';
    }
  }

  const timestamp = parts['t'] ?? '';
  const signature = parts['v1'] ?? '';

  if (timestamp === '' || signature === '' || !/^\d+$/.test(timestamp)) {
    return false;
  }

  if (Math.abs(now - Number(timestamp)) > toleranceSeconds) {
    return false;
  }

  const key = await crypto.subtle.importKey(
    'raw',
    new TextEncoder().encode(secret),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign'],
  );
  const expected = toHex(
    await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(`${timestamp}.${payload}`)),
  );

  return timingSafeEqual(expected, signature);
}

/** Headers as a `Headers` object or a plain record (Node's `IncomingHttpHeaders`, a framework's map). */
export type WebhookHeaders = Headers | Record<string, string | readonly string[] | undefined>;

export interface VerifyStandardWebhookOptions {
  /** The RAW request body — the exact bytes received, not a re-encoded copy. */
  payload: string;
  /** The request headers; `webhook-id`, `webhook-timestamp` and `webhook-signature` are read. */
  headers: WebhookHeaders;
  /**
   * The endpoint's secret: a `whsec_…` secret, or the 64-hex secret of an endpoint that
   * moved from the `cbox` scheme (Cbox ID uses it as `whsec_` + base64 of the hex string,
   * which keys the HMAC with the same bytes).
   */
  secret: string;
  /** Freshness window in seconds. Defaults to 300 (5 minutes). */
  toleranceSeconds?: number;
  /** Injectable clock (unix seconds), for tests. Defaults to `Date.now()`. */
  now?: number;
}

function header(headers: WebhookHeaders, name: string): string | undefined {
  if (typeof Headers !== 'undefined' && headers instanceof Headers) {
    return headers.get(name) ?? undefined;
  }

  const record = headers as Record<string, string | readonly string[] | undefined>;
  const key = Object.keys(record).find((k) => k.toLowerCase() === name);
  const value = key === undefined ? undefined : record[key];

  return Array.isArray(value) ? value.join(' ') : (value as string | undefined);
}

function base64ToBytes(value: string): Uint8Array<ArrayBuffer> | null {
  try {
    const binary = atob(value);
    return Uint8Array.from(binary, (c) => c.charCodeAt(0));
  } catch {
    return null;
  }
}

function toBase64(bytes: ArrayBuffer): string {
  let binary = '';
  for (const byte of new Uint8Array(bytes)) {
    binary += String.fromCharCode(byte);
  }
  return btoa(binary);
}

/**
 * Verify a delivery from an endpoint on the `standard_webhooks` signature scheme
 * ([Standard Webhooks](https://www.standardwebhooks.com/)): `webhook-signature` carries one or
 * more space-separated `v1,<base64 HMAC-SHA256 of "{webhook-id}.{webhook-timestamp}.{body}">`,
 * and the timestamp must be within the freshness window. Use {@link verifyWebhook} for the
 * default `cbox` scheme (`X-Cbox-Signature`).
 *
 * Returns `true` only when a signature is present, fresh and valid. Never throws.
 */
export async function verifyStandardWebhook(options: VerifyStandardWebhookOptions): Promise<boolean> {
  const { payload, headers, secret } = options;
  const toleranceSeconds = options.toleranceSeconds ?? 300;
  const now = options.now ?? Math.floor(Date.now() / 1000);

  const id = header(headers, 'webhook-id');
  const timestamp = header(headers, 'webhook-timestamp');
  const signatures = header(headers, 'webhook-signature');

  if (!id || !timestamp || !signatures || !/^\d+$/.test(timestamp)) {
    return false;
  }

  if (Math.abs(now - Number(timestamp)) > toleranceSeconds) {
    return false;
  }

  const keyBytes: Uint8Array<ArrayBuffer> | null = secret.startsWith('whsec_') ? base64ToBytes(secret.slice('whsec_'.length)) : new TextEncoder().encode(secret);

  if (keyBytes === null || keyBytes.length === 0) {
    return false;
  }

  const key = await crypto.subtle.importKey('raw', keyBytes, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const expected = toBase64(await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(`${id}.${timestamp}.${payload}`)));

  // Several signatures may be sent while a secret rotates; any valid `v1` one is enough.
  let valid = false;
  for (const candidate of signatures.split(' ')) {
    const [version, signature] = candidate.split(',', 2);
    if (version === 'v1' && signature !== undefined && timingSafeEqual(expected, signature)) {
      valid = true;
    }
  }

  return valid;
}
