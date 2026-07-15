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
