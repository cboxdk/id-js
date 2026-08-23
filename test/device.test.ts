import { afterEach, describe, expect, it, vi } from 'vitest';
import { AuthenticationError, CboxIdClient, ConfigurationError } from '../src/index.js';
import { fakeInstance, ISSUER } from './helpers.js';

// A CLI holds no secret, which is the shape this flow exists for.
const cliConfig = {
  issuer: ISSUER,
  clientId: 'client-abc',
};

afterEach(() => {
  vi.unstubAllGlobals();
});

describe('requestDeviceAuthorization', () => {
  it('returns the code and the page to enter it on', async () => {
    const inst = await fakeInstance();
    vi.stubGlobal('fetch', inst.fetchMock);

    const auth = await new CboxIdClient(cliConfig).requestDeviceAuthorization();

    expect(auth.userCode).toBe('WDJB-MJHT');
    expect(auth.verificationUri).toBe(`${ISSUER}/device`);
    expect(auth.verificationUriComplete).toBe(`${ISSUER}/device?user_code=WDJB-MJHT`);
  });

  it('defaults the poll interval to the five seconds the server assumes', async () => {
    const inst = await fakeInstance();
    // RFC 8628 §3.2 makes `interval` optional and its absence mean 5. A client that
    // defaults to 0 hammers the endpoint and is answered with slow_down forever.
    inst.setDeviceFlow({
      authorization: {
        device_code: 'device-abc',
        user_code: 'WDJB-MJHT',
        verification_uri: `${ISSUER}/device`,
        expires_in: 600,
      },
    });
    vi.stubGlobal('fetch', inst.fetchMock);

    const auth = await new CboxIdClient(cliConfig).requestDeviceAuthorization();

    expect(auth.interval).toBe(5);
    expect(auth.verificationUriComplete).toBeNull();
  });

  it('says plainly when the instance does not serve the device grant', async () => {
    // An issuer whose discovery omits the endpoint — a deployment that has not enabled
    // it. Without this the SDK would post to `undefined` and fail as a network error.
    const fetchMock = vi.fn(async (input: unknown) => {
      const url = String(input);
      if (url.endsWith('/.well-known/openid-configuration')) {
        return new Response(
          JSON.stringify({
            issuer: ISSUER,
            authorization_endpoint: `${ISSUER}/oauth/authorize`,
            token_endpoint: `${ISSUER}/oauth/token`,
            jwks_uri: `${ISSUER}/oauth/jwks`,
          }),
          { status: 200, headers: { 'content-type': 'application/json' } },
        );
      }
      throw new Error(`unexpected fetch: ${url}`);
    });
    vi.stubGlobal('fetch', fetchMock);

    await expect(new CboxIdClient(cliConfig).requestDeviceAuthorization()).rejects.toThrow(
      ConfigurationError,
    );
  });
});

describe('pollDeviceToken', () => {
  it('keeps polling while the person has not finished, then returns them', async () => {
    const inst = await fakeInstance();
    inst.setDeviceFlow({
      polls: [
        { body: { error: 'authorization_pending' }, status: 400 },
        { body: { error: 'authorization_pending' }, status: 400 },
      ],
    });
    vi.stubGlobal('fetch', inst.fetchMock);

    const client = new CboxIdClient(cliConfig);
    const auth = await client.requestDeviceAuthorization();
    const user = await client.pollDeviceToken(auth);

    expect(user.id).toBe('user-1');
    expect(user.email).toBe('ada@acme.com');
    expect(user.refreshToken).toBe('refresh-abc');
    // Two pending answers and the success: it did not give up on the first non-200.
    expect(inst.devicePolls()).toBe(3);
  });

  it('stops when the person declines', async () => {
    const inst = await fakeInstance();
    inst.setDeviceFlow({ polls: [{ body: { error: 'access_denied' }, status: 400 }] });
    vi.stubGlobal('fetch', inst.fetchMock);

    const client = new CboxIdClient(cliConfig);
    const auth = await client.requestDeviceAuthorization();

    await expect(client.pollDeviceToken(auth)).rejects.toThrow(/declined/i);
    // AND IT STOPPED. A loop that treats every error as "keep waiting" polls a dead
    // authorization until the code expires, ten minutes after the person said no.
    expect(inst.devicePolls()).toBe(1);
  });

  it('stops when the code has expired', async () => {
    const inst = await fakeInstance();
    inst.setDeviceFlow({ polls: [{ body: { error: 'expired_token' }, status: 400 }] });
    vi.stubGlobal('fetch', inst.fetchMock);

    const client = new CboxIdClient(cliConfig);
    const auth = await client.requestDeviceAuthorization();

    await expect(client.pollDeviceToken(auth)).rejects.toThrow(AuthenticationError);
    expect(inst.devicePolls()).toBe(1);
  });

  it('backs off on slow_down, and keeps the slower rate afterwards', async () => {
    vi.useFakeTimers();

    try {
      const inst = await fakeInstance();
      inst.setDeviceFlow({
        polls: [
          { body: { error: 'slow_down' }, status: 400 },
          { body: { error: 'authorization_pending' }, status: 400 },
        ],
      });
      vi.stubGlobal('fetch', inst.fetchMock);

      const client = new CboxIdClient(cliConfig);
      const auth = await client.requestDeviceAuthorization();

      expect(auth.interval).toBe(0);

      const pending = client.pollDeviceToken(auth);

      // First poll goes out immediately at interval 0 and is answered slow_down.
      await vi.advanceTimersByTimeAsync(0);
      expect(inst.devicePolls()).toBe(1);

      // RFC 8628 §3.5: add five seconds. Not four-and-a-bit — the second poll must not
      // have gone out yet.
      await vi.advanceTimersByTimeAsync(4999);
      expect(inst.devicePolls()).toBe(1);

      await vi.advanceTimersByTimeAsync(1);
      expect(inst.devicePolls()).toBe(2);

      // AND IT STAYS SLOWED. Returning to the refused rate after one round earns the
      // same answer forever, which is the loop that looks like it is working and never
      // finishes. The third poll is five seconds after the second, not immediate.
      await vi.advanceTimersByTimeAsync(4999);
      expect(inst.devicePolls()).toBe(2);

      await vi.advanceTimersByTimeAsync(1);

      const user = await pending;

      expect(user.id).toBe('user-1');
      expect(inst.devicePolls()).toBe(3);
    } finally {
      vi.useRealTimers();
    }
  });

  it('can be cancelled, so Ctrl-C works', async () => {
    const inst = await fakeInstance();
    inst.setDeviceFlow({
      authorization: {
        device_code: 'device-abc',
        user_code: 'WDJB-MJHT',
        verification_uri: `${ISSUER}/device`,
        expires_in: 600,
        interval: 30,
      },
      polls: [{ body: { error: 'authorization_pending' }, status: 400 }],
    });
    vi.stubGlobal('fetch', inst.fetchMock);

    const client = new CboxIdClient(cliConfig);
    const auth = await client.requestDeviceAuthorization();

    const controller = new AbortController();
    const pending = client.pollDeviceToken(auth, { signal: controller.signal });
    controller.abort();

    // Rejects NOW rather than after the 30-second interval elapses: the abort is wired
    // to the timer, not checked after it. A CLI that ignores Ctrl-C for half a minute
    // reads as hung.
    await expect(pending).rejects.toThrow(/cancelled/i);
    expect(inst.devicePolls()).toBe(0);
  });
});
