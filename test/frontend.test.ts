import { describe, expect, it, vi } from 'vitest';

import { CboxIdFrontend } from '../src/frontend.js';
import { ConfigurationError } from '../src/errors.js';

const CONFIG = {
  mode: 'live',
  issuer: 'https://id.acme.test',
  endpoints: {
    authorization: 'https://id.acme.test/oauth/authorize',
    token: 'https://id.acme.test/oauth/token',
    userinfo: 'https://id.acme.test/oauth/userinfo',
    end_session: 'https://id.acme.test/oauth/logout',
    jwks: 'https://id.acme.test/.well-known/jwks.json',
  },
  social: [{ provider: 'google', name: 'Google' }],
};

function respond(body: unknown, status = 200) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' },
  });
}

describe('CboxIdFrontend', () => {
  /**
   * The mistake worth catching loudly. Pasting a client secret into a browser bundle is
   * the failure this whole channel exists to make unnecessary, and if it only surfaced as
   * an opaque 401 in the network tab the cause would be invisible.
   */
  it('refuses anything that is not a publishable key', () => {
    expect(
      () => new CboxIdFrontend({ issuer: 'https://id.acme.test', publishableKey: 'sk_live_secret' }),
    ).toThrow(ConfigurationError);

    expect(
      () => new CboxIdFrontend({ issuer: 'https://id.acme.test', publishableKey: '' }),
    ).toThrow(ConfigurationError);
  });

  it('sends the key in a header, never in the query string', async () => {
    const fetchImpl = vi.fn().mockResolvedValue(respond(CONFIG));

    await new CboxIdFrontend({
      issuer: 'https://id.acme.test',
      publishableKey: 'pk_live_abc',
      fetch: fetchImpl as unknown as typeof fetch,
    }).config();

    const [url, init] = fetchImpl.mock.calls[0] ?? [];

    // A query string would put the key in server logs, in `Referer` on every outbound
    // link, and in browser history.
    expect(url).toBe('https://id.acme.test/frontend/v1/config');
    expect(init.headers['X-Cbox-Publishable-Key']).toBe('pk_live_abc');
  });

  /**
   * A page with a sign-in form, a user button and an organization switcher mounts three
   * components in the same tick. Three parallel fetches of the same immutable document is
   * a waste the SDK should absorb rather than ask every consumer to.
   */
  it('fetches the config once no matter how many components ask at once', async () => {
    const fetchImpl = vi.fn().mockResolvedValue(respond(CONFIG));
    const frontend = new CboxIdFrontend({
      issuer: 'https://id.acme.test',
      publishableKey: 'pk_live_abc',
      fetch: fetchImpl as unknown as typeof fetch,
    });

    await Promise.all([frontend.config(), frontend.config(), frontend.config()]);

    expect(fetchImpl).toHaveBeenCalledTimes(1);
  });

  /**
   * A transient network failure must not poison the instance for the lifetime of the page
   * — which is what caching the rejected promise would do.
   */
  it('retries after a failure rather than caching it forever', async () => {
    const fetchImpl = vi
      .fn()
      .mockRejectedValueOnce(new Error('network'))
      .mockResolvedValue(respond(CONFIG));

    const frontend = new CboxIdFrontend({
      issuer: 'https://id.acme.test',
      publishableKey: 'pk_live_abc',
      fetch: fetchImpl as unknown as typeof fetch,
    });

    await expect(frontend.config()).rejects.toThrow();
    await expect(frontend.config()).resolves.toMatchObject({ mode: 'live' });
    expect(fetchImpl).toHaveBeenCalledTimes(2);
  });

  /**
   * SIGNED OUT IS A STATE, NOT AN ERROR. A user button renders on pages nobody has signed
   * in on, and making callers treat a rejection as a state is how flash-of-signed-out bugs
   * are born.
   */
  it('answers with a null user, and does not call out at all, when there is no token', async () => {
    const fetchImpl = vi.fn();

    const session = await new CboxIdFrontend({
      issuer: 'https://id.acme.test',
      publishableKey: 'pk_live_abc',
      fetch: fetchImpl as unknown as typeof fetch,
    }).session(undefined);

    expect(session).toEqual({ user: null });
    expect(fetchImpl).not.toHaveBeenCalled();
  });

  it('passes the access token as the authority for the session', async () => {
    const fetchImpl = vi.fn().mockResolvedValue(respond({ user: { id: '1', email: 'a@b.test', name: 'A' } }));

    await new CboxIdFrontend({
      issuer: 'https://id.acme.test',
      publishableKey: 'pk_live_abc',
      fetch: fetchImpl as unknown as typeof fetch,
    }).session('at_123');

    expect(fetchImpl.mock.calls[0]?.[1].headers.Authorization).toBe('Bearer at_123');
  });

  it('names the likely cause when the request is refused', async () => {
    const fetchImpl = vi.fn().mockResolvedValue(respond({ error: 'unauthorized' }, 401));

    const frontend = new CboxIdFrontend({
      issuer: 'https://id.acme.test',
      publishableKey: 'pk_live_abc',
      fetch: fetchImpl as unknown as typeof fetch,
    });

    // The origin allow-list is the overwhelmingly likely cause, and a developer reading
    // this message should not have to go looking for the concept.
    await expect(frontend.config()).rejects.toThrow(/origin/i);
  });

  it('knows whether it drives real sign-ins', () => {
    const live = new CboxIdFrontend({ issuer: 'https://id.acme.test', publishableKey: 'pk_live_a' });
    const test = new CboxIdFrontend({ issuer: 'https://id.acme.test', publishableKey: 'pk_test_a' });

    expect(live.isLive).toBe(true);
    expect(test.isLive).toBe(false);
  });
});
