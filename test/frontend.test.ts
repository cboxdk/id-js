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

  /**
   * The browser channel carries login tickets, one-time codes and the session the user is
   * in the middle of establishing. Over http a network attacker reads the ticket and
   * redeems it — and serves the sign-in box the user is looking at, so nothing on the page
   * gives it away.
   */
  it('refuses an issuer that is not https', () => {
    expect(
      () => new CboxIdFrontend({ issuer: 'http://id.acme.test', publishableKey: 'pk_live_abc' }),
    ).toThrow(ConfigurationError);
  });

  it('allows a loopback issuer over http, for local development', () => {
    expect(
      () => new CboxIdFrontend({ issuer: 'http://localhost:8000', publishableKey: 'pk_test_abc' }),
    ).not.toThrow();
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

    // `retries: 0` so the first call genuinely fails: with the default the client would
    // retry past the single rejection and this would prove nothing. The property under
    // test is that the REJECTION is not cached, not that failures are fatal.
    const frontend = new CboxIdFrontend({
      issuer: 'https://id.acme.test',
      publishableKey: 'pk_live_abc',
      retries: 0,
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

describe('CboxIdFrontend — production behaviour', () => {
  /**
   * Retrying a refusal delays the developer finding out that their origin is not on the
   * list, and hammering a rate limit makes it worse. Only the transient is retried.
   */
  it('retries a 5xx and gives up on a refusal', async () => {
    const flaky = vi
      .fn()
      .mockResolvedValueOnce(respond({}, 503))
      .mockResolvedValue(respond(CONFIG));

    await expect(
      new CboxIdFrontend({
        issuer: 'https://id.acme.test',
        publishableKey: 'pk_live_abc',
        fetch: flaky as unknown as typeof fetch,
      }).config(),
    ).resolves.toMatchObject({ mode: 'live' });
    expect(flaky).toHaveBeenCalledTimes(2);

    const refused = vi.fn().mockResolvedValue(respond({}, 401));

    await expect(
      new CboxIdFrontend({
        issuer: 'https://id.acme.test',
        publishableKey: 'pk_live_abc',
        fetch: refused as unknown as typeof fetch,
      }).config(),
    ).rejects.toMatchObject({ code: 'origin_not_allowed' });
    expect(refused).toHaveBeenCalledTimes(1);
  });

  it('surfaces a rate limit as such, with the wait the server asked for', async () => {
    const fetchImpl = vi.fn().mockResolvedValue(
      new Response('{}', { status: 429, headers: { 'Retry-After': '30' } }),
    );

    await expect(
      new CboxIdFrontend({
        issuer: 'https://id.acme.test',
        publishableKey: 'pk_live_abc',
        fetch: fetchImpl as unknown as typeof fetch,
      }).config(),
    ).rejects.toMatchObject({ code: 'rate_limited', retryAfter: 30 });
  });

  /**
   * A 200 whose body is not the document means something between the page and us is
   * rewriting responses — a proxy, an extension, a captive portal. Surfaced as that,
   * rather than as `undefined` deep inside somebody's component.
   */
  it('refuses a 200 that is not the document, and does not retry it', async () => {
    const fetchImpl = vi.fn().mockResolvedValue(respond({ nonsense: true }));

    await expect(
      new CboxIdFrontend({
        issuer: 'https://id.acme.test',
        publishableKey: 'pk_live_abc',
        fetch: fetchImpl as unknown as typeof fetch,
      }).config(),
    ).rejects.toMatchObject({ code: 'malformed' });
    expect(fetchImpl).toHaveBeenCalledTimes(1);
  });

  it('reports an unreachable issuer as unavailable, naming the likely cause', async () => {
    const fetchImpl = vi.fn().mockRejectedValue(new TypeError('Failed to fetch'));

    await expect(
      new CboxIdFrontend({
        issuer: 'https://id.acme.test',
        publishableKey: 'pk_live_abc',
        retries: 0,
        fetch: fetchImpl as unknown as typeof fetch,
      }).config(),
    ).rejects.toMatchObject({ code: 'unavailable' });
  });
});

describe('CboxIdFrontend — embedded sign-in', () => {
  /**
   * Handing tokens to a page that proved a password is the implicit grant, which OAuth 2.1
   * removes. The ticket is the whole point of the design, and nothing token-shaped may
   * ever come back here.
   */
  it('returns a ticket and never anything token-shaped', async () => {
    const fetchImpl = vi.fn().mockResolvedValue(respond({ status: 'ok', login_ticket: 'lt_abc', expires_in: 60 }));

    const result = await new CboxIdFrontend({
      issuer: 'https://id.acme.test',
      publishableKey: 'pk_live_abc',
      fetch: fetchImpl as unknown as typeof fetch,
    }).signIn('ada@acme.test', 'pw');

    expect(result).toEqual({ status: 'ok', loginTicket: 'lt_abc', expiresIn: 60 });
    expect(JSON.stringify(result)).not.toMatch(/access_token|id_token|refresh_token/);
  });

  it('posts the credentials rather than putting them in a URL', async () => {
    const fetchImpl = vi.fn().mockResolvedValue(respond({ status: 'invalid' }, 401));

    await new CboxIdFrontend({
      issuer: 'https://id.acme.test',
      publishableKey: 'pk_live_abc',
      fetch: fetchImpl as unknown as typeof fetch,
    }).signIn('ada@acme.test', 'pw');

    const [url, init] = fetchImpl.mock.calls[0] ?? [];

    expect(url).toBe('https://id.acme.test/frontend/v1/sign-in');
    expect(init.method).toBe('POST');
    // A password in a query string reaches server logs, Referer and browser history.
    expect(String(url)).not.toContain('pw');
  });

  it('reports each next step the server names', async () => {
    for (const status of ['mfa_required', 'otp_required'] as const) {
      const fetchImpl = vi.fn().mockResolvedValue(respond({ status, mfa_token: 'mt_abc' }));

      const result = await new CboxIdFrontend({
        issuer: 'https://id.acme.test',
        publishableKey: 'pk_live_abc',
        fetch: fetchImpl as unknown as typeof fetch,
      }).signIn('ada@acme.test', 'pw');

      expect(result.status).toBe(status);
    }

    const sso = vi.fn().mockResolvedValue(respond({ status: 'sso_required' }));

    expect(
      (
        await new CboxIdFrontend({
          issuer: 'https://id.acme.test',
          publishableKey: 'pk_live_abc',
          fetch: sso as unknown as typeof fetch,
        }).signIn('ada@acme.test', 'pw')
      ).status,
    ).toBe('sso_required');
  });

  /**
   * A challenge with no token to answer it with is not a challenge — the page would draw a
   * code field it can never submit. Treated as a refusal rather than passed through as a
   * state the caller cannot act on.
   */
  it('treats a challenge with no pending token as a refusal', async () => {
    const fetchImpl = vi.fn().mockResolvedValue(respond({ status: 'mfa_required' }));

    const result = await new CboxIdFrontend({
      issuer: 'https://id.acme.test',
      publishableKey: 'pk_live_abc',
      fetch: fetchImpl as unknown as typeof fetch,
    }).signIn('ada@acme.test', 'pw');

    expect(result).toEqual({ status: 'invalid' });
  });

  /**
   * Every refusal is the same refusal — a wrong password, an unknown address and a locked
   * account are one answer, because distinguishing them is the enumeration oracle.
   */
  it('collapses every refusal into one status', async () => {
    const fetchImpl = vi.fn().mockResolvedValue(respond({ status: 'invalid' }, 401));

    const result = await new CboxIdFrontend({
      issuer: 'https://id.acme.test',
      publishableKey: 'pk_live_abc',
      fetch: fetchImpl as unknown as typeof fetch,
    }).signIn('nobody@acme.test', 'pw');

    expect(result).toEqual({ status: 'invalid' });
  });

  it('surfaces a rate limit with the wait the server asked for', async () => {
    const fetchImpl = vi.fn().mockResolvedValue(
      new Response(JSON.stringify({ status: 'rate_limited' }), {
        status: 429,
        headers: { 'Retry-After': '30', 'Content-Type': 'application/json' },
      }),
    );

    const result = await new CboxIdFrontend({
      issuer: 'https://id.acme.test',
      publishableKey: 'pk_live_abc',
      fetch: fetchImpl as unknown as typeof fetch,
    }).signIn('ada@acme.test', 'pw');

    expect(result).toEqual({ status: 'rate_limited', retryAfter: 30 });
  });
});

describe('CboxIdFrontend — second factor', () => {
  function client(fetchImpl: unknown) {
    return new CboxIdFrontend({
      issuer: 'https://id.acme.test',
      publishableKey: 'pk_live_abc',
      fetch: fetchImpl as typeof fetch,
    });
  }

  /**
   * The pending state travels as a token because a cross-origin page has no session cookie
   * to carry it in. Losing it between the two calls is losing the sign-in.
   */
  it('carries the pending token out of the first call', async () => {
    const fetchImpl = vi.fn().mockResolvedValue(respond({ status: 'mfa_required', mfa_token: 'mt_abc' }));

    const result = await client(fetchImpl).signIn('ada@acme.test', 'pw');

    expect(result).toEqual({ status: 'mfa_required', mfaToken: 'mt_abc' });
  });

  it('exchanges a code for a login ticket', async () => {
    const fetchImpl = vi.fn().mockResolvedValue(respond({ status: 'ok', login_ticket: 'lt_abc', expires_in: 60 }));

    const result = await client(fetchImpl).submitSecondFactor('mt_abc', '123456');

    expect(result).toEqual({ status: 'ok', loginTicket: 'lt_abc', expiresIn: 60 });

    const [, init] = fetchImpl.mock.calls[0] ?? [];
    expect(JSON.parse(init.body)).toEqual({ mfa_token: 'mt_abc', code: '123456', method: 'mfa' });
  });

  it('sends the emailed-code challenge as its own method', async () => {
    const fetchImpl = vi.fn().mockResolvedValue(respond({ status: 'ok', login_ticket: 'lt', expires_in: 60 }));

    await client(fetchImpl).submitSecondFactor('mt_abc', '123456', 'otp');

    const [, init] = fetchImpl.mock.calls[0] ?? [];
    expect(JSON.parse(init.body).method).toBe('otp');
  });

  it('reports a wrong code as invalid rather than throwing', async () => {
    const fetchImpl = vi.fn().mockResolvedValue(respond({ status: 'invalid' }, 401));

    await expect(client(fetchImpl).submitSecondFactor('mt_abc', '000000')).resolves.toEqual({ status: 'invalid' });
  });

  it('never leaks a token-shaped field out of the second factor either', async () => {
    const fetchImpl = vi.fn().mockResolvedValue(respond({ status: 'ok', login_ticket: 'lt', access_token: 'nope' }));

    const result = await client(fetchImpl).submitSecondFactor('mt_abc', '123456');

    expect(JSON.stringify(result)).not.toContain('access_token');
  });
});

describe('CboxIdFrontend — passkeys', () => {
  function client(fetchImpl: unknown) {
    return new CboxIdFrontend({
      issuer: 'https://id.acme.test',
      publishableKey: 'pk_live_abc',
      fetch: fetchImpl as typeof fetch,
    });
  }

  it('asks for options and carries the handle back', async () => {
    const fetchImpl = vi.fn().mockResolvedValue(
      respond({ challenge: 'c', challenge_token: 'h_abc', rpId: 'id.acme.test', allowCredentials: [] }),
    );

    const options = await client(fetchImpl).passkeyOptions();

    expect(options.challenge_token).toBe('h_abc');
    // Discoverable credentials: the page never says who is signing in.
    expect(options.allowCredentials).toEqual([]);
  });

  /**
   * The server verifies the RAW body, so the assertion travels unchanged — rebuilding it
   * would change the bytes and every valid signature would be refused.
   */
  it('sends the assertion through unchanged, with the handle beside it', async () => {
    const fetchImpl = vi.fn().mockResolvedValue(respond({ status: 'ok', login_ticket: 'lt', expires_in: 60 }));

    await client(fetchImpl).signInWithPasskey('h_abc', { id: 'cred-1', response: { signature: 'sig' } });

    const [, init] = fetchImpl.mock.calls[0] ?? [];
    const sent = JSON.parse(init.body);

    expect(sent.id).toBe('cred-1');
    expect(sent.response.signature).toBe('sig');
    expect(sent.challenge_token).toBe('h_abc');
  });

  it('returns a login ticket, the same as every other route in', async () => {
    const fetchImpl = vi.fn().mockResolvedValue(respond({ status: 'ok', login_ticket: 'lt_abc', expires_in: 60 }));

    const result = await client(fetchImpl).signInWithPasskey('h_abc', { id: 'cred-1' });

    expect(result).toEqual({ status: 'ok', loginTicket: 'lt_abc', expiresIn: 60 });
  });

  it('reports a refused assertion as invalid rather than throwing', async () => {
    const fetchImpl = vi.fn().mockResolvedValue(respond({ status: 'invalid' }, 401));

    await expect(client(fetchImpl).signInWithPasskey('h_abc', { id: 'cred-1' })).resolves.toEqual({ status: 'invalid' });
  });
});

/**
 * THE SERVER ANSWERS PRECISELY, and this client used to throw that away.
 *
 * "No publishable key was presented" is a different problem from "That publishable key
 * cannot be used from this origin" — one is a wiring mistake, the other an allow-list — and
 * substituting a generic guess for both made the SDK less useful than the API it wraps.
 */
describe('the reason the server gave', () => {
  it('is preferred over our own guess', async () => {
    const frontend = new CboxIdFrontend({
      issuer: 'https://id.acme.test',
      publishableKey: 'pk_test_abc',
      fetch: async () =>
        new Response(JSON.stringify({ error: 'missing_key', error_description: 'No publishable key was presented.' }), {
          status: 401,
          headers: { 'Content-Type': 'application/json' },
        }),
    });

    await expect(frontend.config()).rejects.toThrow(/No publishable key was presented/);
  });

  it('falls back when the refusal carries no readable body, which is the browser case', async () => {
    const frontend = new CboxIdFrontend({
      issuer: 'https://id.acme.test',
      publishableKey: 'pk_test_abc',
      fetch: async () => new Response('', { status: 403 }),
    });

    await expect(frontend.config()).rejects.toThrow(/allow-list/);
  });
});
