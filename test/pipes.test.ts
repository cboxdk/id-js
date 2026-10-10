import { afterEach, describe, expect, it, vi } from 'vitest';
import {
  CboxIdClient,
  PipeLeaseDeniedError,
  PipeLeaseError,
  PipeNotConnectedError,
  PipeReauthorizationRequiredError,
  PipeTemporarilyUnavailableError,
  VaultClient,
  pipeConnectUrl,
} from '../src/index.js';

const ISSUER = 'https://id.test';
const CONNECT = `${ISSUER}/account/connected-services/github/connect`;

afterEach(() => {
  vi.unstubAllGlobals();
});

function reply(body: unknown, status = 200, headers: Record<string, string> = {}) {
  const mock = vi.fn(async (_input: unknown, _init?: RequestInit) =>
    new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json', ...headers } }),
  );
  vi.stubGlobal('fetch', mock);
  return mock;
}

const lease = {
  access_token: 'gho_abc',
  token_type: 'Bearer',
  provider: 'github',
  user_id: 'usr_1',
  connection_id: 'con_1',
  scopes: ['read:user', 'repo'],
  expires_at: null,
  lease_expires_at: '2026-10-09T14:05:00+00:00',
  metadata: {},
};

describe('VaultClient.leasePipeToken', () => {
  it('leases a token for a named person and maps the response', async () => {
    const mock = reply(lease);

    const token = await new VaultClient(ISSUER, 'app-token').leasePipeToken('github', { userId: 'usr_1', purpose: 'list-repos' });

    const [url, init] = mock.mock.calls[0]!;
    expect(url).toBe(`${ISSUER}/api/v1/vault/pipes/github/token`);
    expect(init!.method).toBe('POST');
    expect((init!.headers as Record<string, string>).authorization).toBe('Bearer app-token');
    expect(JSON.parse(String(init!.body))).toEqual({ purpose: 'list-repos', user_id: 'usr_1' });
    expect(token).toEqual({
      accessToken: 'gho_abc',
      tokenType: 'Bearer',
      provider: 'github',
      userId: 'usr_1',
      connectionId: 'con_1',
      scopes: ['read:user', 'repo'],
      expiresAt: null,
      leaseExpiresAt: '2026-10-09T14:05:00+00:00',
      metadata: {},
    });
  });

  it('leaves user_id out for a token issued for the person', async () => {
    const mock = reply({ ...lease, metadata: { instance_url: 'https://acme.my.salesforce.com' } });

    const token = await new VaultClient(ISSUER, 'user-token').leasePipeToken('salesforce', { purpose: 'sync' });

    expect(JSON.parse(String(mock.mock.calls[0]![1]!.body))).toEqual({ purpose: 'sync' });
    expect(token.metadata.instance_url).toBe('https://acme.my.salesforce.com');
  });

  it('surfaces connect_url on not_connected, ready to bring the person back', async () => {
    reply({ error: 'not_connected', message: 'This person has not connected the provider.', connect_url: CONNECT }, 404);

    const error = await new VaultClient(ISSUER, 't').leasePipeToken('github', { userId: 'u', purpose: 'p' }).catch((e: unknown) => e);

    expect(error).toBeInstanceOf(PipeNotConnectedError);
    expect(error).toBeInstanceOf(PipeLeaseError);
    const e = error as PipeNotConnectedError;
    expect(e.status).toBe(404);
    expect(e.error).toBe('not_connected');
    expect(e.connectUrl).toBe(CONNECT);
    expect(e.connectUrlWith({ clientId: 'cid_1', returnTo: 'https://app.test/settings' })).toBe(
      `${CONNECT}?client_id=cid_1&return_to=https%3A%2F%2Fapp.test%2Fsettings`,
    );
  });

  it('types a provider that needs reconnecting', async () => {
    reply({ error: 'reauthorization_required', message: 'Connect again.', connect_url: CONNECT }, 409);

    const error = await new VaultClient(ISSUER, 't').leasePipeToken('github', { purpose: 'p' }).catch((e: unknown) => e);

    expect(error).toBeInstanceOf(PipeReauthorizationRequiredError);
    expect((error as PipeReauthorizationRequiredError).connectUrl).toBe(CONNECT);
  });

  it('carries Retry-After when the provider cannot refresh just now', async () => {
    reply({ error: 'temporarily_unavailable', message: 'Try again shortly.' }, 503, { 'retry-after': '30' });

    const error = await new VaultClient(ISSUER, 't').leasePipeToken('google', { purpose: 'p' }).catch((e: unknown) => e);

    expect(error).toBeInstanceOf(PipeTemporarilyUnavailableError);
    expect((error as PipeTemporarilyUnavailableError).retryAfter).toBe(30);
  });

  it('types a denied lease, and leaves a missing scope as the base error', async () => {
    reply({ error: 'lease_denied', message: 'The lease was denied.' }, 403);
    const denied = await new VaultClient(ISSUER, 't').leasePipeToken('github', { purpose: 'p' }).catch((e: unknown) => e);
    expect(denied).toBeInstanceOf(PipeLeaseDeniedError);
    expect((denied as PipeLeaseDeniedError).connectUrlWith({ clientId: 'c' })).toBeNull();

    reply({ error: 'insufficient_scope' }, 403);
    const scope = await new VaultClient(ISSUER, 't').leasePipeToken('github', { purpose: 'p' }).catch((e: unknown) => e);
    expect(scope).toBeInstanceOf(PipeLeaseError);
    expect(scope).not.toBeInstanceOf(PipeLeaseDeniedError);
    expect((scope as PipeLeaseError).error).toBe('insufficient_scope');
  });

  it('survives a body that is not JSON', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => new Response('<html>bad gateway</html>', { status: 502 })));

    const error = await new VaultClient(ISSUER, 't').leasePipeToken('github', { purpose: 'p' }).catch((e: unknown) => e);

    expect(error).toBeInstanceOf(PipeLeaseError);
    expect((error as PipeLeaseError).status).toBe(502);
    expect((error as PipeLeaseError).message).not.toContain('html');
  });
});

describe('connect URLs', () => {
  it('builds the hosted connect page with client_id and return_to', () => {
    expect(pipeConnectUrl(`${ISSUER}/`, 'github', { clientId: 'cid_1', returnTo: 'https://app.test/x' })).toBe(
      `${CONNECT}?client_id=cid_1&return_to=https%3A%2F%2Fapp.test%2Fx`,
    );
    expect(pipeConnectUrl(ISSUER, 'notion')).toBe(`${ISSUER}/account/connected-services/notion/connect`);
  });

  it('is preselected to the configured app on the client', () => {
    const client = new CboxIdClient({ issuer: ISSUER, clientId: 'cid_9' });

    expect(client.pipeConnectUrl('slack', 'https://app.test/integrations')).toBe(
      `${ISSUER}/account/connected-services/slack/connect?client_id=cid_9&return_to=https%3A%2F%2Fapp.test%2Fintegrations`,
    );
  });
});
