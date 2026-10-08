import { readFile } from 'node:fs/promises';
import { afterEach, describe, expect, it, vi } from 'vitest';
import {
  AUDIT_CHAIN_GENESIS,
  AuditLogExportError,
  AuditLogger,
  EnvironmentClient,
  auditEventDocument,
  auditEventHash,
  canonicalJson,
  exportAuditLogs,
  verifyAuditChain,
  verifyAuditLogChain,
  type EnvironmentApi,
} from '../src/management/index.js';

const HOST = 'https://acme.test';
const API = `${HOST}/api/v1`;

interface Call {
  url: string;
  method: string;
  headers: Headers;
  body: { events?: unknown[] } | undefined;
}

function fakeFetch(handler: (call: Call) => Response) {
  const calls: Call[] = [];
  const fetch = vi.fn(async (input: string | URL | Request, init?: RequestInit) => {
    const call: Call = {
      url: String(input),
      method: init?.method ?? 'GET',
      headers: new Headers(init?.headers),
      body: typeof init?.body === 'string' ? JSON.parse(init.body) : undefined,
    };
    calls.push(call);
    return handler(call);
  }) as unknown as typeof globalThis.fetch;

  return { fetch, calls };
}

function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json' } });
}

function client(fetch: typeof globalThis.fetch): EnvironmentClient {
  return new EnvironmentClient({ baseUrl: HOST, apiKey: 'cbid_env_k', fetch, retry: { maxRetries: 0 } });
}

type FixtureEvent = EnvironmentApi.AuditLogEvent & { canonical: string };

async function fixture(): Promise<FixtureEvent[]> {
  const raw = JSON.parse(await readFile(new URL('./fixtures/audit-chain.json', import.meta.url), 'utf8')) as { data: FixtureEvent[] };
  return raw.data;
}

afterEach(() => {
  vi.useRealTimers();
});

describe('audit chain — byte-for-byte with the server', () => {
  it('canonicalises and hashes each event exactly as Cbox ID did (vector computed by the server code)', async () => {
    let previous = AUDIT_CHAIN_GENESIS;

    for (const event of await fixture()) {
      expect(canonicalJson(auditEventDocument(event))).toBe(event.canonical);
      expect(event.prev_hash).toBe(previous);
      expect(await auditEventHash(previous, event)).toBe(event.hash);
      previous = event.hash;
    }
  });

  it('verifies the chain in any order, and finds a changed, missing or relinked event', async () => {
    const events = await fixture();

    expect(await verifyAuditChain([...events].reverse())).toEqual({
      valid: true,
      verified_count: 3,
      first_sequence: 1,
      last_sequence: 3,
      broken_at_sequence: null,
      reason: null,
    });

    const changed = events.map((e) => (e.sequence === 2 ? { ...e, action: 'user.signed_out' } : e));
    expect(await verifyAuditChain(changed)).toMatchObject({ valid: false, reason: 'hash', broken_at_sequence: 2, verified_count: 1 });

    const gap = events.filter((e) => e.sequence !== 2);
    expect(await verifyAuditChain(gap)).toMatchObject({ valid: false, reason: 'missing', broken_at_sequence: 2 });

    const relinked = events.map((e) => (e.sequence === 3 ? { ...e, prev_hash: AUDIT_CHAIN_GENESIS } : e));
    expect(await verifyAuditChain(relinked)).toMatchObject({ valid: false, reason: 'link', broken_at_sequence: 3 });

    // A window that starts later trusts its first prev_hash, unless told what it must be.
    const tail = events.filter((e) => e.sequence > 1);
    expect(await verifyAuditChain(tail)).toMatchObject({ valid: true, first_sequence: 2 });
    expect(await verifyAuditChain(tail, { previousHash: 'f'.repeat(64) })).toMatchObject({ valid: false, reason: 'link' });
  });

  it('writes numbers and strings the way PHP json_encode does', () => {
    // Expected strings are PHP 8's json_encode output for the same values.
    const values = [1.0, 1e25, 1e-7, 0.1, 1.5, 1e15, 1e16, 1e17, 0.0001, 0.00012, 1.2345e20, -2.5e-5, 0.1 + 0.2, 1e100, -0];
    expect(values.map(canonicalJson)).toEqual([
      '1', '1.0e+25', '1.0e-7', '0.1', '1.5', '1000000000000000', '10000000000000000', '1.0e+17', '0.0001', '0.00012',
      '1.2345e+20', '-2.5e-5', '0.30000000000000004', '1.0e+100', '-0',
    ]);
    expect(canonicalJson({ b: 'x/y', a: 'Æ\u2028"\n' })).toBe('{"a":"Æ\\u2028\\"\\n","b":"x/y"}');
    expect(canonicalJson({ '1': 'b', '0': 'a' })).toBe('["a","b"]');
    expect(canonicalJson({ '10': 'k', '2': 'j' })).toBe('{"10":"k","2":"j"}');
    expect(canonicalJson({})).toBe('[]');
  });
});

describe('AuditLogger', () => {
  it('sends batches of at most 100, each under its own Idempotency-Key', async () => {
    const { fetch, calls } = fakeFetch((call) => json({ data: { events: call.body?.events ?? [] } }, 201));
    const logger = new AuditLogger(client(fetch), { flushIntervalMs: 0 });

    for (let i = 0; i < 250; i++) {
      logger.record({ organization_id: 'org_1', action: 'invoice.viewed', actor: { id: `u${i}`, type: 'user' } });
    }
    await logger.flush();

    expect(calls.map((c) => c.body?.events?.length)).toEqual([100, 100, 50]);
    expect(calls.every((c) => c.method === 'POST' && c.url === `${API}/audit-logs/events`)).toBe(true);
    expect(new Set(calls.map((c) => c.headers.get('idempotency-key'))).size).toBe(3);
    const first = calls[0]!.body!.events![0] as { occurred_at: string };
    expect(first.occurred_at).toMatch(/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/);
    expect(logger.pending).toBe(0);
  });

  it('keeps a failed batch, and resends it with the same key', async () => {
    let fail = true;
    const { fetch, calls } = fakeFetch(() => {
      if (fail) {
        fail = false;
        return json({ error: 'server_error', message: 'Down.' }, 503);
      }
      return json({ data: { events: [] } }, 201);
    });
    const logger = new AuditLogger(client(fetch), { flushIntervalMs: 0 });
    logger.record({ organization_id: 'org_1', action: 'a.b', actor: { id: 'u', type: 'user' }, occurred_at: '2026-10-08T00:00:00.000Z' });

    await expect(logger.flush()).rejects.toMatchObject({ status: 503 });
    expect(logger.pending).toBe(1);
    await logger.flush();

    expect(calls).toHaveLength(2);
    expect(calls[1]!.headers.get('idempotency-key')).toBe(calls[0]!.headers.get('idempotency-key'));
    expect(logger.pending).toBe(0);
  });

  it('flushes on its interval, and refuses events once closed', async () => {
    vi.useFakeTimers();
    const { fetch, calls } = fakeFetch(() => json({ data: { events: [] } }, 201));
    const logger = new AuditLogger(client(fetch), { flushIntervalMs: 1_000 });
    logger.record({ organization_id: 'org_1', action: 'a.b', actor: { id: 'u', type: 'user' } });

    expect(calls).toHaveLength(0);
    await vi.advanceTimersByTimeAsync(1_000);
    expect(calls).toHaveLength(1);

    await logger.close();
    expect(() => logger.record({ organization_id: 'org_1', action: 'a.b', actor: { id: 'u', type: 'user' } })).toThrow(/closed/);
  });
});

describe('audit log exports and lists', () => {
  const exported = (state: string) => ({
    data: { id: 'exp_1', organization_id: 'org_1', state, filters: {}, row_count: null, url: state === 'ready' ? 'https://files.test/x.csv' : null, created_at: null, completed_at: null, expires_at: null },
  });

  it('creates an export and reads it until it is ready', async () => {
    const states = ['pending', 'pending', 'ready'];
    const { fetch, calls } = fakeFetch((call) => (call.method === 'POST' ? json(exported('pending'), 201) : json(exported(states.shift()!))));
    const result = await exportAuditLogs(client(fetch), { organization_id: 'org_1' }, { pollIntervalMs: 0 });

    expect(result.url).toBe('https://files.test/x.csv');
    expect(calls.map((c) => `${c.method} ${c.url}`)).toEqual([
      `POST ${API}/audit-logs/exports`,
      `GET ${API}/audit-logs/exports/exp_1`,
      `GET ${API}/audit-logs/exports/exp_1`,
      `GET ${API}/audit-logs/exports/exp_1`,
    ]);
  });

  it('throws when the export fails', async () => {
    const { fetch } = fakeFetch((call) => (call.method === 'POST' ? json(exported('pending'), 201) : json(exported('failed'))));
    await expect(exportAuditLogs(client(fetch), {}, { pollIntervalMs: 0 })).rejects.toBeInstanceOf(AuditLogExportError);
  });

  it('pages events and verifies an organization’s chain from the list', async () => {
    const events = await fixture();
    const { fetch, calls } = fakeFetch((call) =>
      new URL(call.url).searchParams.has('after')
        ? json({ data: events.slice(2), meta: { has_more: false, next_cursor: null } })
        : json({ data: events.slice(0, 2), meta: { has_more: true, next_cursor: 'c1' } }),
    );

    const ids: string[] = [];
    for await (const event of client(fetch).auditLogs.events.listAll({ organization_id: 'org_1', actions: ['invoice.voided', 'user.signed_in'] })) {
      ids.push(event.id);
    }
    expect(ids).toEqual(events.map((e) => e.id));
    expect(calls[0]!.url).toBe(`${API}/audit-logs/events?organization_id=org_1&actions%5B%5D=invoice.voided&actions%5B%5D=user.signed_in`);

    expect(await verifyAuditLogChain(client(fetch), { organization_id: 'org_1' })).toMatchObject({ valid: true, verified_count: 3 });
    expect(new URL(calls[2]!.url).searchParams.get('order')).toBe('asc');
  });
});
