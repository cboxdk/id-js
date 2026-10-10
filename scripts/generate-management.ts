/**
 * Generates the typed management clients in `src/management/generated/` from the OpenAPI
 * documents Cbox ID publishes, vendored in `openapi/`.
 *
 *   npm run generate                                  regenerate from openapi/*.yaml
 *   npm run generate -- --fetch environment=https://acme.cboxid.com
 *                                                     refresh one vendored spec from a live host
 *   npm run generate -- --fetch all=https://id.example.com
 *                                                     refresh all four from one (self-hosted) host
 *   npm run generate -- --check                       exit 1 when the generated code is stale
 *
 * A small, dependency-light generator on purpose: the output is meant to be read. It knows
 * exactly the subset of JSON Schema the server's spec builder emits, and fails loudly on
 * anything it does not understand rather than guessing.
 *
 * Runs with Node's built-in TypeScript type stripping (Node >= 22.6).
 */
import { mkdir, readFile, writeFile } from 'node:fs/promises';
import { dirname, join } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { parse } from 'yaml';

type Json = Record<string, unknown>;

export interface PlaneConfig {
  plane: 'environment' | 'workspace' | 'platform' | 'account';
  file: string;
  className: string;
  /** Path the server serves this spec at, relative to the host. */
  specPath: string;
  /** Security schemes that are this plane's management credentials. */
  schemes: string[];
  /** Path prefix stripped when a non-action route's name is derived from its path. */
  prefix: string;
}

export const PLANES: PlaneConfig[] = [
  {
    plane: 'environment',
    file: 'environment',
    className: 'EnvironmentClient',
    specPath: '/api/v1/environment/openapi.yaml',
    schemes: ['EnvironmentApiKey', 'ManagementAccessToken', 'WorkspaceAccessToken'],
    prefix: '',
  },
  {
    plane: 'workspace',
    file: 'workspace',
    className: 'WorkspaceClient',
    specPath: '/api/v1/workspace/openapi.yaml',
    schemes: ['OrganizationApiKey', 'WorkspaceApiKey', 'WorkspaceAccessToken'],
    prefix: '/workspace',
  },
  {
    plane: 'platform',
    file: 'platform',
    className: 'PlatformClient',
    specPath: '/api/v1/platform/openapi.yaml',
    schemes: ['OperatorToken'],
    prefix: '/platform',
  },
  {
    plane: 'account',
    file: 'account',
    className: 'AccountClient',
    specPath: '/api/v1/me/openapi.yaml',
    schemes: ['PersonToken'],
    prefix: '/me',
  },
];

const METHODS = ['get', 'post', 'put', 'patch', 'delete'] as const;
const DANGERS = new Set(['read', 'write', 'destructive', 'critical']);
/** Names a schema may not take as-is: they would shadow a global in the generated module. */
const RESERVED_TYPES = new Set(['Error', 'Record', 'Partial', 'Date', 'Object', 'Function', 'String', 'Number', 'Boolean', 'Array', 'Promise', 'Map', 'Set', 'Response', 'Request', 'Headers', 'URL']);
const IDENTIFIER = /^[A-Za-z_$][A-Za-z0-9_$]*$/;

function isRecord(value: unknown): value is Json {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function camel(segment: string): string {
  return segment.replace(/[-_]+([a-z0-9])/g, (_, c: string) => c.toUpperCase());
}

function pascal(parts: string[]): string {
  return parts.map((p) => camel(p)).map((p) => p.charAt(0).toUpperCase() + p.slice(1)).join('');
}

function quoteKey(key: string): string {
  return IDENTIFIER.test(key) ? key : `'${key.replace(/\\/g, '\\\\').replace(/'/g, "\\'")}'`;
}

function literal(value: unknown): string {
  return typeof value === 'string' ? `'${value.replace(/\\/g, '\\\\').replace(/'/g, "\\'")}'` : JSON.stringify(value);
}

function doc(text: string | undefined, indent: string, extra: string[] = []): string {
  const lines = [...(text ?? '').trim().split('\n').map((l) => l.trimEnd()), ...extra]
    // A `*/` inside a description would end the comment early.
    .map((l) => l.replace(/\*\//g, '*\\/'));

  while (lines.length > 0 && lines[0] === '') lines.shift();
  while (lines.length > 0 && lines[lines.length - 1] === '') lines.pop();

  if (lines.length === 0) {
    return '';
  }

  if (lines.length === 1) {
    return `${indent}/** ${lines[0]} */\n`;
  }

  return `${indent}/**\n${lines.map((l) => (l === '' ? `${indent} *` : `${indent} * ${l}`)).join('\n')}\n${indent} */\n`;
}

/** An operation's key in the generated table: its action name, or its derived name. */
function tableKey(op: Operation): string {
  return op.action ?? op.name.join('.');
}

interface Operation {
  name: string[];
  action: string | null;
  operationId: string | null;
  method: string;
  path: string;
  pathParams: string[];
  summary: string | undefined;
  description: string | undefined;
  scope: string | null;
  danger: string | null;
  approval: boolean;
  inputKind: 'body' | 'query' | null;
  inputRequired: boolean;
  inputSchema: Json | null;
  responseSchema: Json | null;
  pagination: 'cursor' | 'page' | null;
}

class Generator {
  readonly #spec: Json;
  readonly #config: PlaneConfig;
  readonly #typeNames = new Map<string, string>();
  readonly #used = new Set<string>();
  readonly skipped: string[] = [];

  constructor(spec: Json, config: PlaneConfig) {
    this.#spec = spec;
    this.#config = config;

    for (const name of Object.keys(this.#schemas())) {
      const safe = RESERVED_TYPES.has(name) ? `${name}Schema` : name;
      this.#typeNames.set(name, safe);
      this.#used.add(safe);
    }
  }

  #components(kind: string): Json {
    const components = isRecord(this.#spec.components) ? this.#spec.components : {};
    const section = components[kind];
    return isRecord(section) ? section : {};
  }

  #schemas(): Json {
    return this.#components('schemas');
  }

  #deref(value: unknown, kind: string): Json {
    if (isRecord(value) && typeof value.$ref === 'string') {
      const name = value.$ref.split('/').pop() ?? '';
      const target = this.#components(kind)[name];

      if (!isRecord(target)) {
        throw new Error(`${this.#config.file}: unresolved ${value.$ref}`);
      }

      return target;
    }

    if (!isRecord(value)) {
      throw new Error(`${this.#config.file}: expected an object, got ${JSON.stringify(value)}`);
    }

    return value;
  }

  /** A JSON Schema as a TypeScript type. */
  type(schema: unknown, indent: string): string {
    if (schema === true || schema === undefined) return 'unknown';
    if (!isRecord(schema)) throw new Error(`${this.#config.file}: unsupported schema ${JSON.stringify(schema)}`);

    if (typeof schema.$ref === 'string') {
      const name = schema.$ref.split('/').pop() ?? '';
      const mapped = this.#typeNames.get(name);
      if (mapped === undefined) throw new Error(`${this.#config.file}: unresolved ${schema.$ref}`);
      return mapped;
    }

    if ('const' in schema) return literal(schema.const);

    for (const key of ['oneOf', 'anyOf'] as const) {
      if (Array.isArray(schema[key])) {
        return this.#union((schema[key] as unknown[]).map((s) => this.type(s, indent)));
      }
    }

    if (Array.isArray(schema.allOf)) {
      return (schema.allOf as unknown[]).map((s) => this.#wrap(this.type(s, indent))).join(' & ');
    }

    const types = Array.isArray(schema.type) ? (schema.type as string[]) : typeof schema.type === 'string' ? [schema.type] : [];

    if (Array.isArray(schema.enum)) {
      const values = (schema.enum as unknown[]).map(literal);
      if (types.includes('null') && !values.includes('null')) values.push('null');
      return this.#union(values);
    }

    if (types.length === 0) {
      return isRecord(schema.properties) ? this.#object(schema, indent) : 'unknown';
    }

    return this.#union(types.map((t) => this.#primitive(t, schema, indent)));
  }

  #wrap(type: string): string {
    return type.includes(' | ') && !type.startsWith('{') ? `(${type})` : type;
  }

  #union(types: string[]): string {
    return [...new Set(types)].join(' | ');
  }

  #primitive(type: string, schema: Json, indent: string): string {
    switch (type) {
      case 'string':
        return 'string';
      case 'integer':
      case 'number':
        return 'number';
      case 'boolean':
        return 'boolean';
      case 'null':
        return 'null';
      case 'array': {
        const item = this.type(schema.items, indent);
        return IDENTIFIER.test(item) ? `${item}[]` : `Array<${item}>`;
      }
      case 'object':
        return this.#object(schema, indent);
      default:
        throw new Error(`${this.#config.file}: unsupported type ${type}`);
    }
  }

  #object(schema: Json, indent: string): string {
    const properties = isRecord(schema.properties) ? schema.properties : {};
    const required = new Set(Array.isArray(schema.required) ? (schema.required as string[]) : []);
    const inner = `${indent}  `;
    const lines: string[] = [];

    for (const [key, value] of Object.entries(properties)) {
      const description = isRecord(value) && typeof value.description === 'string' ? value.description : undefined;
      lines.push(`${doc(description, inner)}${inner}${quoteKey(key)}${required.has(key) ? '' : '?'}: ${this.type(value, inner)};`);
    }

    const additional = schema.additionalProperties;

    if (additional !== undefined && additional !== false) {
      // An index signature must admit every named property too, so it widens to `unknown`
      // whenever the object also has named ones.
      const value = lines.length > 0 ? 'unknown' : this.type(additional === true ? undefined : additional, inner);
      lines.push(`${inner}[key: string]: ${value};`);
    }

    if (lines.length === 0) {
      return 'Record<string, unknown>';
    }

    return `{\n${lines.join('\n')}\n${indent}}`;
  }

  operations(): Operation[] {
    const paths = isRecord(this.#spec.paths) ? this.#spec.paths : {};
    const defaultSecurity = this.#spec.security;
    const ops: Operation[] = [];

    for (const [path, rawItem] of Object.entries(paths)) {
      const item = this.#deref(rawItem, 'pathItems');
      const shared = Array.isArray(item.parameters) ? (item.parameters as unknown[]) : [];

      for (const method of METHODS) {
        const op = item[method];
        if (!isRecord(op)) continue;

        const security = (Array.isArray(op.security) ? op.security : defaultSecurity) as unknown[] | undefined;
        const schemes = (security ?? []).flatMap((s) => (isRecord(s) ? Object.keys(s) : []));
        const action = typeof op['x-action'] === 'string' ? op['x-action'] : null;

        if (!schemes.some((s) => this.#config.schemes.includes(s))) {
          this.skipped.push(`${method.toUpperCase()} ${path} (${schemes.join(', ') || 'no security'})`);
          continue;
        }

        const parameters = [...shared, ...(Array.isArray(op.parameters) ? (op.parameters as unknown[]) : [])].map((p) =>
          this.#deref(p, 'parameters'),
        );
        const pathParams = [...path.matchAll(/\{([^}]+)\}/g)].map((m) => m[1]!);
        const query = parameters.filter((p) => p.in === 'query');
        const description = typeof op.description === 'string' ? op.description : undefined;
        // `x-scope` / `x-danger` are the contract. Routes the spec builder does not generate from
        // an action carry neither, and only say it in prose — read that as a fallback.
        const scope = typeof op['x-scope'] === 'string' ? op['x-scope'] : (description?.match(/Requires scope `([^`]+)`/)?.[1] ?? null);
        const dangerMatch = typeof op['x-danger'] === 'string' ? op['x-danger'] : (description?.match(/Danger: ([a-z]+)/)?.[1] ?? null);

        if (dangerMatch !== null && !DANGERS.has(dangerMatch)) {
          throw new Error(`${this.#config.file}: ${method} ${path} has an unknown danger ${dangerMatch}`);
        }
        const responses = isRecord(op.responses) ? op.responses : {};

        let inputKind: Operation['inputKind'] = null;
        let inputSchema: Json | null = null;
        let inputRequired = false;

        if (op.requestBody !== undefined) {
          const body = this.#deref(op.requestBody, 'requestBodies');
          const content = isRecord(body.content) ? body.content : {};
          const json = content['application/json'];

          if (!isRecord(json)) {
            throw new Error(`${this.#config.file}: ${method} ${path} has a non-JSON body`);
          }

          if (query.length > 0) {
            throw new Error(`${this.#config.file}: ${method} ${path} has both a body and query parameters`);
          }

          inputKind = 'body';
          inputSchema = isRecord(json.schema) ? json.schema : {};
          const requiredProps = Array.isArray(inputSchema.required) ? inputSchema.required.length : 0;
          inputRequired = body.required === true && requiredProps > 0;
        } else if (query.length > 0) {
          inputKind = 'query';
          inputSchema = {
            type: 'object',
            properties: Object.fromEntries(
              query.map((p) => [
                p.name as string,
                { ...(isRecord(p.schema) ? p.schema : {}), ...(typeof p.description === 'string' ? { description: p.description } : {}) },
              ]),
            ),
            required: query.filter((p) => p.required === true).map((p) => p.name as string),
          };
          inputRequired = query.some((p) => p.required === true);
        }

        let responseSchema: Json | null = null;

        for (const code of ['200', '201', '204']) {
          if (responses[code] === undefined) continue;
          const response = this.#deref(responses[code], 'responses');
          const content = isRecord(response.content) ? response.content : {};
          const json = content['application/json'];
          responseSchema = isRecord(json) && isRecord(json.schema) ? json.schema : null;
          break;
        }

        // An action whose own answer is `202 Accepted` documents it as `oneOf` its body and
        // the approval body. The branch that is not the approval is the result.
        if (responseSchema === null && responses['202'] !== undefined && !['200', '201', '204'].some((c) => responses[c] !== undefined)) {
          const response = this.#deref(responses['202'], 'responses');
          const content = isRecord(response.content) ? response.content : {};
          const json = content['application/json'];
          const branches = isRecord(json) && isRecord(json.schema) && Array.isArray(json.schema.oneOf) ? json.schema.oneOf : [];
          const own = branches.find((b) => isRecord(b) && !JSON.stringify(b).includes('approval_required'));
          responseSchema = isRecord(own) ? own : null;
        }

        const queryNames = new Set(query.map((p) => p.name));

        ops.push({
          name: action !== null ? action.split('.') : this.#derivedName(method, path),
          action,
          operationId: typeof op.operationId === 'string' ? op.operationId : null,
          method: method.toUpperCase(),
          path,
          pathParams,
          summary: typeof op.summary === 'string' ? op.summary : undefined,
          description,
          scope,
          danger: dangerMatch !== null && DANGERS.has(dangerMatch) ? dangerMatch : null,
          approval: responses['202'] !== undefined && this.#isApprovalResponse(responses['202']),
          inputKind,
          inputRequired,
          inputSchema,
          responseSchema,
          pagination: queryNames.has('after') ? 'cursor' : queryNames.has('page') ? 'page' : null,
        });
      }
    }

    // The account and platform planes name every action `account.…` / `platform.…`. The client
    // already says which plane it is, so `me.sessions.revokeOthers()` rather than
    // `me.account.sessions.revokeOthers()`. Only when EVERY action shares the prefix.
    const prefix = this.#config.plane;
    const actions = ops.filter((o) => o.action !== null);

    if (actions.length > 0 && actions.every((o) => o.name[0] === prefix && o.name.length > 2)) {
      for (const op of actions) op.name = op.name.slice(1);
    }

    return ops.sort((a, b) => a.name.join('.').localeCompare(b.name.join('.')));
  }

  /** The element type of a paged list's `data` array. */
  #itemType(op: Operation): string {
    const properties = op.responseSchema !== null && isRecord(op.responseSchema.properties) ? op.responseSchema.properties : {};
    const data = properties.data;

    if (!isRecord(data) || data.type !== 'array') {
      throw new Error(`${this.#config.file}: paged ${op.name.join('.')} answers no data array`);
    }

    return this.type(data.items, '    ');
  }

  #isApprovalResponse(response: unknown): boolean {
    if (isRecord(response) && typeof response.$ref === 'string') {
      return response.$ref.endsWith('/ApprovalRequired');
    }

    return JSON.stringify(response).includes('approval_required');
  }

  /** A name for a route that is not an action, from its path: `GET /apis/{id}` → `apis.get`. */
  #derivedName(method: string, path: string): string[] {
    const rest = path.startsWith(`${this.#config.prefix}/`) ? path.slice(this.#config.prefix.length) : path;
    const segments = rest.split('/').filter((s) => s !== '');
    const resources = segments.filter((s) => !s.startsWith('{')).map((s) => s.replace(/-/g, '_'));
    const onItem = segments.length > 0 && segments[segments.length - 1]!.startsWith('{');
    const verb = { get: onItem ? 'get' : 'list', post: 'create', put: 'set', patch: 'update', delete: 'delete' }[method] ?? method;

    return [...resources, verb];
  }

  #claim(name: string): string {
    if (this.#used.has(name)) {
      throw new Error(`${this.#config.file}: generated type name ${name} collides`);
    }

    this.#used.add(name);
    return name;
  }

  render(): { code: string; operations: Operation[] } {
    const config = this.#config;
    const info = isRecord(this.#spec.info) ? this.#spec.info : {};
    const operations = this.operations();
    const opsConst = `${camel(config.plane)}Operations`;
    const out: string[] = [];

    out.push(
      `// GENERATED by scripts/generate-management.ts from openapi/${config.file}.yaml — do not edit.\n` +
        '// Regenerate with `npm run generate`.\n',
    );
    out.push(`import { ManagementTransport, type ManagementClientOptions } from '../transport.js';`);
    out.push(`import type { CallOptions, OperationSpec, Outcome } from '../types.js';\n`);

    // ── Schemas
    out.push(`// ── Schemas (components.schemas) ${'─'.repeat(60)}\n`);

    for (const [name, schema] of Object.entries(this.#schemas())) {
      const typeName = this.#typeNames.get(name)!;
      const description = isRecord(schema) && typeof schema.description === 'string' ? schema.description : undefined;
      const body = this.type(schema, '');
      out.push(
        body.startsWith('{')
          ? `${doc(description, '')}export interface ${typeName} ${body}\n`
          : `${doc(description, '')}export type ${typeName} = ${body};\n`,
      );
    }

    // ── Per-operation types
    out.push(`// ── Operation inputs and responses ${'─'.repeat(57)}\n`);
    const typeNames = new Map<Operation, { input: string | null; response: string }>();

    for (const op of operations) {
      const base = pascal(op.name);
      let input: string | null = null;

      if (op.inputKind !== null && op.inputSchema !== null) {
        input = this.#claim(`${base}${op.inputKind === 'body' ? 'Body' : 'Query'}`);
        const body = this.type(op.inputSchema, '');
        out.push(
          body.startsWith('{')
            ? `/** ${op.inputKind === 'body' ? 'Request body' : 'Query parameters'} of \`${op.name.join('.')}\`. */\nexport interface ${input} ${body}\n`
            : `export type ${input} = ${body};\n`,
        );
      }

      const response = this.#claim(`${base}Response`);
      const responseType = op.responseSchema === null ? 'void' : this.type(op.responseSchema, '');
      out.push(`/** Response body of \`${op.name.join('.')}\`. */\nexport type ${response} = ${responseType};\n`);
      typeNames.set(op, { input, response });
    }

    // ── Operation table
    out.push(`// ── Operations ${'─'.repeat(77)}\n`);
    out.push(doc(`Every operation of the ${info.title ?? config.plane} — method, path, scope and danger — keyed by action name.`, '').trimEnd());
    out.push(`export const ${opsConst} = {`);
    const keys = new Set<string>();

    for (const op of operations) {
      if (keys.has(tableKey(op))) throw new Error(`${config.file}: two operations are keyed ${tableKey(op)}`);
      keys.add(tableKey(op));
    }

    for (const op of operations) {
      const spec = [
        `action: ${op.action === null ? 'null' : literal(op.action)}`,
        `operationId: ${op.operationId === null ? 'null' : literal(op.operationId)}`,
        `method: '${op.method}'`,
        `path: ${literal(op.path)}`,
        `pathParams: [${op.pathParams.map(literal).join(', ')}]`,
        `scope: ${op.scope === null ? 'null' : literal(op.scope)}`,
        `danger: ${op.danger === null ? 'null' : literal(op.danger)}`,
        `approval: ${op.approval}`,
        `body: ${op.inputKind === 'body'}`,
        `pagination: ${op.pagination === null ? 'null' : literal(op.pagination)}`,
      ];
      out.push(`  ${literal(tableKey(op))}: { ${spec.join(', ')} },`);
    }

    out.push(`} as const satisfies Record<string, OperationSpec>;\n`);

    // ── Client
    out.push(`// ── Client ${'─'.repeat(81)}\n`);

    const servers = Array.isArray(this.#spec.servers) ? (this.#spec.servers as Json[]) : [];
    const fixedServer = servers.map((s) => s.url).find((u): u is string => typeof u === 'string' && !u.includes('{'));
    const defaultBase = fixedServer?.replace(/\/api\/v1\/?$/, '');
    const optionsType = `${config.className}Options`;

    out.push(
      defaultBase === undefined
        ? `/** Options for a {@link ${config.className}}. \`baseUrl\` is required: the environment's own host. */\nexport type ${optionsType} = ManagementClientOptions & { baseUrl: string };\n`
        : `/** Options for a {@link ${config.className}}. \`baseUrl\` defaults to \`${defaultBase}\`. */\nexport type ${optionsType} = ManagementClientOptions;\n`,
    );

    const description = typeof info.description === 'string' ? info.description.split('\n\n')[0] : undefined;
    out.push(doc(`${info.title ?? config.className}.\n\n${description ?? ''}`, '').trimEnd());
    out.push(`export class ${config.className} {`);
    out.push(`  /** The transport every method runs on — authentication, retries, approvals. */`);
    out.push(`  readonly transport: ManagementTransport;\n`);
    out.push(`  constructor(options: ${optionsType}) {`);
    out.push(
      `    this.transport = new ManagementTransport('${config.plane}', options${defaultBase === undefined ? '' : `, ${literal(defaultBase)}`});`,
    );
    out.push(`  }\n`);
    out.push(`  /** Call a route by method and path (relative to \`/api/v1\`) — for anything not generated. */`);
    out.push(`  request<TBody = unknown, O extends CallOptions = CallOptions>(`);
    out.push(`    method: OperationSpec['method'],`);
    out.push(`    path: string,`);
    out.push(`    input?: { query?: Record<string, unknown>; body?: unknown },`);
    out.push(`    options?: O,`);
    out.push(`  ): Promise<Outcome<TBody, O>> {`);
    out.push(`    return this.transport.request<TBody, O>(method, path, input, options);`);
    out.push(`  }\n`);

    // Build the namespace tree.
    interface Node {
      children: Map<string, Node>;
      ops: Operation[];
    }
    const root: Node = { children: new Map(), ops: [] };

    for (const op of operations) {
      let node = root;
      for (const segment of op.name.slice(0, -1)) {
        const key = camel(segment);
        if (!node.children.has(key)) node.children.set(key, { children: new Map(), ops: [] });
        node = node.children.get(key)!;
      }
      node.ops.push(op);
    }

    const renderNode = (node: Node, indent: string): string[] => {
      const lines: string[] = [];
      const members = new Set<string>();
      const claimMember = (name: string, where: string): string => {
        if (members.has(name) || node.children.has(name)) {
          throw new Error(`${config.file}: member ${name} collides at ${where}`);
        }
        members.add(name);
        return name;
      };

      for (const op of node.ops) {
        const leaf = claimMember(camel(op.name[op.name.length - 1]!), op.name.join('.'));
        const { input, response } = typeNames.get(op)!;
        const params = op.pathParams.map((p) => `${camel(p)}: string`);
        const args = `[${op.pathParams.map((p) => camel(p)).join(', ')}]`;

        if (input !== null) params.push(`${op.inputKind === 'body' ? 'body' : 'query'}${op.inputRequired ? '' : '?'}: ${input}`);

        const inputArg = input === null ? 'undefined' : op.inputKind === 'body' ? 'body' : 'query';
        const meta = [
          `\`${op.method} ${op.path}\`${op.action !== null ? ` · action \`${op.action}\`` : ''}`,
          ...(op.scope !== null ? [`@scope \`${op.scope}\``] : []),
          ...(op.danger !== null ? [`@danger ${op.danger}`] : []),
          ...(op.approval ? ['May be held for approval (`202 approval_required`); waited on unless `approval: \'return\'`.'] : []),
        ];
        const summary = op.summary ?? '';
        const details = op.description !== undefined && op.description.trim() !== '' ? `\n\n${op.description}` : '';
        lines.push(doc(`${summary}${details}`, indent, ['', ...meta]).trimEnd());
        lines.push(
          `${indent}${leaf}: <O extends CallOptions = CallOptions>(${[...params, 'options?: O'].join(', ')}): Promise<Outcome<${response}, O>> =>`,
        );
        lines.push(`${indent}  this.transport.call<${response}, O>(${opsConst}[${literal(tableKey(op))}], ${args}, ${inputArg}, options),`);

        if (op.pagination !== null) {
          const all = claimMember(`${leaf}All`, `${op.name.join('.')}All`);
          const queryParams = op.pathParams.map((p) => `${camel(p)}: string`);
          queryParams.push(`query?: ${input === null ? 'Record<string, unknown>' : `Omit<${input}, '${op.pagination === 'cursor' ? 'after' : 'page'}'>`}`);
          queryParams.push(`options?: Omit<CallOptions, 'approval'>`);
          lines.push(
            doc(
              `Every item of \`${op.name.join('.')}\`, fetching pages as the iteration reaches them.`,
              indent,
            ).trimEnd(),
          );
          lines.push(
            `${indent}${all}: (${queryParams.join(', ')}): AsyncGenerator<${this.#itemType(op)}, void, undefined> =>`,
          );
          lines.push(
            `${indent}  this.transport.paginate(${opsConst}[${literal(tableKey(op))}], ${args}, query as Record<string, unknown> | undefined, options),`,
          );
        }
      }

      for (const [key, child] of node.children) {
        lines.push(`${indent}${key}: {`);
        lines.push(...renderNode(child, `${indent}  `));
        lines.push(`${indent}},`);
      }

      return lines;
    };

    for (const [key, child] of root.children) {
      out.push(`  readonly ${key} = {`);
      out.push(...renderNode(child, '    '));
      out.push(`  };\n`);
    }

    if (root.ops.length > 0) {
      throw new Error(`${config.file}: an operation has a single-segment name: ${root.ops.map((o) => o.name.join('.')).join(', ')}`);
    }

    out.push(`}\n`);

    return { code: `${out.join('\n').replace(/\n{3,}/g, '\n\n').trimEnd()}\n`, operations };
  }
}

/** Generate one plane's client source from its parsed spec. */
export function generatePlane(spec: Json, config: PlaneConfig): { code: string; operations: number; skipped: string[] } {
  if (typeof spec.openapi !== 'string' || !spec.openapi.startsWith('3.')) {
    throw new Error(`${config.file}: not an OpenAPI 3 document`);
  }

  const generator = new Generator(spec, config);
  const { code, operations } = generator.render();

  return { code, operations: operations.length, skipped: generator.skipped };
}

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');

/** Generate every plane from the vendored specs in `openapi/`. Keyed by output path. */
export async function generateAll(root: string = ROOT): Promise<Map<string, { code: string; operations: number; skipped: string[] }>> {
  const results = new Map<string, { code: string; operations: number; skipped: string[] }>();

  for (const config of PLANES) {
    const spec = parse(await readFile(join(root, 'openapi', `${config.file}.yaml`), 'utf8')) as Json;
    results.set(join(root, 'src', 'management', 'generated', `${config.file}.ts`), generatePlane(spec, config));
  }

  return results;
}

async function fetchSpec(config: PlaneConfig, target: string): Promise<void> {
  const url = target.endsWith('.yaml') || target.endsWith('.json') ? target : `${target.replace(/\/+$/, '')}${config.specPath}`;
  const response = await fetch(url, { headers: { accept: 'application/yaml, application/json' } });

  if (!response.ok) {
    throw new Error(`GET ${url} answered ${response.status}`);
  }

  const text = await response.text();
  const parsed = parse(text) as unknown;

  if (!isRecord(parsed) || typeof parsed.openapi !== 'string') {
    throw new Error(`GET ${url} did not return an OpenAPI document`);
  }

  await writeFile(join(ROOT, 'openapi', `${config.file}.yaml`), text);
  process.stdout.write(`fetched ${config.file} ← ${url}\n`);
}

async function main(argv: string[]): Promise<number> {
  const check = argv.includes('--check');

  for (let i = 0; i < argv.length; i++) {
    if (argv[i] !== '--fetch') continue;
    const [plane, url] = (argv[++i] ?? '').split(/=(.*)/s);

    if (!plane || !url) {
      throw new Error('--fetch takes plane=url, e.g. --fetch environment=https://acme.cboxid.com');
    }

    const targets = plane === 'all' ? PLANES : PLANES.filter((p) => p.plane === plane);

    if (targets.length === 0) {
      throw new Error(`Unknown plane ${plane}; use ${PLANES.map((p) => p.plane).join(', ')} or all`);
    }

    for (const config of targets) {
      await fetchSpec(config, url);
    }
  }

  let stale = false;

  for (const [path, result] of await generateAll()) {
    const current = await readFile(path, 'utf8').catch(() => '');

    if (check) {
      if (current !== result.code) {
        process.stderr.write(`stale: ${path}\n`);
        stale = true;
      }
      continue;
    }

    await mkdir(dirname(path), { recursive: true });
    await writeFile(path, result.code);
    process.stdout.write(`${path}: ${result.operations} operations${result.skipped.length > 0 ? `, skipped ${result.skipped.length} (other credentials)` : ''}\n`);
  }

  if (stale) {
    process.stderr.write('Run `npm run generate` and commit the result.\n');
    return 1;
  }

  return 0;
}

if (process.argv[1] !== undefined && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main(process.argv.slice(2)).then(
    (code) => process.exit(code),
    (error: unknown) => {
      process.stderr.write(`${error instanceof Error ? error.message : String(error)}\n`);
      process.exit(1);
    },
  );
}
