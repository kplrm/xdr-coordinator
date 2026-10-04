const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { test } = require('node:test');

// Load the real TypeScript routes without starting OpenSearch Dashboards.
const root = process.env.OSD_ROOT || path.resolve(__dirname, '../../OpenSearch-Dashboards');
process.env.NODE_PATH = [path.join(root, 'node_modules'), process.env.NODE_PATH]
  .filter(Boolean)
  .join(path.delimiter);
require('node:module').Module._initPaths();
const ts = require('typescript');
require.extensions['.ts'] = (module, filename) => module._compile(
  ts.transpileModule(fs.readFileSync(filename, 'utf8'), {
    compilerOptions: { module: ts.ModuleKind.CommonJS, target: ts.ScriptTarget.ES2020 },
  }).outputText,
  filename
);

const { defineRoutes } = require('../server/routes/index.ts');
const {
  XDR_AGENT_SAVED_OBJECT_TYPE: AGENT,
  XDR_ENROLLMENT_TOKEN_SAVED_OBJECT_TYPE: TOKEN,
  XDR_POLICY_SAVED_OBJECT_TYPE: POLICY,
} = require('../common/index.ts');

// This list must agree with both registered routes and the Agent API document.
const expected = [
  'POST /api/v1/agents/enroll',
  'POST /api/v1/agents/heartbeat',
  'GET /api/v1/agents/commands',
  'POST /api/v1/agents/telemetry',
  'POST /api/v1/agents/security',
  'POST /api/v1/agents/logs',
];
const exercised = new Set();

const response = Object.fromEntries(
  Object.entries({ ok: 200, badRequest: 400, unauthorized: 401, forbidden: 403, notFound: 404, conflict: 409 })
    .map(([name, status]) => [name, ({ body }) => ({ status, body })])
);
response.customError = ({ statusCode, body }) => ({ status: statusCode, body });

// Replace saved objects and OpenSearch with in-memory fakes, but invoke real route handlers.
function fixture() {
  const objects = new Map();
  const batches = [];
  let next = 0;
  const repo = {
    async get(type, id) {
      const found = objects.get(`${type}:${id}`);
      if (!found) throw { output: { statusCode: 404 } };
      return structuredClone(found);
    },
    async find({ type, search }) {
      return {
        saved_objects: [...objects.values()]
          .filter((item) => item.type === type && (!search || item.attributes.token === search))
          .map((item) => structuredClone(item)),
      };
    },
    async create(type, attributes, options = {}) {
      const id = options.id || String(++next);
      const item = { id, type, attributes: structuredClone(attributes) };
      objects.set(`${type}:${id}`, item);
      return item;
    },
    async update(type, id, attributes) {
      const old = await this.get(type, id);
      const item = { ...old, attributes: { ...old.attributes, ...structuredClone(attributes) } };
      objects.set(`${type}:${id}`, item);
      return item;
    },
    async delete(type, id) {
      objects.delete(`${type}:${id}`);
      return {};
    },
  };

  const routes = new Map();
  const router = {};
  for (const method of ['get', 'post', 'put', 'delete', 'patch']) {
    router[method] = (config, handler) =>
      routes.set(`${method.toUpperCase()} ${config.path}`, { config, handler });
  }
  defineRoutes(router, { warn() {}, error() {}, info() {} }, Promise.resolve(repo));

  const context = {
    core: {
      opensearch: {
        client: {
          asInternalUser: {
            bulk: async ({ body }) => {
              batches.push(body);
              return { body: { errors: false, items: [] } };
            },
          },
        },
      },
    },
  };

  // Apply each route's real request schema before calling its handler.
  const call = async (key, input = {}) => {
    assert.ok(routes.has(key), `missing ${key}`);
    if (expected.includes(key)) exercised.add(key);
    const { config, handler } = routes.get(key);
    const req = { headers: { authorization: 'Bearer test-token' }, params: {}, query: {}, ...input };
    if (config.validate) {
      for (const [kind, validator] of Object.entries(config.validate)) {
        req[kind] = validator.validate(req[kind] || {});
      }
    }
    return handler(context, req, response);
  };

  const seed = async () => {
    await repo.create(TOKEN, {
      token: 'test-token', policyId: 'default-endpoint',
      createdAt: new Date().toISOString(), consumedAgentId: 'agent-1',
    }, { id: 'token-1' });
    await repo.create(AGENT, {
      name: 'host', policyId: 'default-endpoint', enrollmentToken: 'test-token',
      status: 'healthy', lastSeen: new Date().toISOString(), tags: [],
      version: '1.0.0', pendingUpgradeVersion: '2.0.0',
    }, { id: 'agent-1' });
  };
  return { repo, routes, call, context, batches, seed };
}

const identity = {
  agent_id: 'agent-1', machine_id: 'machine-1', hostname: 'host',
  policy_id: 'default-endpoint', tags: ['linux'], agent_version: '1.0.0',
};
// A minimal intake event tests routing and indexing, not collector-specific payloads.
const event = (module, kind = 'event') => ({
  id: 'event-1',
  '@timestamp': new Date().toISOString(),
  'event.type': module === 'agent.logger' ? 'agent.log' : 'fixture',
  'event.module': module,
  'event.kind': kind,
  'event.category': 'process',
  'event.severity': 0,
  'agent.id': 'spoofed',
  'host.hostname': 'host',
  payload: {},
});

test('registered agent routes exactly match the maintained contract', () => {
  const { routes } = fixture();
  assert.deepEqual(
    [...routes.keys()].filter((key) => key.includes('/api/v1/agents/')).sort(),
    [...expected].sort()
  );
  const doc = path.resolve(__dirname, '../../xdr-agent/docs/api-endpoints.md');
  if (fs.existsSync(doc)) {
    const rows = [...fs.readFileSync(doc, 'utf8')
      .matchAll(/^\| (GET|POST|PUT|DELETE|PATCH) \| (\/api\/[^ ]+) \|/gm)]
      .map((match) => `${match[1]} ${match[2]}`);
    assert.deepEqual(rows.sort(), [...expected].sort());
  }
});

test('enrollment is authenticated, idempotent, and binds a token to one agent', async () => {
  const f = fixture();
  await f.repo.create(TOKEN, { token: 'test-token', policyId: 'default-endpoint' }, { id: 'token-1' });
  const body = { ...identity, architecture: 'amd64', os_type: 'linux', ip_addresses: ['127.0.0.1'] };
  assert.equal((await f.call(expected[0], { body, headers: {} })).status, 401);
  assert.equal((await f.call(expected[0], { body })).status, 200);
  assert.equal((await f.call(expected[0], { body })).status, 200);
  assert.equal((await f.call(expected[0], { body: { ...body, agent_id: 'other' } })).status, 401);
  const token = await f.repo.get(TOKEN, 'token-1');
  assert.equal(token.attributes.consumedAgentId, 'agent-1');
});

test('heartbeat records degraded health and retains the assigned group; command completion clears upgrades', async () => {
  const f = fixture();
  await f.seed();
  await f.repo.update(AGENT, 'agent-1', { policyId: 'server-group' });
  const protection = {
    rule_source: 'YARA Forge Core', rule_version: '2026-09-27', rule_count: 10,
    mode: 'prevent', platform: 'linux', rules_sha256: 'a'.repeat(64),
    health: { execution_blocking: 'degraded: fixture' },
  };
  const hb = await f.call(expected[1], { body: { ...identity, protection } });
  assert.equal(hb.status, 200);
  assert.deepEqual(hb.body.pending_commands, ['upgrade:2.0.0']);
  const agent = (await f.repo.get(AGENT, 'agent-1')).attributes;
  assert.equal(agent.status, 'degraded');
  assert.equal(agent.policyId, 'server-group');
  assert.deepEqual(agent.protection, protection);
  assert.equal((await f.call(expected[1], { body: identity, headers: { authorization: 'Bearer wrong' } })).status, 401);
  assert.equal((await f.call(expected[2], { query: { agent_id: 'agent-1', agent_version: '1.0.0' } })).status, 200);
  const done = await f.call(expected[2], { query: { agent_id: 'agent-1', agent_version: '2.0.0' } });
  assert.equal(done.body.pending_commands, undefined);
});

// Each intake route must authenticate, normalize the owner, reject wrong topics, and report bulk errors.
for (const [topic, module, kind] of [
  ['telemetry', 'telemetry.process', 'event'],
  ['security', 'detection.malware', 'alert'],
  ['logs', 'agent.logger', 'event'],
]) {
  test(`${topic} intake authenticates, indexes, rejects topic mismatch and reports backend failure`, async () => {
    const f = fixture();
    await f.seed();
    const route = `POST /api/v1/agents/${topic}`;
    const body = { agent_id: 'agent-1', events: [event(module, kind)] };
    assert.equal((await f.call(route, { body, headers: {} })).status, 401);
    assert.equal((await f.call(route, { body })).body.indexed, 1);
    assert.equal(f.batches[0][1]['agent.id'], 'agent-1');
    assert.equal(f.batches[0][0].index._id, 'agent-1:event-1');
    const wrong = event(
      topic === 'security' ? 'telemetry.process' : 'detection.malware',
      topic === 'security' ? 'event' : 'alert'
    );
    assert.equal((await f.call(route, { body: { ...body, events: [wrong] } })).status, 400);
    f.context.core.opensearch.client.asInternalUser.bulk = async () => ({
      body: { errors: true, items: [{ index: { error: { reason: 'fixture' } } }] },
    });
    assert.equal((await f.call(route, { body })).status, 502);
    await f.repo.delete(TOKEN, 'token-1');
    assert.equal((await f.call(route, { body })).status, 401);
  });
}

test('token status, tagging, revocation, and grouping CRUD remain functional', async () => {
  const f = fixture();
  await f.seed();
  const params = { token: 'test-token' };
  assert.equal((await f.call('GET /api/xdr_manager/enrollment_tokens/{token}/status', { params })).status, 200);
  assert.equal((await f.call('PUT /api/xdr_manager/enrollment_tokens/{token}/tag', { params, body: { tag: 'lab' } })).status, 200);
  const created = await f.call('POST /api/xdr_manager/policies', { body: { name: 'Lab', description: 'Lab agents' } });
  assert.equal(created.status, 200);
  assert.equal((await f.repo.find({ type: POLICY })).saved_objects.length, 1);
  assert.equal((await f.call('DELETE /api/xdr_manager/enrollment_tokens/{token}', { params })).status, 200);
});

test('every documented endpoint was exercised', () =>
  assert.deepEqual([...exercised].sort(), [...expected].sort()));
