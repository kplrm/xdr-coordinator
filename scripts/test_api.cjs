const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const https = require('node:https');
const { EventEmitter } = require('node:events');
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
const { summarizeBulkFailures } = require('../server/bulk_index_error.ts');
const { installTelemetryIsmPolicy } = require('../server/telemetry_ism_installer.ts');
const { installSecurityIsmPolicy } = require('../server/security_ism_installer.ts');
const { installAgentLogsIsmPolicy } = require('../server/logs_ism_installer.ts');
const { installEventIndexPatterns } = require('../server/event_index_pattern_installer.ts');
const { XdrManagerPlugin: BrowserPlugin } = require('../public/plugin.ts');
const {
  XDR_AGENT_SAVED_OBJECT_TYPE: AGENT,
  XDR_ENROLLMENT_TOKEN_SAVED_OBJECT_TYPE: TOKEN,
  XDR_POLICY_SAVED_OBJECT_TYPE: POLICY,
  UNMANAGED_CONFIG_REVISION,
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
function fixture(ingestionReady) {
  const objects = new Map();
  const batches = [];
  const errors = [];
  let next = 0;
  let revision = 0;
  // SavedObjects.update uses OpenSearch's partial-document merge, including
  // nested objects. In particular, updating an object to {} does not clear it.
  const mergeDocument = (existing, update) => {
    const merged = structuredClone(existing);
    for (const [key, value] of Object.entries(update)) {
      merged[key] = value && !Array.isArray(value) && typeof value === 'object' &&
        merged[key] && !Array.isArray(merged[key]) && typeof merged[key] === 'object'
        ? mergeDocument(merged[key], value) : structuredClone(value);
    }
    return merged;
  };
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
      if (objects.has(`${type}:${id}`) && !options.overwrite) {
        throw { output: { statusCode: 409 } };
      }
      const item = { id, type, version: String(++revision), attributes: structuredClone(attributes) };
      objects.set(`${type}:${id}`, item);
      return item;
    },
    async update(type, id, attributes, options = {}) {
      const old = await this.get(type, id);
      if (options.version !== undefined && options.version !== objects.get(`${type}:${id}`).version) throw { output: { statusCode: 409 } };
      const item = { ...old, version: String(++revision), attributes: mergeDocument(old.attributes, attributes) };
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
  defineRoutes(router, { warn() {}, error: (message) => errors.push(message), info() {} }, Promise.resolve(repo), ingestionReady);

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
  return { repo, routes, call, context, batches, errors, seed };
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

test('only a published stable release with both uploaded packages is offered; requests and failures are cached', async (t) => {
  let reply;
  const requests = [];
  t.mock.method(https, 'request', (options, onResponse) => {
    requests.push(options);
    const request = new EventEmitter();
    request.setTimeout = () => request;
    request.end = () => queueMicrotask(() => {
      const response = new EventEmitter();
      response.statusCode = reply.status;
      response.headers = reply.headers ?? {};
      onResponse(response);
      response.emit('data', Buffer.from(reply.body));
      response.emit('end');
    });
    return request;
  });
  const f = fixture();
  let now = Date.now();
  t.mock.method(Date, 'now', () => now);
  const release = { tag_name: 'v2.0.0', draft: false, prerelease: false, assets: ['amd64', 'arm64'].map((arch) => ({
    name: `xdr-agent_2.0.0_${arch}.deb`, state: 'uploaded', size: 123,
    browser_download_url: `https://github.com/kplrm/xdr-agent/releases/download/v2.0.0/xdr-agent_2.0.0_${arch}.deb`,
  })) };
  for (reply of [
    { status: 404, body: '1.2.3' },
    { status: 200, body: JSON.stringify({ ...release, assets: release.assets.slice(0, 1) }) },
    { status: 200, body: JSON.stringify({ ...release, draft: true }) },
    { status: 200, body: JSON.stringify({ ...release, prerelease: true }) },
    { status: 200, body: '1.2.3;id' },
  ]) {
    assert.equal((await f.call('GET /api/xdr_manager/version/latest')).status, 502);
    const count = requests.length;
    assert.equal((await f.call('GET /api/xdr_manager/version/latest')).status, 502);
    assert.equal(requests.length, count, 'failed lookups must not repeat on every fleet poll');
    now += 5 * 60_000 + 1;
  }
  reply = { status: 403, body: '{}', headers: { 'retry-after': '3600' } };
  assert.equal((await f.call('GET /api/xdr_manager/version/latest')).status, 502);
  const limitedCount = requests.length;
  now += 5 * 60_000 + 1;
  assert.equal((await f.call('GET /api/xdr_manager/version/latest')).status, 502);
  assert.equal(requests.length, limitedCount, 'GitHub cooldown must extend the normal cache window');
  now += 3600_000;
  reply = { status: 200, body: JSON.stringify(release) };
  const count = requests.length;
  const answers = await Promise.all([f.call('GET /api/xdr_manager/version/latest'), f.call('GET /api/xdr_manager/version/latest')]);
  assert.deepEqual(answers[0], { status: 200, body: { version: '2.0.0' } });
  assert.equal((await f.call('GET /api/xdr_manager/agents')).body.latestVersion, '2.0.0');
  assert.equal(requests.length, count + 1, 'concurrent and subsequent callers share one request');
  for (const request of requests) {
    assert.equal(request.hostname, 'api.github.com');
    assert.equal(request.path, '/repos/kplrm/xdr-agent/releases/latest');
  }
});

test('bulk diagnostics identify status, field and causes without logging event values', () => {
  const error = { index: { status: 400, error: {
    type: 'mapper_parsing_exception',
    reason: "failed to parse field [payload.process.command_line] of type [keyword]. Preview of field's value: 'secret-input'",
    caused_by: { type: 'illegal_argument_exception', reason: 'sensitive payload' },
  } } };
  const summary = summarizeBulkFailures([error, error, error, error]);
  assert.equal(JSON.parse(summary).length, 3);
  assert.deepEqual(JSON.parse(summary)[0], {
    status: 400, field: 'payload.process.command_line',
    causes: ['mapper_parsing_exception', 'illegal_argument_exception'],
  });
  assert.doesNotMatch(summary, /secret-input|sensitive payload/);
  assert.equal(JSON.parse(summarizeBulkFailures([{ index: { status: 403, error: {
    type: 'security_exception', reason: 'no permissions for [indices:data/write/index]',
  } } }]))[0].causes[0], 'security_exception');
});

test('startup bounds process keywords in the template and telemetry stream', async () => {
  let template;
  let update;
  const warnings = [];
  await installTelemetryIsmPolicy({
    transport: { request: async ({ method }) => {
      if (method === 'GET') throw { statusCode: 404 };
      return {};
    } },
    indices: {
      putIndexTemplate: async (request) => { template = request; },
      putMapping: async (request) => { update = request; },
    },
  }, { info() {}, debug() {}, warn: (message) => warnings.push(message) });
  assert.deepEqual(warnings, []);
  assert.equal(update.index, 'xdr-agent-telemetry');
  assert.equal(update.expand_wildcards, 'open,hidden');
  assert.equal(update.allow_no_indices, true);
  assert.equal(update.ignore_unavailable, true);
  const newProcess = template.body.template.mappings.properties.payload.properties.process.properties;
  const existingProcess = update.body.properties.payload.properties.process.properties;
  for (const process of [newProcess, existingProcess]) {
    for (const fields of [process, process.parent.properties]) {
      for (const name of ['command_line', 'args']) {
        assert.equal(fields[name].type, 'keyword');
        assert.equal(fields[name].ignore_above, 8191);
      }
    }
  }
  assert.deepEqual(Object.keys(existingProcess).sort(), ['args', 'command_line', 'parent']);
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

test('upgrade dispatch is spaced, limited to three attempts, and survives repeated or concurrent polls', async () => {
  const f = fixture();
  await f.seed();
  const poll = () => f.call(expected[2], { query: { agent_id: 'agent-1', agent_version: '1.0.0' } });
  const first = await poll();
  assert.deepEqual(first.body.pending_commands, ['upgrade:2.0.0']);
  for (let i = 0; i < 20; i++) assert.equal((await poll()).body.pending_commands, undefined);
  const due = async () => {
    const stored = await f.repo.get(AGENT, 'agent-1');
    await f.repo.update(AGENT, 'agent-1', { upgrade: { ...stored.attributes.upgrade, nextAttemptAt: '2000-01-01T00:00:00Z' } });
  };
  await due();
  const concurrent = await Promise.all([poll(), poll()]);
  assert.equal(concurrent.filter((answer) => answer.body.pending_commands).length, 1);
  assert.equal((await f.repo.get(AGENT, 'agent-1')).attributes.upgrade.attempts, 2);
  await due();
  assert.ok((await poll()).body.pending_commands);
  await due();
  assert.equal((await poll()).body.pending_commands, undefined);
  const failed = (await f.repo.get(AGENT, 'agent-1')).attributes.upgrade;
  assert.equal(failed.status, 'failed');
  assert.equal(failed.attempts, 3);
  for (let i = 0; i < 20; i++) assert.equal((await poll()).body.pending_commands, undefined);
  const retried = await f.call('POST /api/xdr_manager/agents/{id}/action', { params: { id: 'agent-1' }, body: { action: 'upgrade' } });
  assert.equal(retried.body.agent.upgrade.attempts, 0);
  assert.notEqual(retried.body.agent.upgrade.id, failed.id);
  assert.equal(retried.body.agent.upgrade.status, 'queued');
});

test('reported failures stop permanent downloads and preserve rate-limit cooldown across an explicit retry', async () => {
  const f = fixture();
  await f.seed();
  const query = { agent_id: 'agent-1', agent_version: '1.0.0' };
  const dispatched = await f.call(expected[2], { query });
  const retryAt = Math.floor(Date.now() / 1000) + 3600;
  await f.call(expected[1], { body: {
    ...identity, upgrade_id: dispatched.body.upgrade_id, upgrade_error: 'download: HTTP 429', upgrade_retryable: false, upgrade_retry_at: retryAt,
  } });
  const failed = (await f.repo.get(AGENT, 'agent-1')).attributes.upgrade;
  assert.equal(failed.status, 'failed');
  assert.equal(failed.attempts, 1);
  assert.ok(Date.parse(failed.nextAttemptAt) >= retryAt * 1000);
  assert.equal((await f.call(expected[2], { query })).body.pending_commands, undefined);
  const next = await f.call('POST /api/xdr_manager/agents/{id}/action', { params: { id: 'agent-1' }, body: { action: 'upgrade' } });
  assert.notEqual(next.body.agent.upgrade.id, failed.id);
  assert.equal(next.body.agent.upgrade.nextAttemptAt, failed.nextAttemptAt);
  assert.equal((await f.call(expected[2], { query })).body.pending_commands, undefined);
  await f.call(expected[1], { body: { ...identity, upgrade_id: dispatched.body.upgrade_id, upgrade_error: 'stale failure' } });
  assert.equal((await f.repo.get(AGENT, 'agent-1')).attributes.upgrade.status, 'queued');
});

test('unpublished legacy queues are stopped and upgrades never downgrade newer installed agents', async () => {
  const f = fixture();
  await f.seed();
  await f.repo.update(AGENT, 'agent-1', { pendingUpgradeVersion: '9.0.0' });
  assert.equal((await f.call(expected[2], { query: { agent_id: 'agent-1', agent_version: '1.0.0' } })).body.pending_commands, undefined);
  assert.equal((await f.repo.get(AGENT, 'agent-1')).attributes.upgrade.status, 'failed');
  await f.repo.update(AGENT, 'agent-1', { version: '3.0.0' });
  assert.equal((await f.call('POST /api/xdr_manager/agents/{id}/action', { params: { id: 'agent-1' }, body: { action: 'upgrade' } })).status, 400);
});

test('the default policy is editable, persistent, and listed once', async () => {
  const f = fixture();
  const config = { internal_networks: ['10.0.0.0/8', 'fc00::/7'], network_scan_interval_seconds: 2 };
  const result = await f.call('PUT /api/xdr_manager/policies/{id}', {
    params: { id: 'default-endpoint' },
    body: { name: 'Managed endpoints', description: 'Fleet defaults', config },
  });
  assert.equal(result.status, 200);
  assert.match(result.body.policy.configRevision, /^[a-f0-9]{32}$/);
  const stored = await f.repo.get(POLICY, 'default-endpoint');
  assert.deepEqual(stored.attributes.config, config);
  assert.equal(stored.attributes.configRevision, result.body.policy.configRevision);
  const listed = (await f.call('GET /api/xdr_manager/policies')).body.policies;
  assert.equal(listed.filter((policy) => policy.id === 'default-endpoint').length, 1);
  assert.equal(listed[0].name, 'Managed endpoints');
  assert.deepEqual(listed[0].config, config);
  assert.equal((await f.call('DELETE /api/xdr_manager/policies/{id}', {
    params: { id: 'default-endpoint' },
  })).status, 400);
});

test('policy revisions preserve settings on rename or omission and advance on change or removal', async () => {
  const f = fixture();
  const metadata = { name: 'Lab', description: 'Lab agents' };
  const config = { internal_networks: ['192.168.0.0/16'], telemetry_ship_interval_seconds: 5 };
  const created = (await f.call('POST /api/xdr_manager/policies', {
    body: { ...metadata, config },
  })).body.policy;
  assert.ok(created.configRevision);
  const params = { id: created.id };
  const rename = (await f.call('PUT /api/xdr_manager/policies/{id}', {
    params, body: { name: 'Renamed lab', description: 'Updated description' },
  })).body.policy;
  assert.equal(rename.configRevision, created.configRevision);
  assert.deepEqual(rename.config, config);
  const same = (await f.call('PUT /api/xdr_manager/policies/{id}', {
    params, body: { ...metadata, config: {
      telemetry_ship_interval_seconds: 5, internal_networks: ['192.168.0.0/16'],
    } },
  })).body.policy;
  assert.equal(same.configRevision, created.configRevision, 'object key order is immaterial');
  const changed = (await f.call('PUT /api/xdr_manager/policies/{id}', {
    params, body: { ...metadata, config: { ...config, telemetry_ship_interval_seconds: 7 } },
  })).body.policy;
  assert.notEqual(changed.configRevision, created.configRevision);
  const removed = (await f.call('PUT /api/xdr_manager/policies/{id}', {
    params, body: { ...metadata, config: { telemetry_ship_interval_seconds: 7 } },
  })).body.policy;
  assert.notEqual(removed.configRevision, changed.configRevision);
  assert.deepEqual((await f.repo.get(POLICY, created.id)).attributes.config,
    { telemetry_ship_interval_seconds: 7 }, 'removed overrides must disappear from stored settings');
  const cleared = (await f.call('PUT /api/xdr_manager/policies/{id}', {
    params, body: { ...metadata, config: {} },
  })).body.policy;
  assert.deepEqual(cleared.config, {});
  assert.notEqual(cleared.configRevision, removed.configRevision);
  const unchanged = (await f.call('PUT /api/xdr_manager/policies/{id}', {
    params, body: { ...metadata, config: {} },
  })).body.policy;
  assert.equal(unchanged.configRevision, cleared.configRevision);
  assert.deepEqual((await f.repo.get(POLICY, created.id)).attributes.config, {});
});

test('heartbeat and commands deliver managed settings from the server-assigned policy', async () => {
  const f = fixture();
  await f.seed();
  const config = { internal_networks: [], process_scan_interval_seconds: 3 };
  const assigned = (await f.call('POST /api/xdr_manager/policies', {
    body: { name: 'Servers', description: 'Server configuration', config },
  })).body.policy;
  await f.call('PUT /api/xdr_manager/policies/{id}', {
    params: { id: 'default-endpoint' }, body: {
      name: 'Default', description: 'Different settings', config: { network_scan_interval_seconds: 17 },
    },
  });
  await f.repo.update(AGENT, 'agent-1', { policyId: assigned.id });
  const desired = { schema_version: 1, revision: assigned.configRevision, settings: config };
  const heartbeat = await f.call(expected[1], { body: identity });
  assert.equal(heartbeat.status, 200);
  assert.deepEqual(heartbeat.body.managed_config, desired);
  assert.equal((await f.repo.get(AGENT, 'agent-1')).attributes.policyId, assigned.id);
  const beforePoll = await f.repo.get(AGENT, 'agent-1');
  const commands = await f.call(expected[2], {
    query: { agent_id: 'agent-1', agent_version: '1.0.0' },
  });
  assert.deepEqual(commands.body.managed_config, desired);
  assert.deepEqual(await f.repo.get(AGENT, 'agent-1'), beforePoll,
    'configuration delivery does not write applied status or heartbeat time');
});

test('legacy policies without managed settings do not change agent responses', async () => {
  const f = fixture();
  await f.seed();
  for (const policyId of ['default-endpoint', 'legacy-group', 'missing-group']) {
    let assignedPolicyId = policyId;
    if (policyId === 'legacy-group') {
      const result = await f.call('POST /api/xdr_manager/policies', {
        body: { name: 'Legacy group', description: 'Grouping only' },
      });
      assert.equal(result.body.policy.configRevision, undefined);
      assignedPolicyId = result.body.policy.id;
    }
    await f.repo.update(AGENT, 'agent-1', { policyId: assignedPolicyId });
    assert.equal((await f.call(expected[1], { body: identity })).body.managed_config, undefined);
    assert.equal((await f.call(expected[2], {
      query: { agent_id: 'agent-1', agent_version: '0.4.3' },
    })).body.managed_config, undefined);
  }
});

test('moving a managed agent to an unmanaged policy releases its previous overrides', async () => {
  const f = fixture();
  await f.seed();
  const desired = { schema_version: 1, revision: UNMANAGED_CONFIG_REVISION, settings: {} };
  // The first acknowledgement may arrive in this heartbeat, after reassignment.
  const heartbeat = await f.call(expected[1], {
    body: { ...identity, config_revision: 'previous-policy' },
  });
  assert.deepEqual(heartbeat.body.managed_config, desired);
  const query = { agent_id: 'agent-1', agent_version: '1.0.0' };
  assert.deepEqual((await f.call(expected[2], { query })).body.managed_config, desired);
  await f.call(expected[1], { body: { ...identity, config_revision: desired.revision } });
  assert.deepEqual((await f.call(expected[2], { query })).body.managed_config, desired);
  // A missing assigned policy also cannot retain the former group's settings.
  await f.repo.update(AGENT, 'agent-1', { policyId: 'removed-group' });
  assert.deepEqual((await f.call(expected[2], { query })).body.managed_config, desired);
});

test('managed settings reject invalid CIDRs, unsupported keys, and unsafe interval values', async () => {
  const f = fixture();
  const metadata = { name: 'Invalid', description: 'Must not persist' };
  const invalid = [
    ...['10.0.0.0/33', 'fc00::/129', '10.0.0.0', '10.0.0.0/-1', '10.0.0.0/1.5',
      '10.0.0.0/8/1', 'fe80::1%eth0/64', '999.1.1.1/24'].map((cidr) => ({ internal_networks: [cidr] })),
    { internal_networks: Array(257).fill('10.0.0.0/8') },
    { unknown_setting: true }, { enrollment_token: 'secret' },
    { control_plane_url: 'https://other.example' }, { state_path: '/tmp/other.json' },
    { opensearch: { url: 'https://other.example' } }, { detection_prevention: { mode: 'prevent' } },
    ...['process_scan_interval_seconds', 'network_scan_interval_seconds', 'telemetry_ship_interval_seconds']
      .flatMap((key) => [0, -1, 0.5, 86401].map((value) => ({ [key]: value }))),
  ];
  for (const config of invalid) {
    await assert.rejects(f.call('POST /api/xdr_manager/policies', {
      body: { ...metadata, config },
    }), undefined, JSON.stringify(config));
  }
  assert.equal((await f.repo.find({ type: POLICY })).saved_objects.length, 0);
  const accepted = await f.call('POST /api/xdr_manager/policies', {
    body: { ...metadata, config: {
      internal_networks: ['10.0.0.0/8', 'fc00::/7', '::/0'],
      process_scan_interval_seconds: 1, network_scan_interval_seconds: 86400,
      telemetry_ship_interval_seconds: 5,
    } },
  });
  assert.equal(accepted.status, 200);
});

test('managed settings require the bound token and are hidden after revocation', async () => {
  const f = fixture();
  await f.seed();
  await f.call('PUT /api/xdr_manager/policies/{id}', {
    params: { id: 'default-endpoint' }, body: {
      name: 'Default', description: 'Managed', config: { network_scan_interval_seconds: 2 },
    },
  });
  const query = { agent_id: 'agent-1', agent_version: '1.0.0' };
  assert.ok((await f.call(expected[2], { query })).body.managed_config);
  for (const headers of [{}, { authorization: 'Bearer wrong' }]) {
    for (const [route, input] of [[expected[1], { body: identity }], [expected[2], { query }]]) {
      const result = await f.call(route, { ...input, headers });
      assert.equal(result.status, 401);
      assert.equal(result.body.managed_config, undefined);
    }
  }
  await f.repo.delete(TOKEN, 'token-1');
  for (const [route, input] of [[expected[1], { body: identity }], [expected[2], { query }]]) {
    const result = await f.call(route, input);
    assert.equal(result.status, 401);
    assert.equal(result.body.managed_config, undefined);
  }
});

test('heartbeats expose applied configuration and clear a previous error on successful acknowledgement', async () => {
  const f = fixture();
  await f.seed();
  const policy = (await f.call('PUT /api/xdr_manager/policies/{id}', {
    params: { id: 'default-endpoint' }, body: {
      name: 'Default', description: 'Managed', config: { telemetry_ship_interval_seconds: 5 },
    },
  })).body.policy;
  const failure = await f.call(expected[1], {
    body: { ...identity, config_revision: 'previous-revision', config_error: 'Config file is read-only' },
  });
  assert.equal(failure.body.managed_config.revision, policy.configRevision);
  let agent = (await f.call('GET /api/xdr_manager/agents')).body.agents[0];
  assert.equal(agent.configRevision, 'previous-revision');
  assert.equal(agent.configError, 'Config file is read-only');
  assert.equal(agent.enrollmentToken, undefined);
  await f.call(expected[1], { body: { ...identity, config_revision: policy.configRevision } });
  agent = (await f.call('GET /api/xdr_manager/agents')).body.agents[0];
  assert.equal(agent.configRevision, policy.configRevision);
  assert.equal(agent.configError, '');
  await f.call(expected[1], { body: identity });
  assert.equal((await f.repo.get(AGENT, 'agent-1')).attributes.configRevision, policy.configRevision);
});

test('detection mode does not degrade an Agent for intentionally disabled execution blocking', async () => {
  const f = fixture();
  await f.seed();
  const protection = {
    rule_source: 'YARA', rule_version: 'bundled', rule_count: 10, rules_sha256: 'a'.repeat(64),
    platform: 'linux', mode: 'detect', health: { yara: 'running', execution_blocking: 'disabled' },
  };
  for (const version of ['0.4.3', '99.0.0']) {
    await f.call(expected[1], { body: { ...identity, agent_version: version, protection } });
    assert.equal((await f.repo.get(AGENT, 'agent-1')).attributes.status, 'healthy');
  }
  for (const bad of [
    { ...protection, mode: 'prevent' },
    { ...protection, health: { yara: 'degraded: scan error', execution_blocking: 'disabled' } },
  ]) {
    await f.call(expected[1], { body: { ...identity, protection: bad } });
    assert.equal((await f.repo.get(AGENT, 'agent-1')).attributes.status, 'degraded');
  }
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
    assert.deepEqual(f.batches[0][0].create, {
      _id: 'agent-1:event-1', _index: `xdr-agent-${topic}`,
    });
    const wrong = event(
      topic === 'security' ? 'telemetry.process' : 'detection.malware',
      topic === 'security' ? 'event' : 'alert'
    );
    assert.equal((await f.call(route, { body: { ...body, events: [wrong] } })).status, 400);
    f.context.core.opensearch.client.asInternalUser.bulk = async () => ({
      body: { errors: true, items: [{ index: { status: 400, error: {
        type: 'mapper_parsing_exception',
        reason: "failed to parse field [payload.process.args] of type [keyword]. Preview of field's value: 'secret-input'",
      } } }] },
    });
    assert.equal((await f.call(route, { body })).status, 502);
    assert.match(f.errors[0], /400.*payload.process.args.*mapper_parsing_exception/);
    assert.doesNotMatch(f.errors[0], /secret-input/);
    await f.repo.delete(TOKEN, 'token-1');
    assert.equal((await f.call(route, { body })).status, 401);
  });
}

test('create conflicts are acknowledged as retries; other 409s are rejected', async () => {
  const f = fixture(); await f.seed();
  const body = { agent_id: 'agent-1', events: [event('telemetry.process')] };
  let type = 'version_conflict_engine_exception';
  f.context.core.opensearch.client.asInternalUser.bulk = async () => ({ body: {
    errors: true, items: [{ create: { status: 409, error: { type } } }],
  } });
  assert.equal((await f.call(expected[3], { body })).status, 200);
  type = 'security_exception';
  assert.equal((await f.call(expected[3], { body })).status, 502);
});

test('ingestion cannot create ordinary indices before stream provisioning completes', async () => {
  let fail;
  const ready = new Promise((_resolve, reject) => { fail = reject; });
  const f = fixture(ready); await f.seed();
  const result = f.call(expected[3], { body: { agent_id: 'agent-1', events: [event('telemetry.process')] } });
  fail(new Error('data stream template permission denied'));
  assert.equal((await result).status, 502);
  assert.equal(f.batches.length, 0);
});

test('stream provisioning targets stream names and preserves configured retention', async () => {
  const configured = {
    description: 'Operator changed retention to 45 days', default_state: 'rollover',
    states: [
      { name: 'rollover', actions: [{ rollover: { min_size: '5gb' } }], transitions: [{ state_name: 'hot' }] },
      { name: 'hot', actions: [], transitions: [{ state_name: 'delete', conditions: { min_index_age: '45d' } }] },
      { name: 'delete', actions: [{ delete: {} }], transitions: [] },
    ],
    ism_template: [],
  };
  for (const [topic, install] of [['telemetry', installTelemetryIsmPolicy], ['security', installSecurityIsmPolicy], ['logs', installAgentLogsIsmPolicy]]) {
    const calls = []; let template;
    const original = { ...configured, ism_template: [] };
    await install({
      transport: { request: async (request) => {
        calls.push(request);
        if (request.method === 'GET') return { body: { policy: original, _seq_no: 7, _primary_term: 2 } };
        return {};
      } },
      indices: { putIndexTemplate: async (request) => { template = request.body; }, putMapping: async () => {} },
    }, { info() {}, debug() {}, warn: (message) => assert.fail(message) });
    const policy = calls.find((request) => request.body?.policy).body.policy;
    assert.equal(policy.default_state, 'rollover');
    assert.deepEqual(policy.ism_template[0].index_patterns, [`xdr-agent-${topic}`]);
    assert.deepEqual(policy.states, configured.states);
    assert.deepEqual(template.data_stream, {});
    assert.deepEqual(template.index_patterns, [`xdr-agent-${topic}`]);
    assert.ok(calls.some((request) => request.path === `/_data_stream/xdr-agent-${topic}`));
    assert.ok(calls.every((request) => !request.path.includes('homelab')));
    assert.ok(calls.find((request) => request.body?.policy).path.includes('if_seq_no=7&if_primary_term=2'));
  }
});

test('startup installs Discover views for all streams and upgrades existing management views', async () => {
  const objects = new Map([
    ['xdr-agent-events', { attributes: { title: 'xdr-agent-*' } }],
    ['xdr-agent-logs-hidden', { attributes: { title: '.xdr-agent-logs-*' } }],
    ['xdr-agent-security-hidden', { attributes: { title: '.xdr-agent-security-*' } }],
  ]);
  const repo = {
    find: async () => ({ saved_objects: [...objects].map(([id, value]) => ({ ...value, id })) }),
    delete: async (_, id) => objects.delete(id),
    bulkCreate: async (patterns, options) => {
      for (const pattern of patterns) {
        assert.ok(options.overwrite || !objects.has(pattern.id));
        objects.set(pattern.id, structuredClone(pattern));
      }
      return { saved_objects: patterns };
    },
  };
  const logger = { info() {}, warn: assert.fail, error: assert.fail };
  const fields = [{ name: '@timestamp', type: 'date', searchable: true, aggregatable: true }];
  const requested = new Set();
  const getFields = async (pattern) => { requested.add(pattern); return fields; };
  await installEventIndexPatterns(repo, logger, getFields);
  await installEventIndexPatterns(repo, logger, getFields);
  assert.equal(objects.size, 3, 'restart must not create duplicate views or retain the combined default');
  assert.deepEqual([...objects.values()].map((view) => view.attributes.title).sort(), [
    'xdr-agent-logs', 'xdr-agent-security', 'xdr-agent-telemetry',
  ]);
  for (const view of objects.values()) {
    assert.ok(requested.has(view.attributes.title));
    assert.equal(view.type, 'index-pattern');
    assert.equal(view.attributes.timeFieldName, '@timestamp');
    assert.deepEqual(JSON.parse(view.attributes.fields), fields, 'Discover needs mapped fields immediately');
    assert.deepEqual(view.references, []);
  }
});

test('tenant setup reuses manual views and surfaces failures so a later visit can retry', async () => {
  const repo = {
    find: async () => {
      if (fail) throw new Error('temporary storage error');
      return { saved_objects: ['telemetry', 'logs', 'security'].map((topic) => ({
        id: `manual-${topic}`, attributes: { title: `xdr-agent-${topic}`, fields: '["customized"]' },
      })) };
    },
    bulkCreate: () => assert.fail('Manual views must not be replaced'),
  };
  const logger = { info() {}, error() {} };
  let fail = true;
  await assert.rejects(installEventIndexPatterns(repo, logger, async () => []), /temporary storage error/);
  fail = false;
  const ids = await installEventIndexPatterns(repo, logger, async () => []);
  assert.equal(ids['xdr-agent-telemetry'], 'manual-telemetry');
  assert.equal(ids['xdr-agent-security'], 'manual-security');
});

test('browser startup prepares the selected tenant before Discover and preserves an existing default', async () => {
  for (const initial of [undefined, 'operator-default', 'xdr-agent-events']) {
    let value = initial;
    let completed = false;
    await new BrowserPlugin().start({
      application: { capabilities: { indexPatterns: { save: true } } },
      http: { post: async (path) => {
        assert.equal(path, '/api/xdr_manager/setup');
        await new Promise((resolve) => setTimeout(resolve, 1));
        completed = true;
        return { telemetryId: 'manual-telemetry' };
      } },
      uiSettings: { get: () => value, set: async (_, id) => { value = id; } },
      notifications: { toasts: { addWarning: assert.fail } },
    });
    assert.ok(completed, 'Discover must wait for tenant initialization');
    assert.equal(value, !initial || initial === 'xdr-agent-events' ? 'manual-telemetry' : initial);
  }
});

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
