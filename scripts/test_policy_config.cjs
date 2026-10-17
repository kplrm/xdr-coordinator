const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { test } = require('node:test');

const root = process.env.OSD_ROOT || path.resolve(__dirname, '../../OpenSearch-Dashboards');
const ts = require(path.join(root, 'node_modules/typescript'));
require.extensions['.ts'] = (module, filename) => module._compile(
  ts.transpileModule(fs.readFileSync(filename, 'utf8'), {
    compilerOptions: { module: ts.ModuleKind.CommonJS, target: ts.ScriptTarget.ES2020 },
  }).outputText,
  filename
);

const {
  createPolicyConfigDraft, parsePolicyConfigDraft, policyConfigUpdate,
} = require('../public/components/policy_config.ts');

test('policy editor preserves unmanaged settings and explicit empty internal networks', () => {
  assert.deepEqual(parsePolicyConfigDraft(createPolicyConfigDraft()), {});
  assert.deepEqual(parsePolicyConfigDraft(createPolicyConfigDraft({ internal_networks: [] })), {
    internal_networks: [],
  });
});

test('clearing a managed policy explicitly resets overrides while editing a label leaves local config alone', () => {
  const draft = createPolicyConfigDraft();
  assert.equal(JSON.stringify({ config: policyConfigUpdate(draft, false) }), '{}');
  assert.equal(JSON.stringify({ config: policyConfigUpdate(draft, true) }), '{"config":{}}');
});

test('policy editor submits independent collection and send settings', () => {
  const settings = {
    internal_networks: ['192.168.0.0/16', 'fc00::/7'],
    process_scan_interval_seconds: 1,
    network_scan_interval_seconds: 2,
    telemetry_ship_interval_seconds: 30,
  };
  const draft = createPolicyConfigDraft(settings);
  assert.deepEqual(parsePolicyConfigDraft(draft), settings);
  draft.intervals.network_scan_interval_seconds = '';
  draft.manageInternalNetworks = false;
  assert.deepEqual(parsePolicyConfigDraft(draft), {
    process_scan_interval_seconds: 1,
    telemetry_ship_interval_seconds: 30,
  });
});

test('policy editor rejects invalid intervals before submitting a fleet update', () => {
  for (const value of ['0', '-1', '1.5', '86401', 'Infinity', 'abc']) {
    const draft = createPolicyConfigDraft();
    draft.intervals.process_scan_interval_seconds = value;
    assert.throws(() => parsePolicyConfigDraft(draft), /whole number from 1 to 86400/);
  }
});
