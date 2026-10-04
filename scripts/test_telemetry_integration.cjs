// Opt-in regression against OpenSearch; creates and deletes only unique test indices.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { randomUUID } = require('node:crypto');
const { test } = require('node:test');

const root = process.env.OSD_ROOT || path.resolve(__dirname, '../../OpenSearch-Dashboards');
process.env.NODE_PATH = [path.join(root, 'node_modules'), process.env.NODE_PATH]
  .filter(Boolean).join(path.delimiter);
require('node:module').Module._initPaths();
const ts = require('typescript');
require.extensions['.ts'] = (module, filename) => module._compile(
  ts.transpileModule(fs.readFileSync(filename, 'utf8'), {
    compilerOptions: { module: ts.ModuleKind.CommonJS, target: ts.ScriptTarget.ES2020 },
  }).outputText, filename
);
const { Client } = require('@opensearch-project/opensearch');
const { installTelemetryIsmPolicy } = require('../server/telemetry_ism_installer.ts');

test('oversized process keywords reproduce bulk failure and survive mapping repair', {
  skip: !process.env.XDR_OPENSEARCH_URL,
}, async () => {
  const client = new Client({
    node: process.env.XDR_OPENSEARCH_URL,
    auth: {
      username: process.env.XDR_OPENSEARCH_USER,
      password: process.env.XDR_OPENSEARCH_PASSWORD,
    },
    ssl: { rejectUnauthorized: process.env.XDR_OPENSEARCH_INSECURE_TLS !== '1' },
  });
  let template;
  let repair;
  await installTelemetryIsmPolicy({
    transport: { request: async () => ({}) },
    indices: {
      putIndexTemplate: async ({ body }) => { template = body; },
      putMapping: async (request) => { repair = request; },
    },
  }, { info() {}, debug() {}, warn: (message) => assert.fail(message) });

  const original = structuredClone(template.template.mappings);
  const processFields = original.properties.payload.properties.process.properties;
  for (const fields of [processFields, processFields.parent.properties]) {
    for (const name of ['command_line', 'args']) delete fields[name].ignore_above;
  }
  const docs = [];
  // Cover ASCII and four-byte Unicode, each process field, and array elements.
  for (const value of ['a'.repeat(39389), '😀'.repeat(9000)]) {
    docs.push({ payload: { process: { command_line: value } } });
    docs.push({ payload: { process: { args: ['short-argument', value] } } });
    docs.push({ payload: { process: { parent: { command_line: value } } } });
    docs.push({ payload: { process: { parent: { args: ['short-argument', value] } } } });
  }
  docs.push({ payload: { process: { command_line: 'ordinary-command' } } });
  const index = `.xdr-agent-telemetry-ingest-test-${randomUUID()}`;
  const created = [];
  const create = async (name, mappings) => {
    await client.indices.create({ index: name, body: {
      settings: { 'index.hidden': true, number_of_shards: 1, number_of_replicas: 0 },
      mappings,
    } });
    created.push(name);
  };
  const bulk = (name) => client.bulk({ refresh: true, body: docs.flatMap((doc, i) => [
    { index: { _index: name, _id: String(i) } }, doc,
  ]) });
  try {
    await create(index, original);
    const before = (await bulk(index)).body;
    assert.equal(before.errors, true);
    assert.equal(before.items.filter((item) => item.index.error).length, 8);
    assert.equal(before.items[8].index.status, 201);
    assert.match(JSON.stringify(before.items[0].index.error), /32766/);

    // Apply the real startup repair to an existing index, without recreating it.
    await client.indices.putMapping({ ...repair, index });
    const after = (await bulk(index)).body;
    assert.equal(after.errors, false);
    for (let i = 0; i < docs.length; i++) {
      const stored = (await client.get({ index, id: String(i) })).body;
      assert.deepEqual(stored._source, docs[i], 'full values must remain in _source');
    }
    const ordinary = (await client.search({ index, body: {
      query: { term: { 'payload.process.command_line': 'ordinary-command' } },
    } })).body;
    assert.equal(ordinary.hits.total.value, 1);
    const shortArgs = (await client.search({ index, body: {
      query: { term: { 'payload.process.args': 'short-argument' } },
    } })).body;
    assert.equal(shortArgs.hits.total.value, 2);

    const fresh = `${index}-new`;
    await create(fresh, template.template.mappings);
    assert.equal((await bulk(fresh)).body.errors, false);
  } finally {
    try {
      for (const name of created) await client.indices.delete({ index: name });
    } finally {
      await client.close();
    }
  }
});
