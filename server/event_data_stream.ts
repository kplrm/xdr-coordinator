import type { Logger } from '../../OpenSearch-Dashboards/src/core/server';

export const EVENT_STREAMS = {
  telemetry: 'xdr-agent-telemetry', security: 'xdr-agent-security', logs: 'xdr-agent-logs',
};
type Topic = keyof typeof EVENT_STREAMS;

const rollover = {
  name: 'rollover',
  actions: [{ rollover: { min_size: '10gb', min_index_age: '7d' } }],
  transitions: [{ state_name: 'hot' }],
};

// Keep the old hot/delete states intact: daily indices already in hot must
// retain their deletion schedule, rather than attempt to roll over without an alias.
function streamPolicy(policy: any, stream: string, priority: number) {
  const result = JSON.parse(JSON.stringify(policy));
  delete result.policy_id;
  delete result.last_updated_time;
  const hot = result.states.find((state: any) => state.name === 'hot');
  if (result.default_state === 'hot' && hot?.actions?.length === 0 &&
      hot.transitions?.some((transition: any) => transition.state_name === 'delete') &&
      !result.states.some((state: any) => state.name === 'rollover')) {
    result.default_state = 'rollover';
    result.states.unshift(rollover);
  }
  // Older daily indices already assigned this policy keep their hot/delete
  // states. Stop automatically assigning the new rollover state to daily indices.
  const legacyPattern = `.${stream}-*`;
  const templates = (result.ism_template || []).map((entry: any) => ({
    ...entry, index_patterns: entry.index_patterns.filter((pattern: string) => pattern !== legacyPattern),
  })).filter((entry: any) => entry.index_patterns.length > 0);
  // Exact stream and backing-index names avoid claiming any unrelated indices.
  const patterns = [stream, `.ds-${stream}-*`];
  if (!templates.some((entry: any) => patterns.every((pattern) => entry.index_patterns.includes(pattern)))) {
    templates.push({ index_patterns: patterns, priority });
  }
  result.ism_template = templates;
  return result;
}

export async function installEventDataStream(client: any, logger: Logger, topic: Topic, template: any) {
  const stream = EVENT_STREAMS[topic];
  const prefix = topic === 'logs' ? 'xdr-agent-logs' : `xdr-${topic}`;
  const policyId = `${prefix}-retention`;
  const policyPath = `/_plugins/_ism/policies/${policyId}`;
  let current: any;
  try {
    current = (await client.transport.request({ method: 'GET', path: policyPath })).body;
  } catch (error: any) {
    if ((error.statusCode ?? error.meta?.statusCode) !== 404) throw error;
  }
  const original = current?.policy || {
    description: `Retain XDR ${topic} for 90 days; roll over at 10 GB or 7 days.`,
    default_state: 'hot',
    states: [
      { name: 'hot', actions: [], transitions: [{ state_name: 'delete', conditions: { min_index_age: '90d' } }] },
      { name: 'delete', actions: [{ delete: {} }], transitions: [] },
    ],
    ism_template: [],
  };
  const policy = streamPolicy(original, stream, template.priority);
  const previous = { ...original };
  delete previous.policy_id;
  delete previous.last_updated_time;
  if (!current || JSON.stringify(previous) !== JSON.stringify(policy)) {
    const concurrency = current ? `?if_seq_no=${current._seq_no}&if_primary_term=${current._primary_term}` : '';
    try {
      await client.transport.request({ method: 'PUT', path: policyPath + concurrency, body: { policy } });
    } catch (error: any) {
      // Another Dashboards replica may have installed this same policy first.
      if ((error.statusCode ?? error.meta?.statusCode) !== 409) throw error;
      // Confirm the policy exists: a conflict initializing ISM's system index
      // alone does not mean the requested policy was successfully installed.
      await client.transport.request({ method: 'GET', path: policyPath });
    }
  }
  const body = JSON.parse(JSON.stringify(template));
  body.index_patterns = [stream];
  body.data_stream = {};
  delete body.template.settings['opendistro.index_state_management.policy_id'];
  await client.indices.putIndexTemplate({ name: `xdr-${topic === 'logs' ? 'agent-logs' : topic}-template`, body });
  try {
    await client.transport.request({ method: 'PUT', path: `/_data_stream/${stream}` });
  } catch (error: any) {
    const type = error.body?.error?.type ?? error.meta?.body?.error?.type;
    if (type !== 'resource_already_exists_exception') throw error;
  }
  logger.info(`xdr_manager: ensured data stream [${stream}] and ISM policy [${policyId}]`);
}
