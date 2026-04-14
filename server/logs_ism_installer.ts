/**
 * Sets up an OpenSearch ISM policy and index template for XDR agent logs
 * stored under `.xdr-agent-logs-*`.
 */

import { Logger } from '../../OpenSearch-Dashboards/src/core/server';

const ISM_POLICY_ID = 'xdr-agent-logs-retention';
const INDEX_TEMPLATE_NAME = 'xdr-agent-logs-template';
const INDEX_PATTERN = '.xdr-agent-logs-*';

function buildIsmPolicy() {
  return {
    policy: {
      description: 'Retain XDR agent log indices for 90 days, then delete.',
      default_state: 'hot',
      states: [
        {
          name: 'hot',
          actions: [],
          transitions: [
            {
              state_name: 'delete',
              conditions: {
                min_index_age: '90d',
              },
            },
          ],
        },
        {
          name: 'delete',
          actions: [{ delete: {} }],
          transitions: [],
        },
      ],
      ism_template: [
        {
          index_patterns: [INDEX_PATTERN],
          priority: 120,
        },
      ],
    },
  };
}

function buildIndexTemplate() {
  return {
    index_patterns: [INDEX_PATTERN],
    priority: 120,
    template: {
      settings: {
        number_of_shards: 1,
        number_of_replicas: 0,
        'index.hidden': true,
        'opendistro.index_state_management.policy_id': ISM_POLICY_ID,
      },
      mappings: {
        dynamic: true,
        dynamic_templates: [
          {
            payload_strings_as_keyword: {
              path_match: 'payload.*',
              match_mapping_type: 'string',
              mapping: { type: 'keyword', ignore_above: 1024 },
            },
          },
          {
            strings_as_keyword: {
              match_mapping_type: 'string',
              mapping: { type: 'keyword', ignore_above: 1024 },
            },
          },
        ],
        properties: {
          '@timestamp': { type: 'date' },
          'event.type': { type: 'keyword' },
          'event.category': { type: 'keyword' },
          'event.kind': { type: 'keyword' },
          'event.severity': { type: 'integer' },
          'event.module': { type: 'keyword' },
          'agent.id': { type: 'keyword' },
          'host.hostname': { type: 'keyword' },
          'log.level': { type: 'keyword' },
          message: { type: 'text' },
          tags: { type: 'keyword' },
          indexed_at: { type: 'date' },
          payload: {
            type: 'object',
            dynamic: true,
          },
        },
      },
    },
  };
}

export async function installAgentLogsIsmPolicy(
  opensearchClient: any,
  logger: Logger
): Promise<void> {
  const isPolicyAlreadyExistsError = (err: any): boolean => {
    const statusCode = err?.statusCode ?? err?.meta?.statusCode;
    const message = String(err?.message ?? err?.meta?.body?.error?.reason ?? '').toLowerCase();
    return statusCode === 409 || message.includes('version conflict') || message.includes('already exists');
  };

  try {
    await opensearchClient.transport.request({
      method: 'PUT',
      path: `/_plugins/_ism/policies/${ISM_POLICY_ID}`,
      body: buildIsmPolicy(),
    });
    logger.info(`xdr_manager: upserted ISM policy [${ISM_POLICY_ID}] (90-day retention)`);
  } catch (err: any) {
    if (isPolicyAlreadyExistsError(err)) {
      logger.debug(`xdr_manager: ISM policy [${ISM_POLICY_ID}] already exists/conflicted during startup`);
    } else {
      logger.warn(`xdr_manager: failed to upsert logs ISM policy: ${err}`);
    }
  }

  try {
    await opensearchClient.indices.putIndexTemplate({
      name: INDEX_TEMPLATE_NAME,
      body: buildIndexTemplate(),
    });
    logger.info(`xdr_manager: installed index template [${INDEX_TEMPLATE_NAME}]`);
  } catch (err) {
    logger.warn(`xdr_manager: failed to install logs index template: ${err}`);
  }
}
