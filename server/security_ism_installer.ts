/**
 * Sets up an OpenSearch ISM policy and index template for XDR security
 * events stored under `.xdr-agent-security-*`.
 */

import { Logger } from '../../OpenSearch-Dashboards/src/core/server';

const ISM_POLICY_ID = 'xdr-security-retention';
const INDEX_TEMPLATE_NAME = 'xdr-security-template';
const INDEX_PATTERN = '.xdr-agent-security-*';

function buildIsmPolicy() {
  return {
    policy: {
      description: 'Retain XDR security indices for 90 days, then delete.',
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
          priority: 110,
        },
      ],
    },
  };
}

function buildIndexTemplate() {
  return {
    index_patterns: [INDEX_PATTERN],
    priority: 110,
    template: {
      settings: {
        number_of_shards: 1,
        number_of_replicas: 0,
        'index.hidden': true,
        // Prevent malformed scalar parsing from rejecting entire documents.
        'index.mapping.ignore_malformed': true,
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
          'rule.id': { type: 'keyword' },
          'rule.name': { type: 'keyword' },
          'threat.tactic.name': { type: 'keyword' },
          'threat.technique.id': { type: 'keyword' },
          'threat.technique.subtechnique.id': { type: 'keyword' },
          tags: { type: 'keyword' },
          indexed_at: { type: 'date' },
          payload: {
            type: 'object',
            dynamic: true,
            properties: {
              // ECS rule fields (detection.malware / detection.behavioral alerts)
              rule: {
                properties: {
                  id: { type: 'keyword' },
                  name: { type: 'keyword' },
                  description: { type: 'keyword' },
                  tags: { type: 'keyword' },
                },
              },
              // ECS file fields (hash match / YARA / static alerts)
              file: {
                properties: {
                  path: { type: 'keyword' },
                  hash: {
                    properties: {
                      sha256: { type: 'keyword' },
                    },
                  },
                },
              },
              // Detection metadata
              method: { type: 'keyword' },    // "hash" | "yara-x" | "static"
              // ECS event.action — the response taken: "alert" | "block"
              event: {
                properties: {
                  action: { type: 'keyword' },
                },
              },
              // Source event context
              source: {
                properties: {
                  module: { type: 'keyword' },
                  type: { type: 'keyword' },
                },
              },
              // Threat intel indicator fields
              indicator: {
                properties: {
                  type: { type: 'keyword' },
                  value: { type: 'keyword' },
                  source: { type: 'keyword' },
                },
              },
              // MITRE ATT&CK (behavioral rules)
              mitre: {
                properties: {
                  tactic: { type: 'keyword' },
                  technique: { type: 'keyword' },
                },
              },
              trigger_event_type: { type: 'keyword' },
            },
          },
        },
      },
    },
  };
}

export async function installSecurityIsmPolicy(
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
      logger.warn(`xdr_manager: failed to upsert ISM policy: ${err}`);
    }
  }

  try {
    await opensearchClient.indices.putIndexTemplate({
      name: INDEX_TEMPLATE_NAME,
      body: buildIndexTemplate(),
    });
    logger.info(`xdr_manager: installed index template [${INDEX_TEMPLATE_NAME}]`);
  } catch (err) {
    logger.warn(`xdr_manager: failed to install index template: ${err}`);
  }
}
