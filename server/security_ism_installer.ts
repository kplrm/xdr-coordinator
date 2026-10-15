/** Mappings, data stream and retention for XDR security. */

import type { Logger } from '../../OpenSearch-Dashboards/src/core/server';
import { installEventDataStream } from './event_data_stream';

function buildIndexTemplate() {
  return {
    index_patterns: ['xdr-agent-security'],
    priority: 110,
    template: {
      settings: {
        number_of_shards: 1,
        number_of_replicas: 0,
        'index.hidden': true,
        // Prevent malformed scalar parsing from rejecting entire documents.
        'index.mapping.ignore_malformed': true,
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
          id: { type: 'keyword' },
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
  await installEventDataStream(opensearchClient, logger, 'security', buildIndexTemplate());
}
